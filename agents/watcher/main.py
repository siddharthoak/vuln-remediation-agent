"""
Watcher Agent entry point.

Scheduled trigger (every 15 minutes, see watcher.agent.yaml). On each invocation:
  1. Find open remediation PRs (by branch prefix).
  2. For each PR, load the latest tracking record from the store.
  3. Skip PRs already in a terminal state (CI_PASSED, FAILED_MAX_RETRIES, ESCALATED).
  4. Poll CI status via CIStatusWatcher (has its own timeout).
  5. If CI passed → update tracking record to CI_PASSED.
  6. If CI failed → delegate to RetryGate, which checks the retry bound, writes a new
     RETRY_REQUESTED tracking record, and invokes the Fixer container.

The Watcher NEVER:
  - Calls the Anthropic model
  - Writes code or edits files
  - Touches a git repository (no RepoOps, no GitPython, no git binary calls)
  - Merges or force-pushes PRs
"""

import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import json as _json

from github import Github
from ci_status import CIStatusWatcher, CIOutcome
from pr_client import PRClient
from retry_gate import RetryGate, make_fixer_invoker
from pattern_learner import PatternLearner

from common.tracking_store import make_tracking_store, TrackingStatus
from common.knowledge_store import make_knowledge_store
from common.config import (
    get_target_repo,
    get_target_repos,
    get_github_pat,
    get_watcher_sleep_seconds,
    is_nightly_run_enabled,
    get_nightly_run_time,
    get_nightly_scan_max_wait_seconds,
)
from common.nightly_scheduler import (
    get_active_window_status,
    sleep_until_active_window,
    sleep_until_next_run,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("watcher.main")

REMEDIATION_BRANCH_PREFIX = "fix/"

_TERMINAL_STATUSES = {
    TrackingStatus.CI_PASSED.value,
    TrackingStatus.FAILED_MAX_RETRIES.value,
    TrackingStatus.ESCALATED.value,
    TrackingStatus.ENGINE_ERROR.value,
}

# ── Manual "check now" trigger (POST /check-now, GET /check-now/status) ───────
# Shared by BOTH the scheduled daemon loop and the manual HTTP trigger (see
# _scheduled_loop/_make_watcher_server below), so a demo click can't race a
# scheduled cycle into running _run_once() twice at once -- whichever gets
# the lock first runs; the other waits (scheduled loop, blocking acquire) or
# gets told 409/busy (manual trigger, non-blocking acquire). Same in-memory,
# lock-guarded shape as fixer-server's job state (agents/fixer/main.py).
_check_lock = threading.Lock()
_check_state = {"status": "idle", "message": ""}


def find_open_remediation_prs(repo):
    """Return open PRs whose head branch starts with the remediation prefix."""
    pulls = repo.get_pulls(state="open")
    return [pr for pr in pulls if pr.head.ref.startswith(REMEDIATION_BRANCH_PREFIX)]


def main():
    daemon   = os.environ.get("WATCHER_DAEMON", "0") == "1"
    timezone_name = os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata")

    if daemon:
        logger.info("Watcher daemon mode started.")
        loop_thread = threading.Thread(
            target=_scheduled_loop, daemon=True, name="watcher-loop",
        )
        loop_thread.start()

        port = int(os.environ.get("WATCHER_PORT", "8090"))
        server = _make_watcher_server(port)
        logger.info("Watcher HTTP server listening on :%d", port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Watcher shutting down.")
    else:
        _run_once()


def _scheduled_loop():
    timezone_name = os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata")
    while True:
        try:
            if is_nightly_run_enabled():
                run_time = get_nightly_run_time()
                duration_seconds = get_nightly_scan_max_wait_seconds()

                is_active, remaining_seconds, seconds_until_next = get_active_window_status(
                    run_time=run_time,
                    duration_seconds=duration_seconds,
                    timezone_name=timezone_name,
                )

                if not is_active:
                    logger.info(
                        "Watcher Night Mode: outside active window. Sleeping until %s %s (%.1f hours).",
                        timezone_name,
                        run_time,
                        seconds_until_next / 3600.0,
                    )
                    became_active = sleep_until_active_window(
                        timezone_name=timezone_name,
                        check_cancel_fn=lambda: not is_nightly_run_enabled(),
                    )
                    if not became_active:
                        logger.info("Night Mode toggled OFF: running watcher immediately.")
                        with _check_lock:
                            _run_check_now_locked()
                        continue
                    # Recompute window status upon waking
                    is_active, remaining_seconds, _ = get_active_window_status(
                        run_time=get_nightly_run_time(),
                        duration_seconds=get_nightly_scan_max_wait_seconds(),
                        timezone_name=timezone_name,
                    )

                logger.info(
                    "Watcher Night Mode active window (%.1f minutes remaining). Checking PR CI status...",
                    remaining_seconds / 60.0,
                )
                with _check_lock:
                    _run_check_now_locked()
                cycle_interval = get_watcher_sleep_seconds()
                time.sleep(cycle_interval)
            else:
                with _check_lock:
                    _run_check_now_locked()
                cycle_interval = get_watcher_sleep_seconds()
                logger.info("Watcher sleeping %d seconds until next cycle.", cycle_interval)
                time.sleep(cycle_interval)
        except Exception as exc:
            logger.error("Watcher cycle error: %s", exc, exc_info=True)


def _run_check_now_locked():
    """Runs one watch cycle and updates _check_state. Caller must already
    hold _check_lock -- this function only does the work, it never
    acquires/releases the lock itself (both _scheduled_loop and the manual
    /check-now handler own that decision).
    """
    global _check_state
    _check_state = {"status": "running", "message": "Checking open remediation PRs..."}
    try:
        _run_once()
        _check_state = {"status": "done", "message": "Cycle complete."}
    except Exception as exc:
        logger.error("Watcher cycle error: %s", exc, exc_info=True)
        _check_state = {"status": "error", "message": str(exc)}


def _make_watcher_server(port: int) -> HTTPServer:
    class CheckHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/check-now":
                self._handle_check_now()
            else:
                self.send_error(404)

        def do_GET(self):
            if self.path == "/check-now/status":
                self._send_json(200, _check_state)
            else:
                self.send_error(404)

        def _send_json(self, status: int, payload) -> None:
            body = _json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle_check_now(self):
            if not _check_lock.acquire(blocking=False):
                self._send_json(409, _check_state)
                return

            def _run():
                try:
                    _run_check_now_locked()
                finally:
                    _check_lock.release()

            self.send_response(202)
            self.end_headers()
            threading.Thread(target=_run, daemon=True, name="check-now").start()
            logger.info("Manual check-now accepted.")

        def log_message(self, fmt, *args):  # suppress default access log noise
            logger.debug("HTTP %s", fmt % args)

    return HTTPServer(("0.0.0.0", port), CheckHandler)


def _run_once():
    target_repos = get_target_repos()

    if not target_repos:
        logger.warning("No target repository configured. Skipping watcher cycle.")
        return

    tracking_store  = make_tracking_store()
    kb_store        = make_knowledge_store()

    for github_repo in target_repos:
        repo_token = get_github_pat(github_repo)
        if not repo_token:
            logger.warning("No GitHub credentials available for repo %s. Skipping.", github_repo)
            continue

        try:
            gh = Github(repo_token)
            repo = gh.get_repo(github_repo)
        except Exception as exc:
            logger.warning("Watcher could not access repo %s: %s", github_repo, exc)
            continue

        remediation_prs = find_open_remediation_prs(repo)
        if not remediation_prs:
            logger.info("No open remediation PRs found in %s.", github_repo)
            continue

        logger.info("Watching %d open remediation PR(s) in %s.", len(remediation_prs), github_repo)

        ci_watcher      = CIStatusWatcher(repo_full_name=github_repo, github_pat=repo_token)
        pr_client       = PRClient(repo_full_name=github_repo, github_pat=repo_token)
        retry_gate      = RetryGate(
            tracking_store=tracking_store,
            pr_client=pr_client,
            fixer_invoker=make_fixer_invoker(),
        )
        pattern_learner = PatternLearner(
            repo_full_name=github_repo,
            github_pat=repo_token,
        )

        for pr in remediation_prs:
            _process_pr(pr, tracking_store, ci_watcher, retry_gate, kb_store, pattern_learner)


def _process_pr(pr, tracking_store, ci_watcher, retry_gate, kb_store, pattern_learner) -> None:
    pr_number = pr.number

    records_for_pr = (
        tracking_store.get_all_for_pr(pr_number)
        if hasattr(tracking_store, "get_all_for_pr")
        else []
    )
    if not records_for_pr:
        single = tracking_store.get_latest_for_pr(pr_number)
        records_for_pr = [single] if single else []

    if not records_for_pr:
        logger.warning(
            "PR #%d: no tracking record found (opened outside the agent?). Skipping.",
            pr_number,
        )
        return

    unresolved_records = [r for r in records_for_pr if r.status != TrackingStatus.CI_PASSED.value]
    if not unresolved_records:
        logger.info("PR #%d: all records are CI_PASSED. Skipping.", pr_number)
        return

    exhausted_records = [r for r in unresolved_records if r.status in (TrackingStatus.FAILED_MAX_RETRIES.value, TrackingStatus.ESCALATED.value)]
    active_records = [r for r in unresolved_records if r.status not in _TERMINAL_STATUSES]

    if not active_records and exhausted_records:
        # Check if the latest commit on this open PR has passed CI
        ci_result = ci_watcher.wait_for_ci(pr_number=pr_number, poll_interval_seconds=10, timeout_seconds=30)
        if ci_result.status == CIOutcome.SUCCESS:
            logger.info("PR #%d: CI now PASSED on latest commit! Updating %d record(s) to CI_PASSED.", pr_number, len(exhausted_records))
            for rec in exhausted_records:
                rec.status = TrackingStatus.CI_PASSED.value
                tracking_store.update(rec)
                try:
                    pattern_learner.learn_from_pr(pr_number, rec, kb_store)
                except Exception as exc:
                    logger.warning("PR #%d: pattern learning failed for %s: %s", pr_number, rec.component_name, exc)
            return
        else:
            logger.info("PR #%d: records are in terminal failure status and CI has not passed. Skipping.", pr_number)
            return

    if not active_records:
        logger.info("PR #%d: all records are in terminal status. Skipping.", pr_number)
        return

    if any(r.status == TrackingStatus.RETRY_REQUESTED.value for r in active_records):
        logger.info(
            "PR #%d (%s): one or more records in RETRY_REQUESTED. "
            "Fixer is actively processing this retry. Waiting for retry commit push before checking CI.",
            pr_number, pr.head.ref,
        )
        return

    logger.info(
        "PR #%d (%s): checking CI for %d record(s).",
        pr_number, pr.head.ref, len(active_records),
    )

    ci_result = ci_watcher.wait_for_ci(
        pr_number=pr_number,
        poll_interval_seconds=int(os.environ.get("CI_POLL_INTERVAL", "30")),
        timeout_seconds=int(os.environ.get("CI_TIMEOUT_SECONDS", "1800")),
    )

    if ci_result.status == CIOutcome.SUCCESS:
        logger.info("PR #%d: CI passed. Marking %d record(s) resolved.", pr_number, len(active_records))
        for rec in active_records:
            rec.status = TrackingStatus.CI_PASSED.value
            tracking_store.update(rec)
            # Tier 1: learn fix patterns from this confirmed-good PR
            try:
                pattern_learner.learn_from_pr(pr_number, rec, kb_store)
            except Exception as exc:
                logger.warning("PR #%d: pattern learning failed for %s: %s", pr_number, rec.component_name, exc)
        return

    if ci_result.status == CIOutcome.TIMEOUT:
        logger.warning("PR #%d: CI timed out. Will retry on next Watcher cycle.", pr_number)
        return

    # CI failed — write the intermediate status for all active records then let RetryGate decide.
    logger.info("PR #%d: CI failed. Updating %d record(s) to CI_FAILED and delegating to RetryGate.", pr_number, len(active_records))
    for rec in active_records:
        rec.status = TrackingStatus.CI_FAILED.value
        tracking_store.update(rec)

    candidate_records = [
        r for r in records_for_pr
        if r.status not in (TrackingStatus.FAILED_MAX_RETRIES.value, TrackingStatus.ESCALATED.value)
    ]
    if not candidate_records:
        candidate_records = records_for_pr
    latest_record = sorted(candidate_records, key=lambda r: r.attempt_number, reverse=True)[0]
    retry_gate.process_ci_failure(ci_result, current_tracking_record=latest_record)



if __name__ == "__main__":
    main()
