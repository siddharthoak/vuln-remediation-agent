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
    interval = int(os.environ.get("WATCHER_SLEEP_SECONDS", "900"))  # default 15 min

    if daemon:
        logger.info("Watcher daemon mode: cycling every %d seconds.", interval)
        loop_thread = threading.Thread(
            target=_scheduled_loop, args=(interval,), daemon=True, name="watcher-loop",
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


def _scheduled_loop(interval: int):
    while True:
        with _check_lock:  # blocking acquire -- just waits its turn behind a manual check-now
            _run_check_now_locked()
        logger.info("Watcher sleeping %d seconds until next cycle.", interval)
        time.sleep(interval)


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
    github_repo = os.environ["GITHUB_REPO_TARGET"]
    github_pat  = os.environ["GITHUB_PAT"]

    gh   = Github(github_pat)
    repo = gh.get_repo(github_repo)

    remediation_prs = find_open_remediation_prs(repo)
    if not remediation_prs:
        logger.info("No open remediation PRs found. Nothing to watch.")
        return

    logger.info("Watching %d open remediation PR(s).", len(remediation_prs))

    tracking_store   = make_tracking_store()
    kb_store         = make_knowledge_store()
    ci_watcher       = CIStatusWatcher(repo_full_name=github_repo, github_pat=github_pat)
    pr_client        = PRClient(repo_full_name=github_repo, github_pat=github_pat)
    retry_gate       = RetryGate(
        tracking_store=tracking_store,
        pr_client=pr_client,
        fixer_invoker=make_fixer_invoker(),
    )
    pattern_learner  = PatternLearner(
        repo_full_name=github_repo,
        github_pat=github_pat,
    )

    for pr in remediation_prs:
        _process_pr(pr, tracking_store, ci_watcher, retry_gate, kb_store, pattern_learner)


def _process_pr(pr, tracking_store, ci_watcher, retry_gate, kb_store, pattern_learner) -> None:
    pr_number = pr.number

    record = tracking_store.get_latest_for_pr(pr_number)
    if record is None:
        logger.warning(
            "PR #%d: no tracking record found (opened outside the agent?). Skipping.",
            pr_number,
        )
        return

    if record.status in _TERMINAL_STATUSES:
        logger.info("PR #%d: status=%s (terminal). Skipping.", pr_number, record.status)
        return

    logger.info(
        "PR #%d (%s): checking CI. Current status=%s",
        pr_number, pr.head.ref, record.status,
    )

    ci_result = ci_watcher.wait_for_ci(
        pr_number=pr_number,
        poll_interval_seconds=int(os.environ.get("CI_POLL_INTERVAL", "30")),
        timeout_seconds=int(os.environ.get("CI_TIMEOUT_SECONDS", "1800")),
    )

    if ci_result.status == CIOutcome.SUCCESS:
        logger.info("PR #%d: CI passed. Marking resolved.", pr_number)
        record.status = TrackingStatus.CI_PASSED.value
        tracking_store.update(record)
        # Tier 1: learn fix patterns from this confirmed-good PR
        try:
            pattern_learner.learn_from_pr(pr_number, record, kb_store)
        except Exception as exc:
            logger.warning("PR #%d: pattern learning failed (non-fatal): %s", pr_number, exc)
        return

    if ci_result.status == CIOutcome.TIMEOUT:
        logger.warning("PR #%d: CI timed out. Will retry on next Watcher cycle.", pr_number)
        return

    # CI failed — write the intermediate status then let RetryGate decide what to do.
    # RetryGate owns: bound check, RETRY_REQUESTED record creation, Fixer invocation.
    # The Watcher does not write code, clone repos, or push commits before or after this call.
    logger.info("PR #%d: CI failed. Delegating to RetryGate.", pr_number)
    record.status = TrackingStatus.CI_FAILED.value
    tracking_store.update(record)

    retry_gate.process_ci_failure(ci_result, current_tracking_record=record)


if __name__ == "__main__":
    main()
