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
import time

from github import Github
from ci_status import CIStatusWatcher, CIOutcome
from pr_client import PRClient
from retry_gate import RetryGate, make_fixer_invoker
from pattern_learner import PatternLearner

from common.tracking_store import make_tracking_store, TrackingStatus
from common.knowledge_store import make_knowledge_store
from common.config import get_target_repo, get_target_repos, get_github_pat, get_watcher_sleep_seconds
from common.nightly_scheduler import sleep_until_next_run


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


def find_open_remediation_prs(repo):
    """Return open PRs whose head branch starts with the remediation prefix."""
    pulls = repo.get_pulls(state="open")
    return [pr for pr in pulls if pr.head.ref.startswith(REMEDIATION_BRANCH_PREFIX)]


def main():
    daemon   = os.environ.get("WATCHER_DAEMON", "0") == "1"
    interval = get_watcher_sleep_seconds()

    if daemon:
        nightly = os.environ.get("NIGHTLY_RUN_ENABLED", "1") == "1"
        if nightly:
            run_time = os.environ.get("NIGHTLY_RUN_TIME", "00:00")
            timezone_name = os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata")
            logger.info(
                "Watcher nightly mode enabled: runs at %s (%s).",
                run_time,
                timezone_name,
            )
        else:
            logger.info("Watcher daemon mode: cycling every %d seconds.", interval)
        while True:
            try:
                if nightly:
                    sleep_until_next_run(run_time, timezone_name)
                _run_once()
            except Exception as exc:
                logger.error("Watcher cycle error: %s", exc, exc_info=True)
                if nightly:
                    continue
            if nightly:
                continue
            # Re-read interval each cycle in case config/.env was updated
            cycle_interval = get_watcher_sleep_seconds()
            logger.info("Watcher sleeping %d seconds until next cycle.", cycle_interval)
            time.sleep(cycle_interval)
    else:
        _run_once()



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
