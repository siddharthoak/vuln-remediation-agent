"""
WAT-01: CI status poller — monitor a PR's CI checks and retrieve failure logs.

Uses the GitHub Checks API (not the legacy Commit Status API) because GitHub Actions
and most modern CI integrations report via Checks, which provides structured log access.
The legacy Commit Status API only gives a pass/fail URL and cannot retrieve log content,
which the Watcher needs to reason about failures.
"""

import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from github import Github, GithubException

logger = logging.getLogger(__name__)


class CIOutcome(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"


@dataclass
class FailedCheck:
    name: str
    check_run_id: int
    conclusion: str
    details_url: str
    log_text: str = ""


@dataclass
class CIResult:
    status: CIOutcome
    pr_number: int
    head_sha: str
    check_run_url: Optional[str] = None
    failed_checks: list = field(default_factory=list)

    @property
    def failure_log_text(self) -> str:
        """Concatenated log text from all failed check runs, for LLM reasoning."""
        if not self.failed_checks:
            return ""
        parts = []
        for fc in self.failed_checks:
            parts.append(f"=== Check: {fc.name} (conclusion: {fc.conclusion}) ===")
            parts.append(fc.log_text or "(no log text retrieved)")
        return "\n\n".join(parts)


class CIStatusWatcher:
    """
    Polls the GitHub Checks API for a pull request until CI reaches a terminal state.

    Handles multiple check runs on the same commit (e.g. build + unit tests + integration
    tests as separate checks). The overall result is:
      - SUCCESS only if ALL required checks pass.
      - FAILURE if ANY required check fails.
      - TIMEOUT if the terminal state isn't reached within `timeout_seconds`.
    """

    # Check run conclusions that indicate a terminal failure (not just pending/queued)
    FAILURE_CONCLUSIONS = {"failure", "timed_out", "action_required", "cancelled", "stale"}
    SUCCESS_CONCLUSIONS = {"success", "skipped", "neutral"}

    def __init__(self, repo_full_name: str, github_pat: str):
        self._repo_full_name = repo_full_name
        self._github_pat = github_pat
        gh = Github(github_pat)
        self._repo = gh.get_repo(repo_full_name)

    @property
    def repo(self):
        try:
            from common.config import get_github_pat
            token = get_github_pat(self._repo_full_name) or self._github_pat
            if token != self._github_pat:
                self._github_pat = token
                self._repo = Github(token).get_repo(self._repo_full_name)
        except Exception:
            pass
        return self._repo

    def wait_for_ci(
        self,
        pr_number: int,
        poll_interval_seconds: int = 30,
        timeout_seconds: int = 1800,
    ) -> CIResult:
        """
        Poll until all CI check runs or workflow runs on the PR's head commit reach
        a terminal state, or until `timeout_seconds` is exceeded.

        poll_interval_seconds and timeout_seconds are intentionally configurable since
        CI run durations vary enormously across projects and need tuning in practice.
        """
        pr = self.repo.get_pull(pr_number)
        head_sha = pr.head.sha

        logger.info(
            "Watching CI for PR #%d (sha %s), timeout=%ds, interval=%ds",
            pr_number, head_sha[:8], timeout_seconds, poll_interval_seconds,
        )

        elapsed = 0
        while elapsed < timeout_seconds:
            result = self._evaluate_ci(pr_number, head_sha)
            if result is not None:
                return result

            logger.info(
                "PR #%d: CI still in progress. Waiting %ds (elapsed %ds/%ds)...",
                pr_number, poll_interval_seconds, elapsed, timeout_seconds,
            )
            time.sleep(poll_interval_seconds)
            elapsed += poll_interval_seconds

        logger.warning("PR #%d: CI did not complete within %ds — timeout.", pr_number, timeout_seconds)
        return CIResult(
            status=CIOutcome.TIMEOUT,
            pr_number=pr_number,
            head_sha=head_sha,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _evaluate_check_runs(self, pr_number: int, head_sha: str) -> Optional[CIResult]:
        """Backward-compatible wrapper delegating to _evaluate_ci."""
        return self._evaluate_ci(pr_number, head_sha)

    def _evaluate_ci(self, pr_number: int, head_sha: str) -> Optional[CIResult]:
        """
        Inspect the current CI state on `head_sha`.
        Tries the GitHub Checks API first (when available with 'checks: read' permission).
        If the Checks API returns 403 Forbidden or returns no check runs, falls back
        seamlessly to the GitHub Actions Workflow Runs API ('actions: read' permission).
        """
        try:
            commit = self.repo.get_commit(head_sha)
            check_runs = list(commit.get_check_runs())
            if check_runs:
                return self._classify_check_runs(check_runs, pr_number, head_sha)
        except GithubException as exc:
            if exc.status == 403:
                logger.debug(
                    "Checks API returned 403 for %s (using Workflow Runs API fallback).",
                    head_sha[:8],
                )
            else:
                logger.warning("GitHub API error fetching check runs: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error fetching check runs: %s", exc)

        # Fall back to GitHub Actions Workflow Runs API
        return self._evaluate_workflow_runs(pr_number, head_sha)

    def _classify_check_runs(self, check_runs, pr_number: int, head_sha: str) -> Optional[CIResult]:
        in_progress_statuses = {"queued", "in_progress"}
        all_terminal = all(cr.status not in in_progress_statuses for cr in check_runs)

        if not all_terminal:
            return None  # At least one check still running

        # All check runs are terminal — classify
        failed_checks = []
        for cr in check_runs:
            if cr.conclusion in self.FAILURE_CONCLUSIONS:
                log_text = self._fetch_log(cr)
                failed_checks.append(FailedCheck(
                    name=cr.name,
                    check_run_id=cr.id,
                    conclusion=cr.conclusion,
                    details_url=cr.details_url or "",
                    log_text=log_text,
                ))

        if failed_checks:
            logger.info(
                "PR #%d: CI FAILED — %d check(s) failed: %s",
                pr_number,
                len(failed_checks),
                [fc.name for fc in failed_checks],
            )
            return CIResult(
                status=CIOutcome.FAILURE,
                pr_number=pr_number,
                head_sha=head_sha,
                check_run_url=failed_checks[0].details_url,
                failed_checks=failed_checks,
            )

        logger.info("PR #%d: CI PASSED — all %d check(s) succeeded.", pr_number, len(check_runs))
        return CIResult(
            status=CIOutcome.SUCCESS,
            pr_number=pr_number,
            head_sha=head_sha,
        )

    def _evaluate_workflow_runs(self, pr_number: int, head_sha: str) -> Optional[CIResult]:
        """
        Inspect GitHub Actions workflow runs for `head_sha`.
        Returns CIResult if all runs are complete, or None if in progress / no runs yet.
        """
        try:
            runs = list(self.repo.get_workflow_runs(head_sha=head_sha))
        except GithubException as exc:
            logger.warning("GitHub API error fetching workflow runs for %s: %s", head_sha[:8], exc)
            return None
        except Exception as exc:
            logger.warning("Unexpected error fetching workflow runs: %s", exc)
            return None

        if not runs:
            # CI hasn't started or no workflows registered for this commit yet
            return None

        in_progress_statuses = {"queued", "in_progress", "waiting", "pending", "requested"}
        any_running = any(run.status in in_progress_statuses for run in runs)
        if any_running:
            return None  # At least one workflow still running

        failed_checks = []
        for run in runs:
            if run.conclusion in self.FAILURE_CONCLUSIONS:
                try:
                    jobs = list(run.jobs())
                except Exception as exc:
                    logger.warning("Could not fetch jobs for workflow run %s: %s", run.id, exc)
                    jobs = []

                failed_jobs = [j for j in jobs if j.conclusion in self.FAILURE_CONCLUSIONS]
                if not failed_jobs:
                    failed_checks.append(FailedCheck(
                        name=run.name or f"Workflow {run.id}",
                        check_run_id=run.id,
                        conclusion=run.conclusion or "failure",
                        details_url=run.html_url or "",
                        log_text="",
                    ))
                else:
                    for job in failed_jobs:
                        log_text = self._fetch_job_log(job)
                        failed_checks.append(FailedCheck(
                            name=f"{run.name} / {job.name}",
                            check_run_id=job.id,
                            conclusion=job.conclusion or "failure",
                            details_url=job.html_url or run.html_url or "",
                            log_text=log_text,
                        ))

        if failed_checks:
            logger.info(
                "PR #%d: CI FAILED — %d workflow job(s) failed: %s",
                pr_number,
                len(failed_checks),
                [fc.name for fc in failed_checks],
            )
            return CIResult(
                status=CIOutcome.FAILURE,
                pr_number=pr_number,
                head_sha=head_sha,
                check_run_url=failed_checks[0].details_url,
                failed_checks=failed_checks,
            )

        logger.info("PR #%d: CI PASSED — all %d workflow run(s) succeeded.", pr_number, len(runs))
        return CIResult(
            status=CIOutcome.SUCCESS,
            pr_number=pr_number,
            head_sha=head_sha,
        )

    def _fetch_job_log(self, job) -> str:
        """Fetch log for a failed WorkflowJob using job.logs_url()."""
        try:
            logs_url = job.logs_url()
            if logs_url:
                req = urllib.request.Request(logs_url, headers={"User-Agent": "vuln-remediation-agent"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_text = resp.read().decode("utf-8", errors="replace")
                    return self._extract_relevant_log(raw_text)
        except Exception as exc:
            logger.warning("Could not fetch log for job %s: %s", getattr(job, "id", "unknown"), exc)

        try:
            steps_info = []
            for step in getattr(job, "steps", []):
                if step.conclusion in self.FAILURE_CONCLUSIONS:
                    steps_info.append(f"Step '{step.name}' failed (status: {step.status}, conclusion: {step.conclusion})")
            if steps_info:
                return "\n".join(steps_info)
        except Exception:
            pass

        return ""

    def _fetch_log(self, check_run) -> str:
        """
        Fetch the log output for a failed check run.
        Attempts to fetch full raw job logs from GitHub Actions first,
        falling back to check_run.output if unavailable.
        """
        gh_log = self._fetch_github_actions_log(check_run.id)
        if gh_log:
            return gh_log

        try:
            output = check_run.output
            parts = []
            if output.title:
                parts.append(f"Title: {output.title}")
            if output.summary:
                parts.append(f"Summary:\n{output.summary}")
            if output.text:
                parts.append(f"Detail:\n{output.text}")
            return "\n\n".join(parts) if parts else ""
        except Exception as exc:
            logger.warning("Could not fetch log for check run %d: %s", check_run.id, exc)
            return ""

    def _fetch_github_actions_log(self, job_id: int) -> str:
        """Fetch raw job log from GitHub Actions, handling the presigned redirect safely."""
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        url = f"https://api.github.com/repos/{self._repo_full_name}/actions/jobs/{job_id}/logs"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._github_pat}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "vuln-remediation-agent",
            },
        )
        opener = urllib.request.build_opener(NoRedirectHandler)
        presigned_url = None
        try:
            opener.open(req)
        except urllib.error.HTTPError as err:
            if err.code in (301, 302, 307, 308):
                presigned_url = err.headers.get("Location")
            else:
                logger.debug("Failed to request job log URL for %d: %s", job_id, err)
                return ""
        except Exception as exc:
            logger.debug("Error requesting job log URL for %d: %s", job_id, exc)
            return ""

        if not presigned_url:
            return ""

        try:
            # Pre-signed S3/Azure URL MUST NOT have the GitHub Authorization header
            req2 = urllib.request.Request(presigned_url, headers={"User-Agent": "vuln-remediation-agent"})
            with urllib.request.urlopen(req2, timeout=20) as resp:
                raw_text = resp.read().decode("utf-8", errors="replace")
                return self._extract_relevant_log(raw_text)
        except Exception as exc:
            logger.warning("Failed to download job log from presigned URL for %d: %s", job_id, exc)
            return ""

    @staticmethod
    def _extract_relevant_log(raw_log: str, max_chars: int = 4000) -> str:
        if not raw_log:
            return ""
        lines = raw_log.splitlines()
        err_indices = [
            i for i, line in enumerate(lines)
            if any(k in line for k in ("CRITICAL", "HIGH", "ERROR", "FAILURE", "BUILD FAILURE", "Compilation failure", "Failed to execute goal"))
        ]
        if err_indices:
            start = max(0, err_indices[0] - 5)
            end = min(len(lines), err_indices[-1] + 25)
            snippet = "\n".join(lines[start:end])
            if len(snippet) > max_chars:
                snippet = snippet[:max_chars] + "\n...[truncated]..."
            return snippet
        return "\n".join(lines[-60:])[-max_chars:]

