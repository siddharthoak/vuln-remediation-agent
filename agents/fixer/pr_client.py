"""
FIX-04: PR client — open a GitHub pull request with a structured remediation description.

Uses PyGitHub for the GitHub REST API. Idempotent: if an open PR already exists for the
branch, returns its details rather than creating a duplicate.
"""

import logging
import os
from dataclasses import dataclass
from typing import Optional

from github import Github, GithubException

logger = logging.getLogger(__name__)


@dataclass
class PRResult:
    pr_number: int
    pr_url: str
    was_existing: bool


class PRClient:
    """
    Opens remediation pull requests on GitHub.

    Idempotent: calling open_remediation_pr() for a branch that already has an open PR
    returns the existing PR rather than creating a duplicate.
    """

    def __init__(self, repo_full_name: str, github_pat: Optional[str] = None):
        self._repo_full_name = repo_full_name
        pat = github_pat or os.environ["GITHUB_PAT"]
        self._gh = Github(pat)
        self._repo = self._gh.get_repo(repo_full_name)

    def open_remediation_pr(
        self,
        branch_name: str,
        base_branch: str,
        change_summary,  # ChangeSummary from code_fixer.py
    ) -> PRResult:
        """
        Open a pull request for `branch_name` against `base_branch`.

        If an open PR for this branch already exists, returns it unchanged (no duplicate).
        Returns a PRResult with pr_number, pr_url, and was_existing flag.
        """
        existing = self._find_open_pr(branch_name, base_branch)
        if existing:
            logger.info(
                "Open PR #%d already exists for branch '%s' — skipping creation.",
                existing.number,
                branch_name,
            )
            return PRResult(
                pr_number=existing.number,
                pr_url=existing.html_url,
                was_existing=True,
            )

        title = (
            f"fix: upgrade {change_summary.component_name} "
            f"from {change_summary.old_version} to {change_summary.new_version} "
            "(vulnerability remediation)"
        )
        body = self._build_pr_body(change_summary)

        try:
            pr = self._repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=base_branch,
                draft=False,
            )
        except GithubException as exc:
            raise RuntimeError(
                f"Failed to create PR for branch '{branch_name}': {exc.data}"
            ) from exc

        logger.info("Created PR #%d: %s", pr.number, pr.html_url)
        return PRResult(pr_number=pr.number, pr_url=pr.html_url, was_existing=False)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _find_open_pr(self, branch_name: str, base_branch: str):
        """Return the first open PR for head=branch_name, or None if none exists."""
        try:
            pulls = self._repo.get_pulls(
                state="open",
                head=f"{self._repo.owner.login}:{branch_name}",
                base=base_branch,
            )
            for pr in pulls:
                return pr
        except GithubException as exc:
            logger.warning("Error checking for existing PRs: %s", exc)
        return None

    def _build_pr_body(self, change_summary) -> str:
        files_list = "\n".join(f"- `{f}`" for f in change_summary.files_changed)
        cve_list = (
            ", ".join(change_summary.cve_ids) if change_summary.cve_ids else "see Nexus IQ report"
        )

        return f"""## OSS Vulnerability Remediation

**Component:** `{change_summary.component_name}`
**Previous version:** `{change_summary.old_version}`
**Remediated version:** `{change_summary.new_version}`
**CVEs addressed:** {cve_list}

---

### Changes made

{files_list}

### Rationale

{change_summary.rationale}

---

> This PR was opened automatically by the OSS Remediation Agent.
> A Watcher agent is monitoring CI and will attempt up to {change_summary.max_retries} fix cycles
> if CI fails due to the upgrade. If the retry limit is reached, a comment will be added here.
> Human review is required before merge.
"""

    def add_comment(self, pr_number: int, comment: str) -> None:
        """Add a comment to a PR (used by the Watcher agent for escalation notices)."""
        pr = self._repo.get_pull(pr_number)
        pr.create_issue_comment(comment)
        logger.info("Added comment to PR #%d", pr_number)
