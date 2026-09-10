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
        self._github_pat = github_pat
        self._active_token: Optional[str] = None
        self._gh: Optional[Github] = None
        self._repo_cached = None

    @property
    def _repo(self):
        """
        Dynamically provides the PyGithub Repo object with an active, unexpired token.
        Automatically re-authenticates if the previous token expired during long-running fixes (2h-8h).
        """
        try:
            from common.config import get_github_pat
            current_token = get_github_pat(self._repo_full_name) or self._github_pat or os.environ.get("GITHUB_PAT", "")
        except Exception:
            current_token = self._github_pat or os.environ.get("GITHUB_PAT", "")

        if self._repo_cached is None or self._active_token != current_token:
            self._active_token = current_token
            self._gh = Github(current_token)
            self._repo_cached = self._gh.get_repo(self._repo_full_name)
        return self._repo_cached

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

    def open_combined_remediation_pr(
        self,
        branch_name: str,
        base_branch: str,
        successful_fixes: list,
    ) -> PRResult:
        """
        Open a single pull request for multiple remediations on the given branch.
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

        title = "fix: multiple vulnerability remediations"
        
        body_parts = ["## OSS Vulnerability Remediation (Combined)\n"]
        for finding, record, change_summary in successful_fixes:
            cve_list = ", ".join(finding.cve_ids) if finding.cve_ids else "see Nexus IQ report"
            files_list = "\n".join(f"- `{f}`" for f in change_summary.files_changed)
            
            body_parts.append(f"### Component: `{finding.component_name}`")
            body_parts.append(f"**Previous version:** `{finding.current_version}`")
            body_parts.append(f"**Remediated version:** `{finding.recommended_version}`")
            body_parts.append(f"**CVEs addressed:** {cve_list}")
            body_parts.append(f"\n**Changes made:**\n{files_list}")
            body_parts.append(f"\n**Rationale:**\n{change_summary.rationale}\n---")

        body_parts.append("\n> This PR was opened automatically by the OSS Remediation Agent.")
        body_parts.append("> Human review is required before merge.")
        
        body = "\n".join(body_parts)

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

    def find_any_pr(self, branch_name: str, base_branch: str) -> Optional[PRResult]:
        """Return the most recent PR for head=branch_name in ANY state (open,
        closed, or merged), or None if no PR was ever opened for this branch.

        Read-only -- never creates anything. Used when a branch already
        exists from a prior run (main.py's _fix_one skip-path): the branch
        existing means a PR was very likely opened for it before, but that
        PR may since have been closed manually -- _find_open_pr's
        state="open" filter would miss it entirely, leaving the new tracking
        record permanently stuck at CREATED with no PR ever attached even
        though one genuinely exists. This surfaces it regardless of state so
        the dashboard can still link to it.
        """
        try:
            pulls = self._repo.get_pulls(
                state="all",
                head=f"{self._repo.owner.login}:{branch_name}",
                base=base_branch,
            )
            for pr in pulls:
                return PRResult(pr_number=pr.number, pr_url=pr.html_url, was_existing=True)
        except GithubException as exc:
            logger.warning("Error checking for any PR on branch '%s': %s", branch_name, exc)
        return None

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

    def open_triage_issue(
        self,
        finding,           # VulnerabilityFinding from scan_report_client
        bucket: int,
        rationale: str,
        kb_entry=None,     # Optional KnowledgeEntry
    ) -> int:
        """
        Open a GitHub Issue for a finding the agent cannot automatically fix (bucket 1 or 4).
        Idempotent: returns the existing issue number if one already exists for this component.
        """
        title = (
            f"[OSS Remediation] Manual triage: {finding.component_name} "
            f"{finding.current_version} → {finding.recommended_version}"
        )

        # Idempotency: search open issues with the triage label
        try:
            for issue in self._repo.get_issues(state="open", labels=["oss-remediation-triage"]):
                if issue.title == title:
                    logger.info(
                        "Triage issue already exists (#%d) for %s — skipping.",
                        issue.number, finding.component_name,
                    )
                    return issue.number
        except GithubException as exc:
            logger.warning("Could not search existing issues: %s", exc)

        bucket_labels = {
            1: "Bucket 1 — No fix path available",
            4: "Bucket 4 — Complex framework, major upgrade, no migration KB",
        }
        cve_list = ", ".join(finding.cve_ids) if finding.cve_ids else "see scan report"

        kb_section = ""
        if kb_entry and (kb_entry.breaking_changes or kb_entry.migration_steps):
            bc = "\n".join(f"- {c}" for c in kb_entry.breaking_changes)
            steps = "\n".join(f"{i}. {s}" for i, s in enumerate(kb_entry.migration_steps, 1))
            kb_section = f"""
### Knowledge Base analysis ({kb_entry.source})

**Breaking changes:**
{bc or "_(none documented)_"}

**Suggested migration steps:**
{steps or "_(none documented)_"}
"""

        body = f"""## OSS Remediation — Manual Triage Required

**Component:** `{finding.component_name}`
**Vulnerable version:** `{finding.current_version}`
**Recommended version:** `{finding.recommended_version}`
**Severity:** {finding.severity.upper()}
**CVEs:** {cve_list}

### Why the agent skipped this

**{bucket_labels.get(bucket, f'Bucket {bucket}')}**

{rationale}
{kb_section}
### Next steps

1. Review the CVEs linked above and confirm the recommended version is correct.
2. Assess the migration complexity manually.
3. Apply the fix in a dedicated branch and verify CI passes.
4. Close this issue once the PR is merged.

---
> Opened automatically by the OSS Remediation Agent (bucket {bucket}).
> Assign to the relevant team for prioritisation.
"""
        try:
            # Ensure the label exists before using it
            self._ensure_label("oss-remediation-triage", "e11d48", "Auto-triage issue from OSS Remediation Agent")
            issue = self._repo.create_issue(
                title=title,
                body=body,
                labels=["oss-remediation-triage"],
            )
            logger.info(
                "Opened triage issue #%d for %s (bucket %d).",
                issue.number, finding.component_name, bucket,
            )
            return issue.number
        except GithubException as exc:
            logger.error(
                "Failed to create triage issue for %s: %s", finding.component_name, exc
            )
            return -1

    def _ensure_label(self, name: str, color: str, description: str) -> None:
        try:
            self._repo.get_label(name)
        except GithubException:
            try:
                self._repo.create_label(name=name, color=color, description=description)
            except GithubException:
                pass  # label creation is best-effort
