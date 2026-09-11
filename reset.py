#!/usr/bin/env python3
"""
Reset script for OSS Remediation Agent.

Dynamically detects repository target and GitHub PAT from:
1. data/config.json
2. config/.env
3. Environment variables

Closes open fix PRs on GitHub, deletes remote fix branches,
resets tracking and checkpoint state, and cleans scan reports.

CRITICAL: Preserves data/kb.json so learned fixes and playbooks
are not lost when switching repositories!
"""

import os
import sys

# Add agents directory to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agents"))

from common.config import get_target_repo, get_github_pat
from common.reset_ops import reset_repository_state


def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python reset.py [owner/repo]")
        print("Resets GitHub remediation PRs, remote fix branches, tracking state, and checkpoints.")
        sys.exit(0)

    repo = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else get_target_repo()
    pat = get_github_pat(repo=repo)

    print(f"Target repository: {repo or '(none)'}")
    if not repo:
        print("ERROR: No target repository configured in config/.env or data/config.json")
        sys.exit(1)

    print("Running reset (preserving Knowledge Base)...")
    res = reset_repository_state(repo=repo, pat=pat, keep_kb=True)

    if res["prs_closed"]:
        print(f"Closed PRs: {res['prs_closed']}")
    else:
        print("No open PRs to close.")

    if res["branches_deleted"]:
        print(f"Deleted branches: {res['branches_deleted']}")
    else:
        print("No remote fix branches to delete.")

    if res.get("triage_issues_closed"):
        print(f"Closed triage issues: {res['triage_issues_closed']}")
    else:
        print("No open triage issues to close.")


    if res["tracking_cleared"]:
        print("Cleared data/tracking.json -> {}")
    if res["checkpoint_cleared"]:
        print("Cleared data/scan_poll_checkpoint.json -> {}")

    for rep in res["reports_deleted"]:
        print(f"Deleted report: {rep}")

    print("Knowledge base preserved: kb.json was NOT wiped.")
    if res["errors"]:
        print(f"Warnings/Errors: {res['errors']}")

    print("Reset completed successfully.")


if __name__ == "__main__":
    main()
