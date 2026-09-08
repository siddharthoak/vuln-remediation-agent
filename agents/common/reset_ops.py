"""
Shared Reset Operations for OSS Remediation Agent.

Resets GitHub test PRs, remote remediation branches, local tracking state,
scan checkpoints, and scan reports.

CRITICAL: Preserves kb.json by default so learned knowledge and playbooks
are reused across repositories.
"""

import glob
import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from common.config import get_target_repo, get_github_pat

logger = logging.getLogger(__name__)


def reset_repository_state(
    repo: Optional[str] = None,
    pat: Optional[str] = None,
    keep_kb: bool = True,
) -> dict:
    """
    Performs full environment reset for the target repo:
    1. Closes open PRs on GitHub
    2. Deletes remote fix branches on GitHub
    3. Clears tracking.json
    4. Clears scan_poll_checkpoint.json
    5. Cleans up downloaded scan reports
    6. Preserves kb.json (when keep_kb=True)
    """
    target_repo = repo or get_target_repo()
    target_pat = pat or get_github_pat()

    summary = {
        "repo": target_repo,
        "prs_closed": [],
        "branches_deleted": [],
        "tracking_cleared": False,
        "checkpoint_cleared": False,
        "reports_deleted": [],
        "kb_preserved": keep_kb,
        "errors": [],
    }

    if not target_repo:
        summary["errors"].append("No target repository configured.")
        return summary

    # 1. Close open PRs and delete fix branches on GitHub
    if target_pat:
        headers = {
            "Authorization": f"token {target_pat}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "vuln-remediation-agent",
        }
        try:
            url = f"https://api.github.com/repos/{target_repo}/pulls?state=open"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                prs = json.loads(response.read().decode("utf-8"))

            for pr in prs:
                pr_num = pr["number"]
                branch = pr["head"]["ref"]

                # Close PR
                patch_url = f"https://api.github.com/repos/{target_repo}/pulls/{pr_num}"
                patch_data = json.dumps({"state": "closed"}).encode("utf-8")
                patch_req = urllib.request.Request(
                    patch_url, data=patch_data, headers=headers, method="PATCH"
                )
                try:
                    urllib.request.urlopen(patch_req, timeout=10)
                    summary["prs_closed"].append(pr_num)
                    logger.info("Closed PR #%d on %s", pr_num, target_repo)
                except Exception as e:
                    summary["errors"].append(f"Failed to close PR #{pr_num}: {e}")

                # Delete branch if remediation branch
                if branch.startswith("fix/"):
                    del_url = f"https://api.github.com/repos/{target_repo}/git/refs/heads/{branch}"
                    del_req = urllib.request.Request(del_url, headers=headers, method="DELETE")
                    try:
                        urllib.request.urlopen(del_req, timeout=10)
                        summary["branches_deleted"].append(branch)
                        logger.info("Deleted remote branch %s on %s", branch, target_repo)
                    except Exception as e:
                        summary["errors"].append(f"Failed to delete branch {branch}: {e}")

        except Exception as e:
            summary["errors"].append(f"GitHub API query failed for {target_repo}: {e}")
    else:
        summary["errors"].append("No GitHub PAT provided; skipped GitHub remote cleanup.")

    # 2. Reset tracking.json
    for t_path in [
        os.environ.get("TRACKING_STORE_PATH"),
        "/data/tracking.json",
        "data/tracking.json",
        "./data/tracking.json",
    ]:
        if not t_path:
            continue
        try:
            p = Path(t_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}", encoding="utf-8")
            summary["tracking_cleared"] = True
            logger.info("Reset tracking store at %s", p)
            break
        except Exception as e:
            logger.debug("Could not write tracking to %s: %s", t_path, e)

    # 3. Reset scan_poll_checkpoint.json
    for cp_path in [
        "/data/scan_poll_checkpoint.json",
        "data/scan_poll_checkpoint.json",
        "./data/scan_poll_checkpoint.json",
    ]:
        try:
            p = Path(cp_path)
            if p.parent.exists():
                p.write_text("{}", encoding="utf-8")
                summary["checkpoint_cleared"] = True
                logger.info("Reset scan poll checkpoint at %s", p)
                break
        except Exception as e:
            logger.debug("Could not write checkpoint to %s: %s", cp_path, e)

    # 4. Clean up scan reports
    report_dirs = [
        os.environ.get("SCAN_REPORT_PATH"),
        "/reports",
        "scan-reports",
        "./scan-reports",
    ]
    for rd in report_dirs:
        if not rd or not os.path.isdir(rd):
            continue
        for rep in glob.glob(os.path.join(rd, "*.json")):
            try:
                os.remove(rep)
                summary["reports_deleted"].append(os.path.basename(rep))
            except Exception as e:
                summary["errors"].append(f"Failed to delete report {rep}: {e}")

    # 5. Handle KB store: KEEP by default
    if not keep_kb:
        for kb_path in [
            os.environ.get("KB_STORE_PATH"),
            "/data/kb.json",
            "data/kb.json",
            "./data/kb.json",
        ]:
            if not kb_path:
                continue
            try:
                p = Path(kb_path)
                if p.exists():
                    p.write_text("{}", encoding="utf-8")
                    summary["kb_preserved"] = False
                    break
            except Exception:
                pass
    else:
        logger.info("Preserving knowledge base (kb.json) across reset.")

    return summary
