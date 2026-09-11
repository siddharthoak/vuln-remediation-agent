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
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from common.config import get_target_repo, get_target_repos, get_github_pat

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _github_api_get(url: str, headers: dict) -> list:
    """Helper to fetch a list from GitHub API with basic pagination support."""
    results = []
    page = 1
    delim = "&" if "?" in url else "?"
    while page <= 10:  # limit max pages for safety
        page_url = f"{url}{delim}per_page=100&page={page}"
        req = urllib.request.Request(page_url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if not data or not isinstance(data, list):
                    break
                results.extend(data)
                if len(data) < 100:
                    break
                page += 1
        except Exception:
            break
    return results


def reset_repository_state(
    repo: Optional[str] = None,
    pat: Optional[str] = None,
    keep_kb: bool = True,
) -> dict:
    """
    Performs full environment reset for the target repo:
    1. Closes open PRs on GitHub (remediation branches)
    2. Deletes remote fix branches on GitHub
    3. Closes open manual triage issues on GitHub
    4. Clears tracking.json
    5. Clears scan_poll_checkpoint.json
    6. Cleans up downloaded scan reports
    7. Cleans up uploads and downloads
    8. Preserves kb.json (when keep_kb=True)
    """
    target_repo = repo or get_target_repo()
    target_pat = pat or get_github_pat(target_repo)

    summary = {
        "repo": target_repo,
        "prs_closed": [],
        "branches_deleted": [],
        "triage_issues_closed": [],
        "tracking_cleared": False,
        "checkpoint_cleared": False,
        "reports_deleted": [],
        "kb_preserved": keep_kb,
        "errors": [],
    }

    if not target_repo:
        summary["errors"].append("No target repository configured.")
        return summary

    # 1. GitHub cleanups: PRs, Branches, and Triage Issues
    if target_pat:
        headers = {
            "Authorization": f"token {target_pat}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "vuln-remediation-agent",
        }
        # 1a. Close open PRs and delete associated branches
        try:
            prs = _github_api_get(f"https://api.github.com/repos/{target_repo}/pulls?state=open", headers)
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
                        if branch not in summary["branches_deleted"]:
                            summary["branches_deleted"].append(branch)
                        logger.info("Deleted remote branch %s on %s", branch, target_repo)
                    except Exception as e:
                        summary["errors"].append(f"Failed to delete branch {branch}: {e}")

            # 1b. Also delete any orphaned remote fix/* branches not tied to currently open PRs
            try:
                all_branches = _github_api_get(f"https://api.github.com/repos/{target_repo}/branches", headers)
                for b in all_branches:
                    b_name = b.get("name", "")
                    if b_name.startswith("fix/") and b_name not in summary["branches_deleted"]:
                        del_url = f"https://api.github.com/repos/{target_repo}/git/refs/heads/{b_name}"
                        del_req = urllib.request.Request(del_url, headers=headers, method="DELETE")
                        try:
                            urllib.request.urlopen(del_req, timeout=10)
                            summary["branches_deleted"].append(b_name)
                            logger.info("Deleted orphaned remote branch %s on %s", b_name, target_repo)
                        except Exception as e:
                            summary["errors"].append(f"Failed to delete branch {b_name}: {e}")
            except Exception as e:
                logger.debug("Could not inspect all branches on %s: %s", target_repo, e)

            # 1c. Close open triage issues created by the agent
            try:
                open_issues = _github_api_get(f"https://api.github.com/repos/{target_repo}/issues?state=open", headers)
                for issue in open_issues:
                    if "pull_request" in issue:
                        continue
                    issue_num = issue.get("number")
                    labels = [lbl.get("name") if isinstance(lbl, dict) else str(lbl) for lbl in issue.get("labels", [])]
                    title = issue.get("title", "")
                    if "oss-remediation-triage" in labels or title.startswith("[OSS Remediation]"):
                        patch_url = f"https://api.github.com/repos/{target_repo}/issues/{issue_num}"
                        patch_data = json.dumps({"state": "closed"}).encode("utf-8")
                        patch_req = urllib.request.Request(patch_url, data=patch_data, headers=headers, method="PATCH")
                        try:
                            urllib.request.urlopen(patch_req, timeout=10)
                            summary["triage_issues_closed"].append(issue_num)
                            logger.info("Closed triage issue #%d on %s", issue_num, target_repo)
                        except Exception as e:
                            summary["errors"].append(f"Failed to close triage issue #{issue_num}: {e}")
            except Exception as e:
                logger.debug("Could not clean up triage issues on %s: %s", target_repo, e)

        except Exception as e:
            summary["errors"].append(f"GitHub API query failed for {target_repo}: {e}")
    else:
        summary["errors"].append("No GitHub PAT provided; skipped GitHub remote cleanup.")

    # 2. Reset tracking.json (checks repo root first, then container / env paths)
    tracking_candidates = [
        Path(os.environ["TRACKING_STORE_PATH"]) if os.environ.get("TRACKING_STORE_PATH") else None,
        _REPO_ROOT / "data" / "tracking.json",
        Path("data/tracking.json"),
        Path("./data/tracking.json"),
    ]
    if os.name != "nt" and Path("/data").exists():
        tracking_candidates.insert(0, Path("/data/tracking.json"))

    for p in tracking_candidates:
        if not p:
            continue
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}", encoding="utf-8")
            summary["tracking_cleared"] = True
            logger.info("Reset tracking store at %s", p)
        except Exception as e:
            logger.debug("Could not write tracking to %s: %s", p, e)

    # Clean stray C:\data\tracking.json on Windows if it exists
    if os.name == "nt":
        for stray in [Path("C:/data/tracking.json"), Path("C:/data/scan_poll_checkpoint.json")]:
            try:
                if stray.exists():
                    stray.write_text("{}", encoding="utf-8")
            except Exception:
                pass

    # 3. Reset scan_poll_checkpoint.json
    # Fetch the latest completed run ID on GitHub so that any running ScanPoller daemon does NOT
    # immediately treat existing prior scans as "new" and re-open a PR within 60 seconds of reset!
    latest_run_id = None
    if target_pat and target_repo:
        try:
            runs_url = f"https://api.github.com/repos/{target_repo}/actions/workflows/security-scan.yml/runs?status=completed&per_page=1"
            req = urllib.request.Request(runs_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                runs = data.get("workflow_runs", [])
                if runs and "id" in runs[0]:
                    latest_run_id = runs[0]["id"]
        except Exception as e:
            logger.debug("Could not fetch latest completed run ID during checkpoint reset: %s", e)

    checkpoint_payload = (
        json.dumps({"last_run_id": latest_run_id, "last_poll_time": time.time()})
        if latest_run_id
        else "{}"
    )

    checkpoint_candidates = [
        _REPO_ROOT / "data" / "scan_poll_checkpoint.json",
        Path("data/scan_poll_checkpoint.json"),
        Path("./data/scan_poll_checkpoint.json"),
    ]
    if os.name != "nt" and Path("/data").exists():
        checkpoint_candidates.insert(0, Path("/data/scan_poll_checkpoint.json"))

    for p in checkpoint_candidates:
        try:
            if p.parent.exists() or p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(checkpoint_payload, encoding="utf-8")
                summary["checkpoint_cleared"] = True
                logger.info("Reset scan poll checkpoint at %s (checkpointed to run_id=%s)", p, latest_run_id)
        except Exception as e:
            logger.debug("Could not write checkpoint to %s: %s", p, e)

    # 4. Clean up scan reports
    report_dirs = [
        Path(os.environ["SCAN_REPORT_PATH"]) if os.environ.get("SCAN_REPORT_PATH") else None,
        _REPO_ROOT / "scan-reports",
        Path("scan-reports"),
        Path("./scan-reports"),
    ]
    if os.name != "nt" and Path("/reports").exists():
        report_dirs.insert(0, Path("/reports"))

    for rd in report_dirs:
        if not rd or not rd.is_dir():
            continue
        for rep in rd.glob("*.json"):
            try:
                rep.unlink(missing_ok=True)
                summary["reports_deleted"].append(rep.name)
            except Exception as e:
                summary["errors"].append(f"Failed to delete report {rep}: {e}")

    # 5. Clean up temporary push locks
    try:
        temp_dir = Path(tempfile.gettempdir())
        for lock_file in temp_dir.glob("fixer_push_*.lock"):
            lock_file.unlink(missing_ok=True)
    except Exception:
        pass

    # 6. Handle KB store: KEEP by default
    if not keep_kb:
        kb_candidates = [
            Path(os.environ["KB_STORE_PATH"]) if os.environ.get("KB_STORE_PATH") else None,
            _REPO_ROOT / "data" / "kb.json",
            Path("data/kb.json"),
            Path("./data/kb.json"),
        ]
        if os.name != "nt" and Path("/data").exists():
            kb_candidates.insert(0, Path("/data/kb.json"))

        for p in kb_candidates:
            if not p:
                continue
            try:
                if p.exists():
                    p.write_text("{}", encoding="utf-8")
                    summary["kb_preserved"] = False
                    break
            except Exception:
                pass
    else:
        logger.info("Preserving knowledge base (kb.json) across reset.")

    return summary

