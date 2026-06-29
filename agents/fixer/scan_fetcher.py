"""
ScanFetcher — triggers the security-scan workflow on the target repo via
workflow_dispatch, polls until the run completes, then downloads and extracts
the 'vulnerability-reports' artifact into SCAN_REPORT_PATH.

The workflow always uploads artifacts (if: always()), so artifacts are
available even when the run conclusion is 'failure' (expected: the app has
intentional CVEs that trip the OWASP failOnCVSS=7 threshold).
"""

import io
import logging
import os
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

WORKFLOW_FILE  = "security-scan.yml"
ARTIFACT_NAME  = "vulnerability-reports"
POLL_INTERVAL  = 15    # seconds between status checks
MAX_RUN_WAIT   = 1200  # 20 minutes — OWASP DC + Trivy + Grype takes ~8-12 min
RUN_FIND_WAIT  = 60    # seconds to wait for the dispatched run to appear in the API


class ScanFetchError(Exception):
    """Raised when the workflow trigger, poll, or artifact download fails."""


class ScanFetcher:
    """
    Trigger the security-scan workflow on the target repo and download
    the resulting vulnerability reports into the local scan-reports directory.
    """

    def __init__(
        self,
        repo_full_name: str,
        github_pat: str,
        report_dir: str,
        branch: str = "main",
    ):
        self._repo       = repo_full_name
        self._report_dir = Path(report_dir)
        self._branch     = branch
        self._headers    = {
            "Authorization":        f"Bearer {github_pat}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._base = f"https://api.github.com/repos/{repo_full_name}"

    # ── Public API ────────────────────────────────────────────────────────────

    def trigger_and_download(self) -> None:
        """
        Full pipeline: dispatch → find run → wait → download artifact.
        Raises ScanFetchError on any failure.
        """
        logger.info(
            "ScanFetcher: triggering %s on %s (branch=%s)",
            WORKFLOW_FILE, self._repo, self._branch,
        )
        before_epoch = int(time.time())
        self._dispatch()
        run_id = self._find_run(after_epoch=before_epoch)
        self._wait_for_run(run_id)
        self._download_artifact(run_id)

    # ── Step 1: dispatch ──────────────────────────────────────────────────────

    def _dispatch(self) -> None:
        url  = f"{self._base}/actions/workflows/{WORKFLOW_FILE}/dispatches"
        resp = requests.post(url, headers=self._headers, json={"ref": self._branch}, timeout=30)
        if resp.status_code != 204:
            raise ScanFetchError(
                f"Workflow dispatch failed: HTTP {resp.status_code} — {resp.text[:400]}"
            )
        logger.info("Workflow dispatched successfully.")

    # ── Step 2: find the run created by this dispatch ─────────────────────────

    def _find_run(self, after_epoch: int) -> int:
        """
        Poll the runs list until a workflow_dispatch run created at/after
        `after_epoch` appears. GitHub takes a few seconds to register the run.
        """
        deadline = time.time() + RUN_FIND_WAIT
        time.sleep(5)
        while time.time() < deadline:
            url  = (
                f"{self._base}/actions/runs"
                f"?event=workflow_dispatch&branch={self._branch}&per_page=5"
            )
            resp = requests.get(url, headers=self._headers, timeout=30)
            resp.raise_for_status()
            for run in resp.json().get("workflow_runs", []):
                if self._gh_ts_to_epoch(run["created_at"]) >= after_epoch - 10:
                    logger.info(
                        "Found run %s (status=%s created=%s)",
                        run["id"], run["status"], run["created_at"],
                    )
                    return run["id"]
            logger.debug("Run not yet visible — retrying in 5 s …")
            time.sleep(5)

        raise ScanFetchError(
            f"Timed out waiting for a new workflow run to appear "
            f"(waited {RUN_FIND_WAIT}s after dispatch)."
        )

    # ── Step 3: wait for completion ───────────────────────────────────────────

    def _wait_for_run(self, run_id: int) -> None:
        logger.info("Waiting for run %d to complete (timeout=%d s) …", run_id, MAX_RUN_WAIT)
        deadline = time.time() + MAX_RUN_WAIT
        while time.time() < deadline:
            url  = f"{self._base}/actions/runs/{run_id}"
            resp = requests.get(url, headers=self._headers, timeout=30)
            resp.raise_for_status()
            run        = resp.json()
            status     = run["status"]
            conclusion = run.get("conclusion")
            logger.info("Run %d: status=%s conclusion=%s", run_id, status, conclusion)

            if status == "completed":
                # 'failure' is expected — the app has intentional CVEs.
                # Artifacts are uploaded with 'if: always()' so they exist either way.
                if conclusion in ("cancelled", "skipped", "timed_out", "action_required"):
                    raise ScanFetchError(
                        f"Run {run_id} ended with conclusion={conclusion!r}. "
                        "Cannot download artifacts."
                    )
                return

            time.sleep(POLL_INTERVAL)

        raise ScanFetchError(
            f"Run {run_id} did not complete within {MAX_RUN_WAIT}s."
        )

    # ── Step 4: download and extract artifact ─────────────────────────────────

    def _download_artifact(self, run_id: int) -> None:
        artifact = self._find_artifact(run_id)
        size_mb  = artifact.get("size_in_bytes", 0) / 1_048_576
        logger.info(
            "Downloading artifact '%s' (%.1f MB) …", ARTIFACT_NAME, size_mb
        )

        download_url = artifact["archive_download_url"]
        resp = requests.get(
            download_url,
            headers=self._headers,
            allow_redirects=True,
            stream=True,
            timeout=120,
        )
        resp.raise_for_status()

        self._report_dir.mkdir(parents=True, exist_ok=True)
        raw = b"".join(resp.iter_content(chunk_size=65_536))

        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for member in zf.namelist():
                zf.extract(member, self._report_dir)
                logger.info("  extracted: %s", member)

        logger.info("Scan reports ready in %s", self._report_dir)

    def _find_artifact(self, run_id: int) -> dict:
        url  = f"{self._base}/actions/runs/{run_id}/artifacts"
        resp = requests.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        artifacts = resp.json().get("artifacts", [])
        artifact  = next((a for a in artifacts if a["name"] == ARTIFACT_NAME), None)
        if artifact is None:
            names = [a["name"] for a in artifacts]
            raise ScanFetchError(
                f"Artifact '{ARTIFACT_NAME}' not found in run {run_id}. "
                f"Available: {names}"
            )
        return artifact

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _gh_ts_to_epoch(ts: str) -> int:
        """Convert a GitHub ISO 8601 timestamp ('2024-01-15T10:30:00Z') to epoch seconds."""
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return int(dt.astimezone(timezone.utc).timestamp())
