"""
ScanPoller — watches for newly completed security-scan.yml workflow runs.

Polls GitHub Actions on a configurable interval. When a new completed run
appears (ID greater than the last-processed run), downloads the
vulnerability-reports artifact into SCAN_REPORT_PATH and calls the
supplied callback so the fixer can process it immediately.

Used by the fixer in server/daemon mode so that a manually triggered
GitHub Actions scan is picked up without `docker compose run --rm fixer`.
"""

import io
import json
import logging
import os
import time
import zipfile
from pathlib import Path
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

WORKFLOW_FILE     = "security-scan.yml"
ARTIFACT_NAME     = "vulnerability-reports"
DEFAULT_INTERVAL  = 60          # seconds between polls
CHECKPOINT_FILE   = "scan_poll_checkpoint.json"
SKIP_CONCLUSIONS  = {"cancelled", "skipped", "action_required", "timed_out"}


class ScanPoller:
    """
    Background poller that detects newly completed security-scan.yml runs and
    downloads the resulting artifact so the fixer can act on it.

    Checkpoint: last processed run ID is persisted next to tracking.json in
    /data so the poller doesn't re-process completed runs after a restart.
    """

    def __init__(
        self,
        repo_full_name: str,
        github_pat: str,
        report_dir: str,
        on_new_scan_ready: Callable[[], None],
        poll_interval: int = DEFAULT_INTERVAL,
        branch: str = "main",
    ):
        self._repo       = repo_full_name
        self._report_dir = Path(report_dir)
        self._callback   = on_new_scan_ready
        self._interval   = poll_interval
        self._branch     = branch
        self._headers    = {
            "Authorization":        f"Bearer {github_pat}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._base       = f"https://api.github.com/repos/{repo_full_name}"

        tracking_path = os.environ.get("TRACKING_STORE_PATH", "/data/tracking.json")
        self._checkpoint = Path(os.path.dirname(tracking_path)) / CHECKPOINT_FILE

    # ── Public API ────────────────────────────────────────────────────────────

    def poll_forever(self) -> None:
        logger.info(
            "ScanPoller: started. repo=%s branch=%s interval=%ds",
            self._repo, self._branch, self._interval,
        )
        while True:
            try:
                self._poll_once()
            except Exception as exc:
                logger.error("ScanPoller: unexpected error: %s", exc, exc_info=True)
            time.sleep(self._interval)

    # ── Poll cycle ────────────────────────────────────────────────────────────

    def _poll_once(self) -> None:
        last_id = self._load_checkpoint()
        run = self._latest_completed_run()
        if run is None:
            logger.debug("ScanPoller: no completed runs found yet.")
            return

        run_id     = run["id"]
        conclusion = run.get("conclusion", "")

        if run_id == last_id:
            logger.debug("ScanPoller: run %d already processed.", run_id)
            return

        if conclusion in SKIP_CONCLUSIONS:
            logger.warning(
                "ScanPoller: latest run %d ended with conclusion=%s — skipping.",
                run_id, conclusion,
            )
            self._save_checkpoint(run_id)
            return

        logger.info(
            "ScanPoller: new completed run %d (conclusion=%s). Downloading artifact.",
            run_id, conclusion,
        )
        self._download_artifact(run_id)
        self._save_checkpoint(run_id)
        logger.info("ScanPoller: reports ready. Invoking fixer.")
        self._callback()

    # ── GitHub helpers ────────────────────────────────────────────────────────

    def _latest_completed_run(self) -> Optional[dict]:
        url  = (
            f"{self._base}/actions/workflows/{WORKFLOW_FILE}/runs"
            f"?branch={self._branch}&status=completed&per_page=1"
        )
        resp = requests.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        runs = resp.json().get("workflow_runs", [])
        return runs[0] if runs else None

    def _download_artifact(self, run_id: int) -> None:
        url  = f"{self._base}/actions/runs/{run_id}/artifacts"
        resp = requests.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        artifacts = resp.json().get("artifacts", [])
        artifact  = next((a for a in artifacts if a["name"] == ARTIFACT_NAME), None)
        if artifact is None:
            names = [a["name"] for a in artifacts]
            logger.warning(
                "ScanPoller: artifact '%s' not found in run %d. Available: %s",
                ARTIFACT_NAME, run_id, names,
            )
            return

        size_mb = artifact.get("size_in_bytes", 0) / 1_048_576
        logger.info("ScanPoller: downloading %.1f MB artifact …", size_mb)

        dl_resp = requests.get(
            artifact["archive_download_url"],
            headers=self._headers,
            allow_redirects=True,
            stream=True,
            timeout=120,
        )
        dl_resp.raise_for_status()

        self._report_dir.mkdir(parents=True, exist_ok=True)
        raw = b"".join(dl_resp.iter_content(chunk_size=65_536))
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for member in zf.namelist():
                zf.extract(member, self._report_dir)
                logger.debug("ScanPoller: extracted %s", member)
        logger.info("ScanPoller: all reports extracted to %s", self._report_dir)

    # ── Checkpoint ────────────────────────────────────────────────────────────

    def _load_checkpoint(self) -> Optional[int]:
        try:
            data = json.loads(self._checkpoint.read_text(encoding="utf-8"))
            return data.get("last_run_id")
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        except OSError as exc:
            logger.warning("ScanPoller: cannot read checkpoint (%s) — starting from latest run", exc)
            return None

    def _save_checkpoint(self, run_id: int) -> None:
        try:
            self._checkpoint.parent.mkdir(parents=True, exist_ok=True)
            self._checkpoint.write_text(
                json.dumps({"last_run_id": run_id}), encoding="utf-8"
            )
        except OSError as exc:
            logger.warning("ScanPoller: cannot write checkpoint (%s) — progress will not be persisted", exc)
