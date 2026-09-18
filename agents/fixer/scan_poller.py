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

from common.config import get_target_repo, get_github_pat, is_scan_requested, set_scan_requested

logger = logging.getLogger(__name__)

WORKFLOW_FILE     = "security-scan.yml"
ARTIFACT_NAME     = "vulnerability-reports"
DEFAULT_INTERVAL  = 60          # seconds between polls
CHECKPOINT_FILE   = "scan_poll_checkpoint.json"
SKIP_CONCLUSIONS  = {"cancelled", "skipped", "action_required", "timed_out"}


class ScanPoller:
    """
    Background poller that detects newly completed security-scan.yml runs,
    can automatically dispatch scans if missing or enabled, and downloads
    the resulting artifact so the fixer can act on it.

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
        auto_dispatch: Optional[bool] = None,
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

        if auto_dispatch is not None:
            self._auto_dispatch = auto_dispatch
        else:
            self._auto_dispatch = os.environ.get("AUTO_FETCH_SCAN", "0") == "1"

        self._has_dispatched_initial = False

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def poll_interval(self) -> int:
        return self._interval

    def reset_window_dispatch(self) -> None:
        """Allow a new scan to be dispatched for a new active window."""
        self._has_dispatched_initial = False

    def clear_reports_and_checkpoint(self) -> None:
        """Purge all report files and reset checkpoint file."""
        import shutil
        try:
            if self._report_dir.exists():
                for item in self._report_dir.iterdir():
                    if item.is_file():
                        item.unlink(missing_ok=True)
                    elif item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                logger.info("ScanPoller: cleared old reports at %s", self._report_dir)
        except Exception as exc:
            logger.warning("ScanPoller: error clearing report dir %s: %s", self._report_dir, exc)

        try:
            if self._checkpoint.exists():
                self._checkpoint.write_text(json.dumps({"last_run_id": None, "last_poll_time": time.time()}), encoding="utf-8")
                logger.info("ScanPoller: reset checkpoint at %s", self._checkpoint)
        except Exception as exc:
            logger.warning("ScanPoller: error resetting checkpoint %s: %s", self._checkpoint, exc)

    def has_reports(self) -> bool:
        """Check if scan report files currently exist in the report directory."""
        if not self._report_dir.exists():
            return False
        return bool(list(self._report_dir.rglob("*.json")))

    def is_scan_running(self) -> bool:
        """Check if any security-scan run is currently queued or in-progress."""
        url = (
            f"{self._base}/actions/workflows/{WORKFLOW_FILE}/runs"
            f"?branch={self._branch}&per_page=5"
        )
        try:
            resp = requests.get(url, headers=self._headers, timeout=30)
            if resp.status_code == 200:
                for r in resp.json().get("workflow_runs", []):
                    if r.get("status") in ("in_progress", "queued", "requested", "waiting"):
                        return True
        except Exception as exc:
            logger.warning("ScanPoller: error checking active runs: %s", exc)
        return False

    def dispatch_scan(self) -> bool:
        """Trigger security-scan.yml via GitHub Actions workflow_dispatch."""
        url = f"{self._base}/actions/workflows/{WORKFLOW_FILE}/dispatches"
        try:
            resp = requests.post(url, headers=self._headers, json={"ref": self._branch}, timeout=30)
            if resp.status_code == 204:
                logger.info("ScanPoller: successfully dispatched workflow %s on branch %s", WORKFLOW_FILE, self._branch)
                return True
            else:
                logger.warning("ScanPoller: workflow dispatch returned HTTP %s: %s", resp.status_code, resp.text[:200])
        except Exception as exc:
            logger.error("ScanPoller: failed to dispatch workflow %s: %s", WORKFLOW_FILE, exc)
        return False

    def poll_once(self) -> bool:
        """Runs a single poll cycle."""
        return self._poll_once()

    def poll_forever(self) -> None:
        logger.info(
            "ScanPoller: started. repo=%s branch=%s interval=%ds auto_dispatch=%s",
            self._repo, self._branch, self._interval, self._auto_dispatch,
        )
        while True:
            try:
                self._poll_once()
            except Exception as exc:
                logger.error("ScanPoller: unexpected error: %s", exc, exc_info=True)
            time.sleep(self._interval)

    def run_nightly(self, max_wait_seconds: int = 7200) -> None:
        """Run one scan cycle, polling only until its completed report arrives."""
        self._has_dispatched_initial = False
        deadline = time.monotonic() + max_wait_seconds
        logger.info(
            "ScanPoller: starting nightly scan cycle (maximum wait %ds).",
            max_wait_seconds,
        )
        while time.monotonic() < deadline:
            try:
                if self._poll_once():
                    logger.info("ScanPoller: nightly scan cycle completed.")
                    return
            except Exception as exc:
                logger.error("ScanPoller: nightly cycle error: %s", exc, exc_info=True)
            time.sleep(min(self._interval, max(deadline - time.monotonic(), 0)))
        logger.error(
            "ScanPoller: nightly scan did not produce a new completed report within %ds.",
            max_wait_seconds,
        )

    # ── Poll cycle ────────────────────────────────────────────────────────────

    def _poll_once(self) -> bool:
        current_repo = get_target_repo()
        current_pat = get_github_pat()
        if current_repo and current_repo != self._repo:
            logger.info("ScanPoller: target repo switched from %s to %s — clearing old reports and checkpoint", self._repo, current_repo)
            self._repo = current_repo
            self._base = f"https://api.github.com/repos/{current_repo}"
            self._has_dispatched_initial = False
            self.clear_reports_and_checkpoint()
        if current_pat:
            self._headers["Authorization"] = f"Bearer {current_pat}"

        # Touch checkpoint activity so dashboard displays active status
        self._touch_checkpoint()

        # If auto-dispatch is enabled, or if no reports exist yet:
        # Check if a scan is running; if not, trigger a new scan automatically!
        if is_scan_requested() and (self._auto_dispatch or not self.has_reports()) and not self._has_dispatched_initial:
            if not self.is_scan_running():
                logger.info(
                    "ScanPoller: auto_dispatch=%s, has_reports=%s — automatically dispatching %s",
                    self._auto_dispatch, self.has_reports(), WORKFLOW_FILE,
                )
                if self.dispatch_scan():
                    set_scan_requested(False)
            else:
                logger.info("ScanPoller: workflow %s is already in progress/queued.", WORKFLOW_FILE)
            self._has_dispatched_initial = True

        last_id = self._load_checkpoint()
        run = self._latest_completed_run()
        if run is None:
            logger.debug("ScanPoller: no completed runs found yet.")
            return False

        run_id     = run["id"]
        conclusion = run.get("conclusion", "")

        if run_id == last_id:
            logger.debug("ScanPoller: run %d already processed.", run_id)
            return False

        if conclusion in SKIP_CONCLUSIONS:
            logger.warning(
                "ScanPoller: latest run %d ended with conclusion=%s — skipping.",
                run_id, conclusion,
            )
            self._save_checkpoint(run_id)
            return False

        logger.info(
            "ScanPoller: new completed run %d (conclusion=%s). Downloading artifact.",
            run_id, conclusion,
        )
        self._download_artifact(run_id)
        self._save_checkpoint(run_id)
        logger.info("ScanPoller: reports ready. Invoking fixer.")
        self._callback()
        return True

    # ── GitHub helpers ────────────────────────────────────────────────────────

    def _latest_completed_run(self) -> Optional[dict]:
        url  = (
            f"{self._base}/actions/workflows/{WORKFLOW_FILE}/runs"
            f"?branch={self._branch}&status=completed&per_page=1"
        )
        resp = requests.get(url, headers=self._headers, timeout=30)
        if resp.status_code == 404:
            raise RuntimeError(
                f"GitHub workflow {WORKFLOW_FILE!r} was not found for "
                f"{self._repo}. Verify GITHUB_REPO_TARGET, the PAT's "
                "repository access, and that .github/workflows/security-scan.yml "
                "exists on the target repository's default branch."
            )
        resp.raise_for_status()
        runs = resp.json().get("workflow_runs", [])
        return runs[0] if runs else None

    def _download_artifact(self, run_id: int) -> None:
        url  = f"{self._base}/actions/runs/{run_id}/artifacts"
        resp = requests.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        artifacts = resp.json().get("artifacts", [])
        artifact = next(
            (a for a in artifacts if a["name"] in ("vulnerability-reports", "dependency-check-report", "trivy-reports", "grype-reports")),
            next((a for a in artifacts if "report" in a["name"].lower()), artifacts[0] if artifacts else None),
        )
        if artifact is None:
            logger.warning("ScanPoller: no artifacts found in run %d", run_id)
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

    def _touch_checkpoint(self) -> None:
        try:
            self._checkpoint.parent.mkdir(parents=True, exist_ok=True)
            last_id = self._load_checkpoint()
            self._checkpoint.write_text(
                json.dumps({"last_run_id": last_id, "last_poll_time": time.time()}),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.debug("ScanPoller: cannot touch checkpoint: %s", exc)

    def _save_checkpoint(self, run_id: int) -> None:
        try:
            self._checkpoint.parent.mkdir(parents=True, exist_ok=True)
            self._checkpoint.write_text(
                json.dumps({"last_run_id": run_id, "last_poll_time": time.time()}),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("ScanPoller: cannot write checkpoint (%s) — progress will not be persisted", exc)
