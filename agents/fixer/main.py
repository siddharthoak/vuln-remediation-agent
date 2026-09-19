"""
Fixer Agent entry point.

Identical to nexus-remediation-agent/agents/fixer/main.py with one change:
  NexusIQClient / nexus_client → ScanReportClient / scan_report_client

Mode A (fresh scan) and Mode B (Watcher retry) routing, parallelism,
tracking record lifecycle, and PR creation are all UNCHANGED.
"""

import logging
import os
import sys
import multiprocessing
import tempfile
import threading
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json as _json
from types import SimpleNamespace
from typing import Optional

from github import Github
from scan_report_client import ScanReportClient, ScanReportError
from scan_fetcher import ScanFetcher, ScanFetchError
from scan_poller import ScanPoller
from repo_ops import DiffReviewResult, RepoOps
from code_fixer import CodeFixer, InvalidRetryError
from pr_client import PRClient
from engines.base import EngineExecutionError
from ecosystems.factory import get_ecosystem, get_manifest_file
from ecosystems.base import EcosystemError
from ecosystems.maven import PomXMLError
from ecosystems.npm import PackageJsonError
from ecosystems.python import PythonManifestError

from common.tracking_store import (
    make_tracking_store,
    make_fresh_record,
    TrackingStatus,
)
from common.knowledge_store import make_knowledge_store
from common.file_lock import FileLock
from datetime import datetime
from zoneinfo import ZoneInfo
from common.nightly_scheduler import (
    get_active_window_status,
    sleep_until_active_window,
    sleep_until_next_run,
    format_duration,
)
from common.config import (
    get_target_repo,
    get_target_repos,
    get_github_pat,
    is_nightly_run_enabled,
    get_nightly_run_time,
    get_nightly_scan_max_wait_seconds,
    set_scan_requested,
)
from classifier.classifier import Classifier, ClassifierResult
try:
    from demo_scan_reports import write_demo_reports
except ImportError:
    try:
        from scripts.generate_demo_scan_reports import write_demo_reports
    except ImportError:
        write_demo_reports = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("fixer.main")

MAX_PARALLEL_FIXES = int(os.environ.get("MAX_PARALLEL_FIXES", "2"))
AUTO_FETCH_SCAN    = os.environ.get("AUTO_FETCH_SCAN", "0") == "1"

# Prevents concurrent fresh-scan runs if the poller fires while one is in progress.
_fresh_scan_lock = threading.Lock()

# ── KB import job state (POST /import-kb, GET /import-kb/status) ──────────────
# In-memory only -- one fixer-server process, no need for a persisted job
# store. Guarded by _kb_import_lock so a second trigger while one is already
# running gets told so (409) instead of racing the same KnowledgeAgent/store.
_kb_import_lock = threading.Lock()
_kb_import_state = {"status": "idle", "current": 0, "total": 0, "message": ""}

# ── Live scan job state (POST /scan/live, GET /scan/live/status) ──────────────
# Same in-memory/lock-guarded shape as KB import above. Genuinely slow (the
# underlying ScanFetcher.trigger_and_download() dispatches a real GitHub
# Actions run and can block up to ~20 minutes), so this always runs in a
# background thread -- never call _run_scan_fetch() synchronously from a
# request handler.
_scan_lock = threading.Lock()
_scan_state = {"status": "idle", "message": ""}

# ── Fresh-fix job state (POST /fix/trigger, GET /fix/status) ──────────────────
# Mirrors _kb_import_state's shape. Updated from inside _do_fresh_scan()
# itself (not just the trigger handler) so BOTH the manual "Trigger Fixer"
# button and the automatic ScanPoller-driven run show live progress -- there's
# only one fresh-scan job at a time (_fresh_scan_lock already guarantees
# that), so a single global state object is enough either way.
_fix_state = {"status": "idle", "current": 0, "total": 0, "message": ""}


def main():
    retry_tracking_id = os.environ.get("RETRY_TRACKING_ID")
    server_mode       = os.environ.get("FIXER_SERVER_MODE", "0") == "1"

    if retry_tracking_id:
        _run_retry(retry_tracking_id)
    elif server_mode:
        _run_server()
    else:
        _run_fresh_scan()


# ── Mode C: server (always-on for local simulation) ───────────────────────────

def _run_server():
    """
    Long-running mode used by `docker compose up -d`.

    Starts two background workers:
      1. ScanPoller — polls GitHub every SCAN_POLL_INTERVAL seconds for new
         completed security-scan.yml runs and triggers _run_fresh_scan() when found.
      2. HTTP server on :8080 — accepts POST /retry from the Watcher and
         invokes _run_retry() for CI-failure re-fix attempts.
    """
    github_repo = get_target_repo()
    github_pat  = get_github_pat()
    report_dir  = os.environ.get("SCAN_REPORT_PATH", "/reports")
    poll_interval = int(os.environ.get("SCAN_POLL_INTERVAL", "60"))

    logger.info("Fixer server mode: starting scan poller worker and HTTP retry server.")

    poller = ScanPoller(
        repo_full_name=github_repo,
        github_pat=github_pat,
        report_dir=report_dir,
        on_new_scan_ready=_run_fresh_scan,
        poll_interval=poll_interval,
    )
    poller_target = lambda: _run_fixer_poller_loop(poller)
    poller_thread = threading.Thread(target=poller_target, daemon=True, name="scan-poller")
    poller_thread.start()

    server = _make_retry_server(port=8080, poller=poller)
    logger.info("Fixer HTTP server listening on :8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Fixer server shutting down.")


def _run_fixer_poller_loop(poller: ScanPoller) -> None:
    """Dynamically handles Night Mode active window vs Continuous polling loop."""
    timezone_name = os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata")
    last_window_date = None

    import time
    while True:
        try:
            if is_nightly_run_enabled():
                run_time = get_nightly_run_time()
                duration_seconds = get_nightly_scan_max_wait_seconds()

                is_active, remaining_seconds, seconds_until_next = get_active_window_status(
                    run_time=run_time,
                    duration_seconds=duration_seconds,
                    timezone_name=timezone_name,
                )

                if not is_active:
                    logger.info(
                        "Night Mode: outside active window. Sleeping until %s %s (%.1f hours).",
                        timezone_name,
                        run_time,
                        seconds_until_next / 3600.0,
                    )
                    became_active = sleep_until_active_window(
                        timezone_name=timezone_name,
                        check_cancel_fn=lambda: not is_nightly_run_enabled(),
                    )
                    if not became_active:
                        logger.info("Night Mode toggled OFF: waking up and running scan immediately.")
                        poller.poll_once()
                        continue
                    # Recompute window status upon waking
                    is_active, remaining_seconds, _ = get_active_window_status(
                        run_time=get_nightly_run_time(),
                        duration_seconds=get_nightly_scan_max_wait_seconds(),
                        timezone_name=timezone_name,
                    )

                # Active window is in progress
                current_date = datetime.now(ZoneInfo(timezone_name)).strftime("%Y-%m-%d")
                if last_window_date != current_date:
                    last_window_date = current_date
                    logger.info(
                        "Starting active window for %s (%s %s for %s). Requesting scan.",
                        current_date,
                        timezone_name,
                        run_time,
                        format_duration(duration_seconds),
                    )
                    set_scan_requested(True)
                    poller.reset_window_dispatch()

                logger.info(
                    "Night Mode active window in progress (%.1f minutes remaining). Polling...",
                    remaining_seconds / 60.0,
                )
                poller.poll_once()
                time.sleep(poller.poll_interval)
            else:
                last_window_date = None
                poller.poll_once()
                time.sleep(poller.poll_interval)
        except Exception as exc:
            logger.error("Fixer poller loop error: %s", exc, exc_info=True)
            time.sleep(10)


def _run_kb_import():
    """Runs KnowledgeAgent.hydrate() against the current scan reports on
    disk, reporting progress into _kb_import_state as it goes. Deliberately
    skips locality resolution and classification entirely -- KB import is
    about researching each finding's upgrade, not deciding whether/how to
    fix it, so it only needs the raw findings list.
    """
    global _kb_import_state
    try:
        report_dir = os.environ.get("SCAN_REPORT_PATH", "/reports")
        scanner = ScanReportClient(report_dir=report_dir)
        findings = scanner.get_vulnerability_report()

        if not findings:
            _kb_import_state = {"status": "done", "current": 0, "total": 0, "message": "No findings in scan reports."}
            return

        _kb_import_state = {"status": "running", "current": 0, "total": len(findings), "message": "Starting..."}

        def on_progress(current, total, message):
            _kb_import_state["current"] = current
            _kb_import_state["total"] = total
            _kb_import_state["message"] = message

        kb_store = make_knowledge_store()
        agent = KnowledgeAgent(github_pat=os.environ.get("GITHUB_PAT"))
        agent.hydrate(findings, kb_store, on_progress=on_progress)

        _kb_import_state["status"] = "done"
        _kb_import_state["message"] = f"Done -- {_kb_import_state['total']} unique finding(s) processed."
    except Exception as exc:
        logger.exception("KB import failed")
        _kb_import_state = {"status": "error", "current": 0, "total": 0, "message": str(exc)}


def _run_scan_fetch():
    """Background-thread target for POST /scan/live -- dispatches the real
    security-scan.yml GitHub Actions workflow and waits for it. Only writes
    reports to disk; deliberately does NOT also run _run_fresh_scan() --
    "run a scan" and "trigger the fixer" are separate demo steps on purpose
    (see agents/fixer/main.py's POST /fix/trigger for the second step).
    """
    global _scan_state
    try:
        github_repo = os.environ["GITHUB_REPO_TARGET"]
        github_pat  = os.environ["GITHUB_PAT"]
        report_dir  = os.environ.get("SCAN_REPORT_PATH", "/reports")
        _scan_state = {"status": "running", "message": f"Dispatching security-scan.yml on {github_repo}..."}
        fetcher = ScanFetcher(repo_full_name=github_repo, github_pat=github_pat, report_dir=report_dir)
        fetcher.trigger_and_download()
        _scan_state = {"status": "done", "message": "Scan complete -- reports downloaded."}
    except ScanFetchError as exc:
        logger.error("Live scan fetch failed: %s", exc)
        _scan_state = {"status": "error", "message": str(exc)}
    except Exception as exc:
        logger.exception("Live scan fetch failed")
        _scan_state = {"status": "error", "message": str(exc)}


def _findings_preview() -> list:
    """Read-only preview for GET /findings -- parses scan reports and runs
    the classifier, WITHOUT hydrating the KB, resolving locality, or fixing
    anything.
    """
    report_dir = os.environ.get("SCAN_REPORT_PATH", "/reports")
    scanner = ScanReportClient(report_dir=report_dir)
    findings = scanner.get_vulnerability_report()

    kb_store = make_knowledge_store()
    classifier = Classifier(kb_store=kb_store)

    out = []
    for finding in findings:
        result = classifier.classify(finding)
        out.append({
            "component_name": finding.component_name,
            "current_version": finding.current_version,
            "recommended_version": finding.recommended_version,
            "severity": finding.severity,
            "cve_ids": finding.cve_ids,
            "bucket": result.bucket,
            "rationale": result.rationale,
        })
    return out


def _make_retry_server(port: int, poller: Optional[ScanPoller] = None) -> HTTPServer:
    class RetryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/", "/status"):
                payload = {
                    "status": "ok",
                    "service": "fixer-server",
                    "scan_running": poller.is_scan_running() if poller else False,
                    "has_reports": poller.has_reports() if poller else False,
                }
                self._send_json(200, payload)
            elif self.path == "/import-kb/status":
                self._send_json(200, _kb_import_state)
            elif self.path == "/scan/live/status":
                self._send_json(200, _scan_state)
            elif self.path == "/fix/status":
                self._send_json(200, _fix_state)
            elif self.path == "/findings":
                try:
                    self._send_json(200, {"findings": _findings_preview()})
                except ScanReportError as exc:
                    self._send_json(200, {"findings": [], "error": str(exc)})
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path == "/retry":
                self._handle_retry()
            elif self.path == "/import-kb":
                self._handle_import_kb()
            elif self.path == "/scan/demo":
                self._handle_scan_demo()
            elif self.path == "/scan/live":
                self._handle_scan_live()
            elif self.path == "/fix/trigger":
                self._handle_fix_trigger()
            elif self.path == "/reset":
                self._handle_reset()
            elif self.path == "/scan":
                dispatched = False
                if poller:
                    dispatched = poller.dispatch_scan()
                self._send_json(202 if dispatched else 500, {
                    "status": "dispatched" if dispatched else "failed_or_no_poller",
                    "workflow": "security-scan.yml",
                })
            else:
                self.send_error(404)

        def _send_json(self, status: int, payload) -> None:
            body = _json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle_retry(self):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                data = _json.loads(body)
                tracking_id = data["tracking_id"]
            except (KeyError, ValueError):
                self.send_error(400, "Expected JSON with tracking_id")
                return

            self.send_response(202)
            self.end_headers()

            multiprocessing.Process(
                target=_run_retry,
                args=(tracking_id,),
                daemon=True,
                name=f"retry-{tracking_id[:8]}",
            ).start()
            logger.info("Retry accepted for tracking_id=%s (spawned process)", tracking_id[:8])

        def _handle_import_kb(self):
            if not _kb_import_lock.acquire(blocking=False):
                self._send_json(409, _kb_import_state)
                return

            def _run():
                try:
                    _run_kb_import()
                finally:
                    _kb_import_lock.release()

            self.send_response(202)
            self.end_headers()
            threading.Thread(target=_run, daemon=True, name="kb-import").start()
            logger.info("KB import accepted.")

        def _handle_scan_demo(self):
            # Synchronous on purpose -- writing two small JSON files takes
            # milliseconds, nowhere near ScanFetcher's up-to-20-minute real
            # scan, so there's no reason to make the caller poll for this.
            # No lock: harmless to overlap (worst case one write clobbers
            # another with equally-valid demo content).
            report_dir = os.environ.get("SCAN_REPORT_PATH", "/reports")
            try:
                cves = write_demo_reports(Path(report_dir))
                self._send_json(200, {"status": "done", "cve_ids": cves})
                logger.info("Demo scan reports written to %s (%d finding(s)).", report_dir, len(cves))
            except Exception as exc:
                logger.exception("Writing demo scan reports failed")
                self._send_json(500, {"status": "error", "message": str(exc)})

        def _handle_scan_live(self):
            if not _scan_lock.acquire(blocking=False):
                self._send_json(409, _scan_state)
                return

            def _run():
                try:
                    _run_scan_fetch()
                finally:
                    _scan_lock.release()

            self.send_response(202)
            self.end_headers()
            threading.Thread(target=_run, daemon=True, name="scan-live").start()
            logger.info("Live scan accepted.")

        def _handle_fix_trigger(self):
            # Acquires _fresh_scan_lock directly (same lock ScanPoller's
            # _run_fresh_scan() guards itself with) and calls _do_fresh_scan()
            # under it here, rather than going through _run_fresh_scan()'s own
            # acquire/release -- that avoids a release-then-reacquire race
            # where the poller could sneak in between this handler's check
            # and the background thread actually starting.
            if not _fresh_scan_lock.acquire(blocking=False):
                self._send_json(409, _fix_state)
                return

            def _run():
                try:
                    _do_fresh_scan()
                except Exception:
                    logger.exception("Fresh-fix run failed")
                    _fix_state["status"] = "error"
                    _fix_state["message"] = "Fresh-fix run failed -- see fixer-server logs."
                finally:
                    _fresh_scan_lock.release()

            self.send_response(202)
            self.end_headers()
            threading.Thread(target=_run, daemon=True, name="fix-trigger").start()
            logger.info("Fresh-fix run accepted.")

        def _handle_reset(self):
            """Clears local demo state -- tracking.json, kb.json, the scan
            poll checkpoint, and current scan reports -- so a demo can start
            clean. Deliberately does NOT touch GitHub: it doesn't close PRs
            or delete branches. That's a human decision, not something a
            reset button silently automates (see the "how does this handle
            an already-used-up target repo" discussion this was built for).
            Refuses (409) while a fixer run or live scan is in flight, reusing
            the same non-blocking acquire/release check-then-act pattern the
            other handlers above use, so a reset can't delete files out from
            under an active job.
            """
            if not _fresh_scan_lock.acquire(blocking=False):
                self._send_json(409, {"status": "error", "message": "A fixer run is in progress -- wait for it to finish before resetting."})
                return
            _fresh_scan_lock.release()
            if not _scan_lock.acquire(blocking=False):
                self._send_json(409, {"status": "error", "message": "A live scan is in progress -- wait for it to finish before resetting."})
                return
            _scan_lock.release()

            report_dir      = Path(os.environ.get("SCAN_REPORT_PATH", "/reports"))
            tracking_path   = Path(os.environ.get("TRACKING_STORE_PATH", "/data/tracking.json"))
            kb_path         = Path(os.environ.get("KB_STORE_PATH", "/data/kb.json"))
            checkpoint_path = tracking_path.parent / "scan_poll_checkpoint.json"

            to_clear = [
                tracking_path, kb_path, checkpoint_path,
                report_dir / "trivy-report.json",
                report_dir / "grype-report.json",
                report_dir / "dependency-check-report" / "dependency-check-report.json",
            ]
            cleared = []
            try:
                for path in to_clear:
                    if path.exists():
                        path.unlink()
                        cleared.append(str(path))
            except Exception as exc:
                logger.exception("Reset failed")
                self._send_json(500, {"status": "error", "message": str(exc)})
                return

            # Mutated in place rather than reassigned -- avoids needing a
            # `global` declaration for three names in this nested method.
            _kb_import_state.clear()
            _kb_import_state.update({"status": "idle", "current": 0, "total": 0, "message": ""})
            _scan_state.clear()
            _scan_state.update({"status": "idle", "message": ""})
            _fix_state.clear()
            _fix_state.update({"status": "idle", "current": 0, "total": 0, "message": ""})

            logger.info("Demo reset: cleared %d file(s): %s", len(cleared), cleared)
            self._send_json(200, {"status": "done", "cleared": cleared})

        def log_message(self, fmt, *args):  # suppress default access log noise
            logger.debug("HTTP %s", fmt % args)

    return HTTPServer(("0.0.0.0", port), RetryHandler)


# ── Multiprocessing worker for parallel remediation ──────────────────────────

def _fix_one_process_worker(task: dict):
    """
    Worker executed in an independent OS process via ProcessPoolExecutor.
    Bypasses Python's Global Interpreter Lock (GIL) for true process-level parallelism.
    """
    finding = task["finding"]
    record = task["record"]
    kb_entry = task["kb_entry"]
    source_path = task["source_path"]
    branch_name = task["branch_name"]
    github_repo = task["github_repo"]
    github_repo_url = task["github_repo_url"]
    github_pat = task["github_pat"]

    logger.info(
        "Processing %s on branch %s in isolated process (PID %d)",
        finding.component_name, branch_name, os.getpid()
    )

    tracking_store = make_tracking_store()
    pr_client = PRClient(repo_full_name=github_repo, github_pat=github_pat)

    with RepoOps() as repo:
        repo.clone_local(source_path, github_repo_url, github_pat)
        repo._repo.git.fetch('origin', branch_name)
        repo._repo.git.checkout(branch_name)

        fixer = CodeFixer(repo_path=repo._local_path)
        ecosystem = get_ecosystem(repo._local_path)

        try:
            if finding.is_transitive:
                summary = fixer.run_transitive_fix(
                    component_name=finding.component_name,
                    current_version=finding.current_version,
                    target_version=finding.recommended_version,
                    introduced_by=finding.introduced_by,
                    tracking_id=record.tracking_id,
                    tracking_store=tracking_store,
                    cve_ids=finding.cve_ids,
                )
            else:
                summary = fixer.run_fresh_fix(
                    component_name=finding.component_name,
                    current_version=finding.current_version,
                    target_version=finding.recommended_version,
                    tracking_id=record.tracking_id,
                    tracking_store=tracking_store,
                    cve_ids=finding.cve_ids,
                    kb_entry=kb_entry,
                )
        except (PomXMLError, PackageJsonError, PythonManifestError) as exc:
            logger.warning(
                "Could not process dependency %s in manifest; opening triage issue: %s",
                finding.component_name, exc,
            )
            pr_client.open_triage_issue(
                finding=finding, bucket=2, rationale=str(exc), kb_entry=kb_entry,
            )
            current = tracking_store.get(record.tracking_id)
            if current is not None:
                current.status = "TRIAGE_OPENED"
                tracking_store.update(current)
            return None
        except Exception as exc:
            logger.exception("Fix failed for %s", finding.component_name)
            current = tracking_store.get(record.tracking_id)
            if current is not None:
                current.status = TrackingStatus.ESCALATED.value
                current.failure_log_excerpt = str(exc)[:4000]
                tracking_store.update(current)
            try:
                pr_client.open_triage_issue(
                    finding=finding, bucket=2,
                    rationale=f"Automatic remediation failed: {str(exc)[:1000]}",
                    kb_entry=kb_entry,
                )
            except Exception:
                pass
            return None

        tests_passed, test_message = ecosystem.verify_tests(repo._local_path)
        if not tests_passed:
            message = f"Runtime verification failed for {finding.component_name}: {test_message[:3500]}"
            logger.error("%s", message)
            current = tracking_store.get(record.tracking_id)
            if current is not None:
                current.status = TrackingStatus.ESCALATED.value
                current.failure_log_excerpt = message[:4000]
                tracking_store.update(current)
            try:
                pr_client.open_triage_issue(
                    finding=finding, bucket=2, rationale=message, kb_entry=kb_entry,
                )
            except Exception:
                pass
            return None

        # Detect manifest file for diff review (ecosystem-aware)
        manifest_file = get_manifest_file(Path(repo._local_path))

        try:
            review = repo.review_dependency_diff(
                component_name=finding.component_name,
                target_version=finding.recommended_version,
                expected_files=summary.files_changed,
                manifest_file=manifest_file,
            )
        except Exception as exc:
            review = DiffReviewResult(False, f"Diff review could not run: {exc}")

        if not review.passed:
            message = f"Automated diff review failed: {review.message}"
            logger.error("%s", message)
            current = tracking_store.get(record.tracking_id)
            if current is not None:
                current.status = TrackingStatus.ESCALATED.value
                current.failure_log_excerpt = message[:4000]
                tracking_store.update(current)
            try:
                pr_client.open_triage_issue(
                    finding=finding, bucket=2, rationale=message, kb_entry=kb_entry,
                )
            except Exception:
                pass
            return None

        fix_kind = f"transitive, via {finding.introduced_by}" if finding.is_transitive else "direct"
        commit_msg = (
            f"fix: upgrade {finding.component_name} to {finding.recommended_version} ({fix_kind})"
            + (f" ({', '.join(finding.cve_ids)})" if finding.cve_ids else "")
        )

        lock_path = os.path.join(tempfile.gettempdir(), f"fixer_push_{branch_name.replace('/', '_')}.lock")
        with FileLock(lock_path, timeout_seconds=180.0):
            try:
                repo.commit_changes(commit_msg, files=summary.files_changed)
                # Fetch and rebase to merge other processes' pushes
                repo._repo.git.pull('--rebase', 'origin', branch_name)
                repo.push_branch(branch_name)
                return (finding, record, summary)
            except Exception as e:
                logger.warning("Rebase conflict for %s. Retrying fix holding process lock...", finding.component_name)
                try:
                    repo._repo.git.rebase('--abort')
                except Exception:
                    pass

                try:
                    repo._repo.git.fetch('origin', branch_name)
                    repo._repo.git.reset('--hard', f'origin/{branch_name}')

                    if finding.is_transitive:
                        summary = fixer.run_transitive_fix(
                            component_name=finding.component_name,
                            current_version=finding.current_version,
                            target_version=finding.recommended_version,
                            introduced_by=finding.introduced_by,
                            tracking_id=record.tracking_id,
                            tracking_store=tracking_store,
                            cve_ids=finding.cve_ids,
                        )
                    else:
                        summary = fixer.run_fresh_fix(
                            component_name=finding.component_name,
                            current_version=finding.current_version,
                            target_version=finding.recommended_version,
                            tracking_id=record.tracking_id,
                            tracking_store=tracking_store,
                            cve_ids=finding.cve_ids,
                            kb_entry=kb_entry,
                        )

                    repo.commit_changes(commit_msg, files=summary.files_changed)
                    repo.push_branch(branch_name)
                    return (finding, record, summary)
                except Exception as inner_e:
                    logger.error("Failed to re-apply fix during conflict resolution: %s", inner_e)
                    message = f"Merge conflict could not be automatically resolved: {inner_e}"
                    current = tracking_store.get(record.tracking_id)
                    if current is not None:
                        current.status = TrackingStatus.ESCALATED.value
                        current.failure_log_excerpt = message[:4000]
                        tracking_store.update(current)
                    return None


# ── Mode A: fresh scan ────────────────────────────────────────────────────────

def _run_fresh_scan():
    if not _fresh_scan_lock.acquire(blocking=False):
        logger.info("Fresh scan already in progress — skipping this trigger.")
        return
    try:
        _do_fresh_scan()
    except Exception:
        # Without this, an exception anywhere in _do_fresh_scan() past its
        # first couple of explicit error branches leaves _fix_state stuck at
        # "running" forever -- the dashboard's progress bar would spin
        # indefinitely even though the run actually died. Re-raised so the
        # CLI one-shot caller (main()'s non-server-mode branch) still fails
        # loudly, same as before this except existed.
        _fix_state["status"] = "error"
        _fix_state["message"] = "Fresh-fix run failed -- see fixer-server logs."
        raise
    finally:
        _fresh_scan_lock.release()


def _do_fresh_scan():
    global _fix_state
    logger.info("Mode: FRESH SCAN (scheduler-triggered)")
    _fix_state = {"status": "running", "current": 0, "total": 0, "message": "Scanning and classifying findings..."}

    target_repos    = get_target_repos()
    github_repo     = target_repos[0] if target_repos else get_target_repo()
    github_repo_url = f"https://github.com/{github_repo}.git"
    github_pat      = get_github_pat(github_repo)

    server_mode = os.environ.get("FIXER_SERVER_MODE", "0") == "1"

    if AUTO_FETCH_SCAN and not server_mode:
        report_dir = os.environ.get("SCAN_REPORT_PATH", "/reports")
        logger.info("AUTO_FETCH_SCAN=1 — triggering security-scan workflow on %s", github_repo)
        fetcher = ScanFetcher(
            repo_full_name=github_repo,
            github_pat=github_pat,
            report_dir=report_dir,
        )
        try:
            fetcher.trigger_and_download()
        except ScanFetchError as exc:
            logger.error("Scan fetch failed: %s", exc)
            _fix_state = {"status": "error", "current": 0, "total": 0, "message": str(exc)}
            if server_mode:
                return
            sys.exit(1)

    tracking_store = make_tracking_store()

    scanner = ScanReportClient()
    try:
        findings = scanner.get_vulnerability_report()
    except ScanReportError as exc:
        logger.error("Scan report load failed: %s", exc)
        _fix_state = {"status": "error", "current": 0, "total": 0, "message": str(exc)}
        if server_mode:
            return
        sys.exit(1)

    if not findings:
        logger.info("No vulnerabilities found in scan reports. Nothing to do.")
        _fix_state = {"status": "done", "current": 0, "total": 0, "message": "No vulnerabilities found in scan reports."}
        return

    logger.info("Found %d vulnerability finding(s).", len(findings))

    pr_client   = PRClient(repo_full_name=github_repo, github_pat=github_pat)
    base_branch = Github(github_pat).get_repo(github_repo).default_branch

    # Cloned before classification (not after, as in the original ordering) --
    # locality resolution needs a real checkout to run `mvn dependency:tree`
    # against before we can classify direct vs. transitive findings.
    source_repo = RepoOps()
    source_path = source_repo.clone(github_repo_url, github_pat)  # str -- RepoOps.clone_local() below needs it as str
    # ecosystems/ (get_ecosystem, resolve_locality) is typed against Path and
    # does real Path-only operations (repo_path / "pom.xml") -- RepoOps.clone()
    # returns a plain str, so wrap it once here rather than changing
    # RepoOps.clone()'s return type and every other str-typed caller of it.
    source_path_obj = Path(source_path)
    logger.info(
        "Source clone ready at %s — up to %d parallel fixes will copy from here.",
        source_path, MAX_PARALLEL_FIXES,
    )

    # Ecosystem-pluggable (see ecosystems/) -- Maven, npm, and Python are supported.
    # A finding whose locality can't be determined defaults to direct.
    # A locality-tool failure is routed to triage; a clean lookup that does not
    # contain the finding is treated as a stale report and keeps the legacy
    # direct-dependency fallback.
    ecosystem = get_ecosystem(source_path_obj)
    locality_failures = {}
    multi_repo_chain = len(target_repos) > 1
    for finding in findings:
        try:
            locality = ecosystem.resolve_locality(source_path_obj, finding.component_name)
        except EcosystemError as exc:
            if multi_repo_chain:
                # The scanner already resolved the dependency graph across the
                # configured repositories. A local dependency-tree failure must
                # not suppress the chain coordinator or turn the finding into
                # manual triage before each repository can be inspected.
                finding.is_transitive = True
                finding.introduced_by = None
                finding.transitive_depth = len(target_repos)
                logger.warning(
                    "Locality resolution failed for %s in a multi-repository chain; "
                    "continuing with scanner-confirmed chain metadata: %s",
                    finding.component_name,
                    exc,
                )
                continue
            rationale = (
                f"Could not resolve dependency locality for {finding.component_name}: "
                f"{str(exc)[:1000]}. Manual triage required."
            )
            logger.error(
                "Locality resolution failed for %s -- opening triage issue: %s",
                finding.component_name, exc,
            )
            locality_failures[finding.component_name] = rationale
            continue
        if not locality.found:
            logger.warning(
                "%s not found in the dependency tree (stale scan report or "
                "version mismatch?) -- treating as direct.", finding.component_name,
            )
            continue
        finding.is_transitive = locality.is_transitive
        finding.introduced_by = locality.introduced_by
        finding.transitive_depth = locality.depth
        if locality.is_transitive:
            logger.info(
                "%s is transitive (depth=%d, introduced by %s).",
                finding.component_name, locality.depth, locality.introduced_by,
            )
    # ─────────────────────────────────────────────────────────────────────────

    # ── Phase 2: KB hydration + classification ────────────────────────────────
    kb_store = make_knowledge_store()

    knowledge_agent = KnowledgeAgent(github_pat=github_pat)
    knowledge_agent.hydrate(findings, kb_store)

    classifier = Classifier(kb_store=kb_store)

    # Classify all findings; bucket 1/4 get triage issues and are skipped from fixing
    classification = {}  # finding.component_name → ClassifierResult
    for finding in findings:
        if finding.component_name in locality_failures:
            result = ClassifierResult(
                bucket=4,
                rationale=locality_failures[finding.component_name],
            )
        else:
            result = classifier.classify(finding)
        classification[finding.component_name] = result
        logger.info(
            "Classifier: %s → bucket %d (%s)",
            finding.component_name, result.bucket, result.rationale,
        )
        if result.bucket in (1, 4):
            logger.info(
                "Bucket %d — opening triage issue for %s.",
                result.bucket, finding.component_name,
            )
            pr_client.open_triage_issue(
                finding=finding,
                bucket=result.bucket,
                rationale=result.rationale,
                kb_entry=result.kb_entry,
            )
    # ─────────────────────────────────────────────────────────────────────────

    branch_name = "fix/vulnerability-remediation"
    
    if len(target_repos) > 1:
        logger.info(
            "Multi-repository dependency chain detected (%d repos: %s). "
            "Executing MultiRepoChainCoordinator...",
            len(target_repos), target_repos,
        )
        from multi_repo_chain import MultiRepoChainCoordinator
        coordinator = MultiRepoChainCoordinator(
            repo_chain=target_repos,
            github_pat=github_pat,
            tracking_store=tracking_store,
            base_branch=base_branch,
            branch_name=branch_name,
        )
        source_repo.cleanup()
        for finding in findings:
            result = classification.get(finding.component_name)
            if result and result.bucket in (1, 4):
                logger.info("Finding %s is in bucket %d -- skipping multi-repo fix.", finding.component_name, result.bucket)
                continue
            coordinator.remediate_finding_across_chain(
                finding=finding,
                kb_entry=result.kb_entry if result else None,
            )
        logger.info("Multi-repository dependency chain remediation complete.")
        return

    tasks = []
    for finding in findings:
        result = classification[finding.component_name]
        if result.bucket in (1, 4):
            continue  # triage issue already created above

        record = make_fresh_record(
            vulnerability_id=finding.cve_ids[0] if finding.cve_ids else finding.component_name,
            repo=github_repo,
            component_name=finding.component_name,
            old_version=finding.current_version,
            new_version=finding.recommended_version,
            is_transitive=finding.is_transitive,
            introduced_by=finding.introduced_by,
            transitive_depth=finding.transitive_depth,
        )
        record.branch_name  = branch_name
        record.kb_bucket    = result.bucket
        record.kb_entry_id  = result.kb_entry.entry_id if result.kb_entry else None
        record.classifier_rationale = result.rationale
        tracking_store.create(record)
        tasks.append((finding, record, result.kb_entry))

    _fix_state = {
        "status": "running", "current": 0, "total": len(tasks),
        "message": "Fixing findings..." if tasks else "No fixable findings -- all routed to triage issues.",
    }

    if not tasks:
        _fix_state["status"] = "done"
        _fix_state["message"] = "No fixable findings -- all routed to triage issues."
        source_repo.cleanup()
        return

    # Create the shared branch once before threads start
    with RepoOps() as init_repo:
        init_repo.clone(github_repo_url, github_pat)
        branch_created = init_repo.create_branch(
            branch_name,
            skip_if_exists=True,
            base_branch=base_branch,
        )
        if not branch_created:
            existing_open_pr = pr_client._find_open_pr(branch_name, base_branch)
            if existing_open_pr:
                logger.info(
                    "Branch already exists with active open PR #%d (%s) -- attaching to tracking records.",
                    existing_open_pr.number, existing_open_pr.html_url,
                )
                for finding, record, kb_entry in tasks:
                    current = tracking_store.get(record.tracking_id) or record
                    current.pr_number = existing_open_pr.number
                    current.status = TrackingStatus.PR_OPENED.value
                    tracking_store.update(current)
                source_repo.cleanup()
                return
            else:
                logger.info(
                    "Remote branch '%s' exists but has no open PR (previous PR was closed/merged). "
                    "Resetting remote branch from %s so a fresh remediation PR can be opened.",
                    branch_name, base_branch,
                )
                try:
                    init_repo._repo.git.push('origin', '--delete', branch_name)
                    logger.info("Deleted stale remote branch '%s' on origin", branch_name)
                except Exception as del_err:
                    logger.warning("Could not delete stale remote branch: %s", del_err)

                # Recreate branch from fresh base_branch
                init_repo.checkout_base_branch(base_branch)
                try:
                    init_repo._repo.git.pull('origin', base_branch)
                except Exception:
                    pass
                if branch_name in [h.name for h in init_repo._repo.heads]:
                    try:
                        init_repo._repo.git.branch('-D', branch_name)
                    except Exception:
                        pass
                init_repo.create_branch(
                    branch_name,
                    skip_if_exists=False,
                    base_branch=base_branch,
                )

        # push the initial branch so workers can pull from it
        init_repo.push_branch(branch_name)

    worker_tasks = [
        {
            "finding": finding,
            "record": record,
            "kb_entry": kb_entry,
            "source_path": source_path,
            "branch_name": branch_name,
            "github_repo": github_repo,
            "github_repo_url": github_repo_url,
            "github_pat": github_pat,
            "base_branch": base_branch,
        }
        for finding, record, kb_entry in tasks
    ]

    successful_fixes = []

    try:
        logger.info(
            "Executing %d remediation task(s) using ProcessPoolExecutor (max_workers=%d, multiprocessing)",
            len(worker_tasks), MAX_PARALLEL_FIXES,
        )
        with ProcessPoolExecutor(max_workers=MAX_PARALLEL_FIXES) as executor:
            futures = {executor.submit(_fix_one_process_worker, t): t for t in worker_tasks}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        successful_fixes.append(res)
                except Exception as exc:
                    logger.error("Process worker error: %s", exc, exc_info=True)
    finally:
        source_repo.cleanup()
        logger.info("Source clone cleaned up.")

    if successful_fixes:
        pr_result = pr_client.open_combined_remediation_pr(
            branch_name=branch_name,
            base_branch=base_branch,
            successful_fixes=successful_fixes,
        )
        for finding, record, summary in successful_fixes:
            current = tracking_store.get(record.tracking_id) or record
            current.pr_number = pr_result.pr_number
            current.status = TrackingStatus.PR_OPENED.value if pr_result.was_existing else TrackingStatus.CI_PENDING.value
            tracking_store.update(current)
            
        if pr_result.was_existing:
            logger.info("Combined PR already existed: %s", pr_result.pr_url)
        else:
            logger.info("Opened Combined PR #%d: %s", pr_result.pr_number, pr_result.pr_url)

    _fix_state["status"] = "done"
    _fix_state["message"] = f"Done -- {len(successful_fixes)}/{len(tasks)} finding(s) fixed."


# ── Mode B: Watcher retry ─────────────────────────────────────────────────────

def _run_retry(tracking_id: str):
    logger.info("Mode: WATCHER RETRY (tracking_id=%s)", tracking_id[:8])

    github_repo     = get_target_repo()
    github_repo_url = f"https://github.com/{github_repo}.git"
    github_pat      = get_github_pat()

    tracking_store = make_tracking_store()
    record = tracking_store.get(tracking_id)

    if record is None:
        logger.error("Tracking record %s not found. Exiting.", tracking_id[:8])
        sys.exit(1)

    if not record.branch_name:
        logger.error(
            "Tracking record %s has no branch_name — cannot check out the PR branch.",
            tracking_id[:8],
        )
        sys.exit(1)

    try:
        with RepoOps() as repo:
            repo.clone(github_repo_url, github_pat)
            repo._repo.git.checkout(record.branch_name)

            fixer = CodeFixer(repo_path=repo._local_path)
            summary = fixer.run_retry_fix(
                tracking_id=tracking_id,
                tracking_store=tracking_store,
            )

            # A retry must not push a source edit that the CI build will reject.
            # The engine is instructed to compile, but this gate is authoritative
            # and also covers engines that cannot execute Maven locally.
            retry_ecosystem = get_ecosystem(repo._local_path)
            compiled, compile_message = retry_ecosystem.verify_build(repo._local_path)
            if not compiled:
                message = (
                    f"Retry verification failed for {record.component_name}: "
                    f"{compile_message[:3500]}"
                )
                logger.error("%s", message)
                current = tracking_store.get(tracking_id)
                if current is not None:
                    current.status = TrackingStatus.ESCALATED.value
                    current.failure_log_excerpt = message[:4000]
                    tracking_store.update(current)
                return

            # Detect manifest file for diff review (ecosystem-aware)
            retry_manifest_file = get_manifest_file(Path(repo._local_path))

            try:
                review = repo.review_dependency_diff(
                    component_name=record.component_name,
                    target_version=record.new_version,
                    expected_files=summary.files_changed,
                    allow_manifest_already_applied=True,
                    manifest_file=retry_manifest_file,
                )
            except Exception as exc:
                review = DiffReviewResult(False, f"Diff review could not run: {exc}")
            if not review.passed:
                message = f"Automated diff review failed: {review.message}"
                logger.error("%s", message)
                current = tracking_store.get(tracking_id)
                if current is not None:
                    current.status = TrackingStatus.ESCALATED.value
                    current.failure_log_excerpt = message[:4000]
                    tracking_store.update(current)
                triage_finding = SimpleNamespace(
                    component_name=record.component_name,
                    current_version=record.old_version,
                    recommended_version=record.new_version,
                    severity="unknown",
                    cve_ids=[record.vulnerability_id] if record.vulnerability_id else [],
                )
                try:
                    PRClient(repo_full_name=github_repo, github_pat=github_pat).open_triage_issue(
                        finding=triage_finding,
                        bucket=2,
                        rationale=message,
                    )
                except Exception:
                    logger.exception(
                        "Could not open triage issue after retry diff review failure for %s.",
                        record.component_name,
                    )
                return

            commit_msg = (
                f"fix(retry): attempt {record.attempt_number} — "
                f"{summary.rationale[:120] if summary.rationale else 'CI failure fix'}"
            )
            repo.commit_changes(commit_msg, files=summary.files_changed)
            repo.push_branch(record.branch_name)

        current = tracking_store.get(tracking_id)
        if current is not None:
            current.status = TrackingStatus.CI_PENDING.value
            tracking_store.update(current)

        # Synchronize all records associated with this PR to CI_PENDING
        all_records = (
            tracking_store.get_all_for_pr(record.pr_number)
            if hasattr(tracking_store, "get_all_for_pr")
            else []
        )
        for r in all_records:
            if r.status in (TrackingStatus.CI_FAILED.value, TrackingStatus.ENGINE_ERROR.value):
                r.status = TrackingStatus.CI_PENDING.value
                tracking_store.update(r)

        logger.info(
            "Retry fix pushed for PR #%s on branch '%s'.",
            record.pr_number, record.branch_name,
        )
    except InvalidRetryError as exc:
        logger.error("Retry validation failed for %s: %s", tracking_id[:8], exc)
        current = tracking_store.get(tracking_id)
        if current is not None:
            current.status = TrackingStatus.ESCALATED.value
            current.failure_log_excerpt = f"Retry validation failed: {exc}"[:4000]
            tracking_store.update(current)
    except EngineExecutionError as exc:
        logger.error("Fixer engine failed to run for retry %s: %s", tracking_id[:8], exc)
        current = tracking_store.get(tracking_id)
        if current is not None:
            current.status = TrackingStatus.ENGINE_ERROR.value
            current.failure_log_excerpt = f"Engine execution error: {exc}"[:4000]
            tracking_store.update(current)
        try:
            pr_client = PRClient(repo_full_name=github_repo, github_pat=github_pat)
            pr_client.add_comment(
                record.pr_number,
                "## OSS Remediation Agent — Engine Failure\n\n"
                f"Fix attempt {record.attempt_number} could not run "
                "(the tooling that generates fixes failed, not the fix itself -- "
                "e.g. a crash, timeout, or missing dependency). This attempt did "
                "not consume a retry, but automatic retries are paused pending "
                f"investigation.\n\n**Error:**\n```\n{str(exc)[:1500]}\n```\n\n"
                "Please investigate the Fixer's engine configuration before "
                "re-triggering a fix for this PR.",
            )
        except Exception as comment_exc:
            logger.error(
                "Could not post engine-failure comment on PR #%s: %s",
                record.pr_number, comment_exc,
            )
    except Exception as exc:
        logger.exception("Unexpected error during retry for %s: %s", tracking_id[:8], exc)
        current = tracking_store.get(tracking_id)
        if current is not None:
            current.status = TrackingStatus.ESCALATED.value
            current.failure_log_excerpt = f"Unexpected retry error: {exc}"[:4000]
            tracking_store.update(current)
        try:
            pr_client = PRClient(repo_full_name=github_repo, github_pat=github_pat)
            pr_client.add_comment(
                record.pr_number,
                f"## OSS Remediation Agent — Retry Escalation\n\n"
                f"Fix attempt {record.attempt_number} encountered an error: `{exc}`. "
                "Automatic retry has been escalated for manual review.",
            )
        except Exception as comment_exc:
            logger.error("Could not post escalation comment on PR #%s: %s", record.pr_number, comment_exc)


if __name__ == "__main__":
    main()
