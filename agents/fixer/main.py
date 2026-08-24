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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json as _json

from github import Github
from scan_report_client import ScanReportClient, ScanReportError
from scan_fetcher import ScanFetcher, ScanFetchError
from scan_poller import ScanPoller
from repo_ops import RepoOps
from code_fixer import CodeFixer, InvalidRetryError
from pr_client import PRClient
from engines.base import EngineExecutionError
from ecosystems.factory import get_ecosystem
from ecosystems.base import EcosystemError

from common.tracking_store import (
    make_tracking_store,
    make_fresh_record,
    TrackingStatus,
)
from common.knowledge_store import make_knowledge_store
from knowledge.main import KnowledgeAgent
from classifier.classifier import Classifier
from demo_scan_reports import write_demo_reports

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("fixer.main")

MAX_PARALLEL_FIXES = int(os.environ.get("MAX_PARALLEL_FIXES", "5"))
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
    github_repo = os.environ["GITHUB_REPO_TARGET"]
    github_pat  = os.environ["GITHUB_PAT"]
    report_dir  = os.environ.get("SCAN_REPORT_PATH", "/reports")
    poll_interval = int(os.environ.get("SCAN_POLL_INTERVAL", "60"))

    logger.info("Fixer server mode: starting scan poller and HTTP retry server.")

    poller = ScanPoller(
        repo_full_name=github_repo,
        github_pat=github_pat,
        report_dir=report_dir,
        on_new_scan_ready=_run_fresh_scan,
        poll_interval=poll_interval,
    )
    poller_thread = threading.Thread(target=poller.poll_forever, daemon=True, name="scan-poller")
    poller_thread.start()

    server = _make_retry_server(port=8080)
    logger.info("Fixer HTTP server listening on :8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Fixer server shutting down.")


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
    anything. Deliberately skips locality resolution (that needs a real repo
    clone) -- a finding's is_transitive here is always its default (False),
    so a bucket-3/4 call on a transitive dependency may look slightly more
    optimistic here than what _do_fresh_scan() would actually decide once it
    has a clone to inspect. That tradeoff (fast, read-only preview vs. a
    perfectly accurate one) is intentional: this endpoint exists so an
    audience can see "what's out there" before/without spending a fix cycle
    on it, not to duplicate _do_fresh_scan()'s full decision pipeline.
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


def _make_retry_server(port: int) -> HTTPServer:
    class RetryHandler(BaseHTTPRequestHandler):
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
            else:
                self.send_error(404)

        def do_GET(self):
            if self.path == "/import-kb/status":
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

            threading.Thread(
                target=_run_retry,
                args=(tracking_id,),
                daemon=True,
                name=f"retry-{tracking_id[:8]}",
            ).start()
            logger.info("Retry accepted for tracking_id=%s", tracking_id[:8])

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

        def log_message(self, fmt, *args):  # suppress default access log noise
            logger.debug("HTTP %s", fmt % args)

    return HTTPServer(("0.0.0.0", port), RetryHandler)


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

    github_repo     = os.environ["GITHUB_REPO_TARGET"]
    github_repo_url = f"https://github.com/{github_repo}.git"
    github_pat      = os.environ["GITHUB_PAT"]

    server_mode = os.environ.get("FIXER_SERVER_MODE", "0") == "1"

    if AUTO_FETCH_SCAN:
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

    # ── Locality resolution (direct vs. transitive) ───────────────────────────
    # Ecosystem-pluggable (see ecosystems/) -- Maven-only, single-module POC
    # scope today. A finding whose locality can't be determined defaults to
    # is_transitive=False, i.e. falls back to today's pre-existing behavior
    # (attempt a direct manifest bump) rather than blocking the whole batch
    # on one lookup failure.
    ecosystem = get_ecosystem(source_path_obj)
    for finding in findings:
        try:
            locality = ecosystem.resolve_locality(source_path_obj, finding.component_name)
        except EcosystemError as exc:
            logger.warning(
                "Locality resolution failed for %s: %s -- treating as direct.",
                finding.component_name, exc,
            )
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

    tasks = []
    for finding in findings:
        result = classification[finding.component_name]
        if result.bucket in (1, 4):
            continue  # triage issue already created above

        branch_name = RepoOps.make_branch_name(finding.component_name, finding.current_version)
        record = make_fresh_record(
            vulnerability_id=finding.cve_ids[0] if finding.cve_ids else finding.component_name,
            repo=github_repo,
            component_name=finding.component_name,
            old_version=finding.current_version,
            new_version=finding.recommended_version,
        )
        record.branch_name  = branch_name
        record.kb_bucket    = result.bucket
        record.kb_entry_id  = result.kb_entry.entry_id if result.kb_entry else None
        record.classifier_rationale = result.rationale
        tracking_store.create(record)
        tasks.append((finding, branch_name, record, result.kb_entry))

    _fix_state = {
        "status": "running", "current": 0, "total": len(tasks),
        "message": "Fixing findings..." if tasks else "No fixable findings -- all routed to triage issues.",
    }

    def _fix_one(task):
        finding, branch_name, record, kb_entry = task
        logger.info("Processing %s → branch %s", finding.component_name, branch_name)

        with RepoOps() as repo:
            repo.clone_local(source_path, github_repo_url, github_pat)
            branch_created = repo.create_branch(branch_name, skip_if_exists=True)
            if not branch_created:
                # The branch existing means a PR was very likely opened for
                # it on some earlier run -- attach it (whatever its current
                # state) rather than silently abandoning this tracking
                # record at CREATED forever. find_any_pr checks state="all",
                # not just "open", so a PR that's since been closed manually
                # still gets linked -- see PRClient.find_any_pr's docstring.
                existing_pr = pr_client.find_any_pr(branch_name, base_branch)
                if existing_pr:
                    logger.info(
                        "Branch already exists for %s -- found PR #%d (%s), attaching to tracking record.",
                        finding.component_name, existing_pr.pr_number, existing_pr.pr_url,
                    )
                    current = tracking_store.get(record.tracking_id)
                    current.pr_number = existing_pr.pr_number
                    current.status = TrackingStatus.PR_OPENED.value
                    tracking_store.update(current)
                else:
                    logger.warning(
                        "Branch already exists for %s but no PR found for it in any "
                        "state -- leaving tracking record as CREATED for manual investigation.",
                        finding.component_name,
                    )
                return None

            fixer = CodeFixer(repo_path=repo._local_path)
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
            except Exception as exc:
                logger.error("Fix failed for %s: %s", finding.component_name, exc)
                return None

            fix_kind = f"transitive, via {finding.introduced_by}" if finding.is_transitive else "direct"
            commit_msg = (
                f"fix: upgrade {finding.component_name} to {finding.recommended_version} ({fix_kind})"
                + (f" ({', '.join(finding.cve_ids)})" if finding.cve_ids else "")
            )
            repo.commit_changes(commit_msg)
            repo.push_branch(branch_name)

        return (finding, branch_name, record, summary)

    try:
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_FIXES) as executor:
            futures = {executor.submit(_fix_one, t): t for t in tasks}

            for future in as_completed(futures):
                result = future.result()
                _fix_state["current"] += 1
                _fix_state["message"] = f"Processed {_fix_state['current']}/{_fix_state['total']} finding(s)..."
                if result is None:
                    continue

                finding, branch_name, record, summary = result

                pr_result = pr_client.open_remediation_pr(
                    branch_name=branch_name,
                    base_branch=base_branch,
                    change_summary=summary,
                )

                record = tracking_store.get(record.tracking_id)
                record.pr_number = pr_result.pr_number
                record.status = TrackingStatus.PR_OPENED.value
                tracking_store.update(record)

                if pr_result.was_existing:
                    logger.info("PR already existed: %s", pr_result.pr_url)
                else:
                    logger.info("Opened PR #%d: %s", pr_result.pr_number, pr_result.pr_url)
                    record.status = TrackingStatus.CI_PENDING.value
                    tracking_store.update(record)
    finally:
        source_repo.cleanup()
        logger.info("Source clone cleaned up.")

    _fix_state["status"] = "done"
    _fix_state["message"] = f"Done -- {_fix_state['current']}/{_fix_state['total']} finding(s) processed."


# ── Mode B: Watcher retry ─────────────────────────────────────────────────────

def _run_retry(tracking_id: str):
    logger.info("Mode: WATCHER RETRY (tracking_id=%s)", tracking_id[:8])

    github_repo     = os.environ["GITHUB_REPO_TARGET"]
    github_repo_url = f"https://github.com/{github_repo}.git"
    github_pat      = os.environ["GITHUB_PAT"]

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

    with RepoOps() as repo:
        repo.clone(github_repo_url, github_pat)
        repo._repo.git.checkout(record.branch_name)

        fixer = CodeFixer(repo_path=repo._local_path)
        try:
            summary = fixer.run_retry_fix(
                tracking_id=tracking_id,
                tracking_store=tracking_store,
            )
        except InvalidRetryError as exc:
            logger.error("Retry validation failed: %s", exc)
            sys.exit(1)
        except EngineExecutionError as exc:
            # The FixEngine itself failed to run (CLI crash/timeout/missing
            # binary) -- it never produced a fix to evaluate, so this is not
            # the same as a fix attempt that ran and turned out wrong. Don't
            # let the record silently rot in RETRY_REQUESTED forever: mark it
            # ENGINE_ERROR (excluded from count_attempts_for_pr, so it won't
            # consume retry budget) and escalate to a human via the PR
            # instead of leaving the Watcher polling a branch nothing was
            # ever pushed to.
            logger.error("Fixer engine failed to run for retry %s: %s", tracking_id[:8], exc)
            record.status = TrackingStatus.ENGINE_ERROR.value
            tracking_store.update(record)
            pr_client = PRClient(repo_full_name=github_repo, github_pat=github_pat)
            try:
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
            sys.exit(1)

        commit_msg = (
            f"fix(retry): attempt {record.attempt_number} — "
            f"{summary.rationale[:120] if summary.rationale else 'CI failure fix'}"
        )
        repo.commit_changes(commit_msg)
        repo.push_branch(record.branch_name)

    record = tracking_store.get(tracking_id)
    record.status = TrackingStatus.CI_PENDING.value
    tracking_store.update(record)

    logger.info(
        "Retry fix pushed for PR #%s on branch '%s'.",
        record.pr_number, record.branch_name,
    )


if __name__ == "__main__":
    main()
