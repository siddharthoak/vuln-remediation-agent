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
from common.nightly_scheduler import sleep_until_next_run
from common.config import get_target_repo, get_target_repos, get_github_pat, is_nightly_run_enabled
from knowledge.main import KnowledgeAgent
from classifier.classifier import Classifier, ClassifierResult

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
    """Dynamically handles Night Mode vs Continuous polling loop."""
    run_time = os.environ.get("NIGHTLY_RUN_TIME", "00:00")
    timezone_name = os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata")
    max_wait = int(os.environ.get("NIGHTLY_SCAN_MAX_WAIT_SECONDS", "7200"))

    import time
    while True:
        try:
            if is_nightly_run_enabled():
                logger.info(
                    "Night Mode active: sleeping until %s (%s).",
                    run_time,
                    timezone_name,
                )
                completed = sleep_until_next_run(
                    run_time,
                    timezone_name,
                    check_cancel_fn=lambda: not is_nightly_run_enabled(),
                )
                if completed:
                    poller.run_nightly(max_wait_seconds=max_wait)
                else:
                    logger.info("Night Mode toggled OFF: waking up and running scan immediately.")
                    poller.poll_once()
            else:
                poller.poll_once()
                time.sleep(poller.poll_interval)
        except Exception as exc:
            logger.error("Fixer poller loop error: %s", exc, exc_info=True)
            time.sleep(10)


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
                body = _json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404)

        def do_POST(self):
            if self.path == "/scan":
                dispatched = False
                if poller:
                    dispatched = poller.dispatch_scan()
                body = _json.dumps({
                    "status": "dispatched" if dispatched else "failed_or_no_poller",
                    "workflow": "security-scan.yml",
                }).encode("utf-8")
                self.send_response(202 if dispatched else 500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path != "/retry":
                self.send_error(404)
                return
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
    finally:
        _fresh_scan_lock.release()


def _do_fresh_scan():
    logger.info("Mode: FRESH SCAN (scheduler-triggered)")

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
            if server_mode:
                return
            sys.exit(1)

    tracking_store = make_tracking_store()

    scanner = ScanReportClient()
    try:
        findings = scanner.get_vulnerability_report()
    except ScanReportError as exc:
        logger.error("Scan report load failed: %s", exc)
        if server_mode:
            return
        sys.exit(1)

    if not findings:
        logger.info("No vulnerabilities found in scan reports. Nothing to do.")
        return

    logger.info("Found %d vulnerability finding(s).", len(findings))

    pr_client   = PRClient(repo_full_name=github_repo, github_pat=github_pat)
    base_branch = Github(github_pat).get_repo(github_repo).default_branch

    # Cloned before classification (not after, as in the original ordering) --
    # locality resolution needs a real checkout to run `mvn dependency:tree`
    # against before we can classify direct vs. transitive findings.
    source_repo = RepoOps()
    source_path = source_repo.clone(github_repo_url, github_pat)
    logger.info(
        "Source clone ready at %s — up to %d parallel fixes will copy from here.",
        source_path, MAX_PARALLEL_FIXES,
    )

    # ── Locality resolution (direct vs. transitive) ───────────────────────────
    # Ecosystem-pluggable (see ecosystems/) -- Maven, npm, and Python are supported.
    # A finding whose locality can't be determined defaults to direct.
    # A locality-tool failure is routed to triage; a clean lookup that does not
    # contain the finding is treated as a stale report and keeps the legacy
    # direct-dependency fallback.
    ecosystem = get_ecosystem(source_path)
    locality_failures = {}
    for finding in findings:
        try:
            locality = ecosystem.resolve_locality(source_path, finding.component_name)
        except EcosystemError as exc:
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

    if not tasks:
        source_repo.cleanup()
        return

    # Create the shared branch once before threads start
    with RepoOps() as init_repo:
        init_repo.clone(github_repo_url, github_pat)
        branch_created = init_repo.create_branch(branch_name, skip_if_exists=True)
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
                init_repo._repo.git.checkout(base_branch)
                try:
                    init_repo._repo.git.pull('origin', base_branch)
                except Exception:
                    pass
                if branch_name in [h.name for h in init_repo._repo.heads]:
                    try:
                        init_repo._repo.git.branch('-D', branch_name)
                    except Exception:
                        pass
                init_repo.create_branch(branch_name, skip_if_exists=False)

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
