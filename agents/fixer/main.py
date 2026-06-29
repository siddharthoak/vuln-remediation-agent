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
import json as _json

from github import Github
from scan_report_client import ScanReportClient, ScanReportError
from scan_fetcher import ScanFetcher, ScanFetchError
from scan_poller import ScanPoller
from repo_ops import RepoOps
from code_fixer import CodeFixer, InvalidRetryError
from pr_client import PRClient

from common.tracking_store import (
    make_tracking_store,
    make_fresh_record,
    TrackingStatus,
)
from common.knowledge_store import make_knowledge_store
from knowledge.main import KnowledgeAgent
from classifier.classifier import Classifier

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


def _make_retry_server(port: int) -> HTTPServer:
    class RetryHandler(BaseHTTPRequestHandler):
        def do_POST(self):
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

            threading.Thread(
                target=_run_retry,
                args=(tracking_id,),
                daemon=True,
                name=f"retry-{tracking_id[:8]}",
            ).start()
            logger.info("Retry accepted for tracking_id=%s", tracking_id[:8])

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
    finally:
        _fresh_scan_lock.release()


def _do_fresh_scan():
    logger.info("Mode: FRESH SCAN (scheduler-triggered)")

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

    source_repo = RepoOps()
    source_path = source_repo.clone(github_repo_url, github_pat)
    logger.info(
        "Source clone ready at %s — up to %d parallel fixes will copy from here.",
        source_path, MAX_PARALLEL_FIXES,
    )

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
        tracking_store.create(record)
        tasks.append((finding, branch_name, record, result.kb_entry))

    def _fix_one(task):
        finding, branch_name, record, kb_entry = task
        logger.info("Processing %s → branch %s", finding.component_name, branch_name)

        with RepoOps() as repo:
            repo.clone_local(source_path, github_repo_url, github_pat)
            branch_created = repo.create_branch(branch_name, skip_if_exists=True)
            if not branch_created:
                logger.info(
                    "Branch already exists — PR likely open. Skipping %s.",
                    finding.component_name,
                )
                return None

            fixer = CodeFixer(repo_path=repo._local_path)
            try:
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

            commit_msg = (
                f"fix: upgrade {finding.component_name} to {finding.recommended_version}"
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
