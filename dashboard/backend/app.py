"""
OSS Remediation Agent — dashboard backend.

Server-rendered (Jinja2 + HTMX), not a JS-framework SPA. Same data sources
as the original streamlit_dashboard.py (TRACKING_STORE_PATH/FIRESTORE_PROJECT/
KB_STORE_PATH env vars, same local-file fallback defaults) -- rendering is
just server-side templates instead of Streamlit widgets or a React build.

Why this over a React frontend: single-stage python:3.11-slim image, no
Node/npm install step, no JS bundler -- builds in seconds. HTMX (vendored
in static/, no CDN dependency) gives auto-refresh and filter-without-
full-reload via plain HTML attributes (hx-get/hx-trigger), no custom JS.
Each tab partial is a "self-polling fragment": hx-trigger="every 30s" lives
on the partial's own root element, so polling naturally stops when htmx
swaps that element out for a different tab (no JS needed to pause it).
"""

import json
import logging
import os
import sys
import time
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents"))

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from common.tracking_store import make_tracking_store, TrackingStatus  # noqa: E402
from common.knowledge_store import make_knowledge_store  # noqa: E402

logger = logging.getLogger(__name__)

app = FastAPI(title="OSS Remediation Agent Dashboard")

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

TRACKING_PATH = Path(os.environ.get("TRACKING_STORE_PATH", "./data/tracking.json"))
DATA_DIR = TRACKING_PATH.parent
CHECKPOINT_PATH = DATA_DIR / "scan_poll_checkpoint.json"
SCAN_DIR = Path(os.environ.get("SCAN_REPORT_PATH", "./scan-reports"))

# fixer-server already has GCP/GitHub credentials mounted and runs the actual
# KnowledgeAgent hydration -- the dashboard stays credential-free and just
# proxies the trigger/status calls over the podman-compose network.
FIXER_SERVER_URL = os.environ.get("FIXER_SERVER_URL", "http://fixer-server:8080")

REPORT_FILES = {
    "Trivy": SCAN_DIR / "trivy-report.json",
    "Grype": SCAN_DIR / "grype-report.json",
    "OWASP": SCAN_DIR / "dependency-check-report" / "dependency-check-report.json",
}

STATUS_ICONS = {
    TrackingStatus.CI_PASSED.value:          "\U0001F7E2",
    TrackingStatus.CI_PENDING.value:         "\U0001F7E1",
    TrackingStatus.CI_FAILED.value:          "\U0001F534",
    TrackingStatus.RETRY_REQUESTED.value:    "\U0001F535",
    TrackingStatus.FAILED_MAX_RETRIES.value: "⛔",
    TrackingStatus.ESCALATED.value:          "⚠️",
    TrackingStatus.ENGINE_ERROR.value:       "\U0001F6D1",
    TrackingStatus.CREATED.value:            "⚪",
    TrackingStatus.PR_OPENED.value:          "\U0001F7E4",
}

# Plain-language explanation of each status -- the raw enum name alone
# (e.g. "CREATED") isn't self-explanatory to anyone who hasn't read
# tracking_store.py's state machine.
#
# This describes what the FIXER PIPELINE believes happened -- distinct from
# the PR-state badge (open/closed/merged), which is what's actually true on
# GitHub right now. They usually agree, but not always: a human can close a
# PR manually and nothing tells the pipeline that happened, so "status" can
# go stale relative to the real PR state. See _records_as_dicts' staleness
# check below, which flags exactly that case instead of hiding it.
STATUS_DESCRIPTIONS = {
    TrackingStatus.CREATED.value:            "pipeline: finding detected, fix not started yet",
    TrackingStatus.PR_OPENED.value:           "pipeline: fix applied, PR opened",
    TrackingStatus.CI_PENDING.value:          "pipeline: PR open, waiting on CI",
    TrackingStatus.CI_PASSED.value:           "pipeline: fix verified, CI passed",
    TrackingStatus.CI_FAILED.value:           "pipeline: CI failed on this attempt",
    TrackingStatus.RETRY_REQUESTED.value:     "pipeline: Watcher requested a corrective retry",
    TrackingStatus.FAILED_MAX_RETRIES.value:  "pipeline: retry budget exhausted -- needs human review",
    TrackingStatus.ESCALATED.value:           "pipeline: escalated to human (invocation or retry-limit issue)",
    TrackingStatus.ENGINE_ERROR.value:        "pipeline: fix engine failed to run (infra issue, not a bad fix) -- needs human review",
}

# If the pipeline still thinks a PR is active but GitHub says otherwise,
# that's a real, useful mismatch to surface -- not something to hide by
# treating the status column as redundant with the PR badge.
_ACTIVE_PR_STATUSES = {TrackingStatus.PR_OPENED.value, TrackingStatus.CI_PENDING.value}

# General bucket-taxonomy definitions, matching agents/classifier/classifier.py's
# own docstring. A TrackingRecord only ever exists for bucket 2 or 3 -- bucket
# 1/4 findings get a GitHub triage issue instead and never reach the fixer, so
# 1/4 are still explained here for completeness (in case someone asks "why
# isn't X in the list at all") but never actually appear on a record.
BUCKET_DEFINITIONS = {
    1: "No fix path -- scanner reported no safe version. A GitHub Issue is opened for manual triage; the fixer never runs on this finding.",
    2: "Patch/minor upgrade, or a major upgrade that isn't a complex framework. Automated fix runs directly.",
    3: "Major-version upgrade with a Knowledge Base entry available (breaking changes / migration steps / find-replace patterns). Automated fix runs with that KB context injected into the prompt.",
    4: "Either a major upgrade to a complex framework (Spring, Hibernate, Struts, ...) with no KB entry, or a transitive-dependency fix judged too risky to automate (introduced by a complex framework, or more than 2 hops deep). A GitHub Issue is opened for human triage instead.",
}

# How much to trust a KB entry's breaking-changes/migration-steps/patterns
# before injecting them into a fix prompt -- determined differently per
# source (see agents/common/knowledge_store.py, agents/knowledge/main.py's
# EXTRACTION_PROMPT, agents/watcher/pattern_learner.py):
KB_CONFIDENCE_HELP = (
    "How much to trust this entry's breaking-changes/migration-steps/patterns "
    "before the fixer uses them as context for a fix:\n\n"
    "tier1_learned -- always High: learned only after a real fix's PR actually "
    "passed CI, so it's empirically proven, not inferred.\n\n"
    "tier2_playbook -- always High: hand-curated by a human when the playbook "
    "was written.\n\n"
    "knowledge_agent -- genuinely variable: the LLM self-rates per its own "
    "extraction prompt -- High if the release notes it read were authoritative, "
    "Medium if inferred, Low if speculative."
)

# Used by the Metrics tab's "Escalated" business-metric count -- terminal,
# needs-a-human states only. Kept separate from _ERR_DISPLAY_STATUSES below:
# CI_FAILED is a normal transient failure (a retry is expected next), not an
# escalation, even though it should still render with an "err" red accent.
_ESCALATED_STATUSES = {
    TrackingStatus.FAILED_MAX_RETRIES.value,
    TrackingStatus.ESCALATED.value,
    TrackingStatus.ENGINE_ERROR.value,
}

# ok/warn/err drives the card accent color in the templates -- a purely
# visual grouping, not a business metric.
_OK_STATUSES = {TrackingStatus.CI_PASSED.value}
_ERR_DISPLAY_STATUSES = _ESCALATED_STATUSES | {TrackingStatus.CI_FAILED.value}


def _status_class(status: str) -> str:
    if status in _OK_STATUSES:
        return "ok"
    if status in _ERR_DISPLAY_STATUSES:
        return "err"
    return "warn"


# ── Live PR-state lookup (open/closed/merged) ──────────────────────────────
# GitHub-style pill badges (colored background, label) -- matches github.com's
# own PR-list badge styling (green Open / purple Merged / red Closed), not a
# generic colored-dot icon.
_PR_STATE_BADGES = {
    "open":   {"label": "Open",   "css": "open"},
    "merged": {"label": "Merged", "css": "merged"},
    "closed": {"label": "Closed", "css": "closed"},
}
_PR_STATE_CACHE: dict = {}   # repo -> (fetched_at, {pr_number: {"state", "icon", "url"}})
_PR_STATE_CACHE_TTL = 90     # seconds


def _fetch_pr_states(repo: str) -> dict:
    """One batched `GET /repos/{repo}/pulls?state=all` call -- not one call
    per PR -- so this stays well within GitHub's rate limits even at
    dashboard-poll frequency (every 30s). Cached per-repo for
    _PR_STATE_CACHE_TTL seconds. Uses GITHUB_PAT if set (higher rate limit,
    5000/hr vs 60/hr), otherwise unauthenticated -- works fine for a public
    repo. Fails soft: any error (network, rate limit, bad/expired token)
    falls back to a stale cache entry if one exists, or {} otherwise, so a
    broken token degrades to "no PR-state icons," not a broken dashboard.
    """
    now = time.time()
    cached = _PR_STATE_CACHE.get(repo)
    if cached and (now - cached[0]) < _PR_STATE_CACHE_TTL:
        return cached[1]

    url = f"https://api.github.com/repos/{repo}/pulls?state=all&per_page=100"
    pat = os.environ.get("GITHUB_PAT")

    prs = None
    if pat:
        try:
            req = urllib.request.Request(
                url, headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {pat}"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                prs = json.loads(resp.read())
        except Exception as exc:
            # A bad/expired token shouldn't take down a feature that can
            # work unauthenticated for a public repo -- fall through and
            # retry without auth instead of giving up immediately.
            logger.warning("Authenticated PR-state fetch failed for %s (%s) -- retrying unauthenticated.", repo, exc)

    if prs is None:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                prs = json.loads(resp.read())
        except Exception as exc:
            logger.warning("Could not fetch PR states for %s: %s", repo, exc)
            return cached[1] if cached else {}

    states = {}
    for pr in prs:
        state = "merged" if pr.get("merged_at") else pr.get("state", "")
        badge = _PR_STATE_BADGES.get(state, {"label": state.title() or "Unknown", "css": "unknown"})
        states[pr["number"]] = {
            "state": state,
            "badge_label": badge["label"],
            "badge_css": badge["css"],
            "url": pr.get("html_url", ""),
        }

    _PR_STATE_CACHE[repo] = (now, states)
    return states


# ── Data access (same env-var fallback convention as streamlit_dashboard.py) ──

def _get_tracking_store():
    if not os.environ.get("TRACKING_STORE_PATH") and not os.environ.get("FIRESTORE_PROJECT"):
        os.environ["TRACKING_STORE_PATH"] = str(TRACKING_PATH)
    return make_tracking_store()


def _get_kb_store():
    if not os.environ.get("KB_STORE_PATH") and not os.environ.get("FIRESTORE_PROJECT"):
        os.environ.setdefault("KB_STORE_PATH", "./data/kb.json")
    return make_knowledge_store()


def _fixer_active() -> bool:
    for p in (CHECKPOINT_PATH, TRACKING_PATH):
        try:
            if p.exists():
                age = (datetime.now(tz=timezone.utc) - datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)).total_seconds()
                if age < 300:
                    return True
        except OSError:
            pass
    return False


def _scan_finding_count() -> int:
    count = 0
    trivy = REPORT_FILES.get("Trivy")
    if trivy and trivy.exists():
        try:
            data = json.loads(trivy.read_text())
            for result in data.get("Results", []):
                count += len(result.get("Vulnerabilities") or [])
        except Exception:
            pass
    grype = REPORT_FILES.get("Grype")
    if grype and grype.exists():
        try:
            data = json.loads(grype.read_text())
            count = max(count, len(data.get("matches", [])))
        except Exception:
            pass
    return count


def _records_as_dicts() -> list:
    store = _get_tracking_store()
    out = []
    pr_states_by_repo: dict = {}  # fetched at most once per repo per call
    for r in store.get_all():
        d = asdict(r)
        tu = d.get("token_usage")
        prompt_tokens = (tu or {}).get("prompt_tokens") or 0
        completion_tokens = (tu or {}).get("completion_tokens") or 0
        d["prompt_tokens"] = prompt_tokens
        d["completion_tokens"] = completion_tokens
        d["total_tokens"] = prompt_tokens + completion_tokens
        d["status_icon"] = STATUS_ICONS.get(d["status"], "•")
        d["status_class"] = _status_class(d["status"])

        d["pr_state"] = None
        d["pr_badge_label"] = None
        d["pr_badge_css"] = None
        if d.get("pr_number") is not None:
            repo = d["repo"]
            if repo not in pr_states_by_repo:
                pr_states_by_repo[repo] = _fetch_pr_states(repo)
            info = pr_states_by_repo[repo].get(d["pr_number"])
            if info:
                d["pr_state"] = info["state"]
                d["pr_badge_label"] = info["badge_label"]
                d["pr_badge_css"] = info["badge_css"]

        # The pipeline's own status can go stale relative to the PR's real
        # GitHub state (e.g. status=PR_OPENED but a human closed the PR
        # manually) -- surface that mismatch explicitly instead of letting
        # the status text quietly disagree with the badge next to it.
        description = STATUS_DESCRIPTIONS.get(d["status"], "")
        if d["status"] in _ACTIVE_PR_STATUSES and d["pr_state"] == "closed":
            description += " -- stale: PR was since closed on GitHub"
        d["status_description"] = description

        # NVD is the standard public reference for a CVE ID -- vulnerability_id
        # isn't always a CVE though (make_fresh_record falls back to the raw
        # component name when a finding has no CVE), so only link when it
        # actually looks like one.
        vuln_id = d.get("vulnerability_id") or ""
        d["vulnerability_url"] = (
            f"https://nvd.nist.gov/vuln/detail/{vuln_id}" if vuln_id.upper().startswith("CVE-") else None
        )

        # Bucket help: the general taxonomy definition always shows; the
        # specific per-finding "why this one landed here" only shows for
        # records created after classifier_rationale started being captured
        # (older records genuinely never had it computed-and-stored, so
        # showing a note about that is more honest than fabricating one).
        if d.get("kb_bucket") is not None:
            help_text = BUCKET_DEFINITIONS.get(d["kb_bucket"], "")
            if d.get("classifier_rationale"):
                help_text += f"\n\nWhy this finding: {d['classifier_rationale']}"
            else:
                help_text += "\n\n(No per-finding rationale recorded for this older record.)"
            if d.get("kb_entry_id"):
                help_text += f"\n\nKB entry: {d['kb_entry_id']} (see Knowledge Base tab)"
            d["bucket_help"] = help_text
        else:
            d["bucket_help"] = ""

        out.append(d)
    return out


def _percentile(sorted_values: list, pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(round(pct * (len(sorted_values) - 1))))
    return sorted_values[idx]


def _sidebar_status() -> dict:
    checkpoint = None
    if CHECKPOINT_PATH.exists():
        mtime = datetime.fromtimestamp(CHECKPOINT_PATH.stat().st_mtime, tz=timezone.utc)
        age_s = (datetime.now(tz=timezone.utc) - mtime).total_seconds()
        last_run_id = None
        try:
            cp = json.loads(CHECKPOINT_PATH.read_text())
            last_run_id = cp.get("last_run_id")
        except Exception:
            pass
        checkpoint = {"age_seconds": age_s, "last_run_id": last_run_id, "stale": age_s >= 120}

    reports = {}
    for label, path in REPORT_FILES.items():
        if path.exists():
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            age_m = (datetime.now(tz=timezone.utc) - mtime).total_seconds() / 60
            reports[label] = {"present": True, "age_minutes": round(age_m)}
        else:
            reports[label] = {"present": False, "age_minutes": None}

    return {
        "checkpoint": checkpoint,
        "reports": reports,
        "fixer_active": _fixer_active(),
        "scan_finding_count": _scan_finding_count(),
        "tracking_path": str(TRACKING_PATH),
    }


# ── Routes: full page ──────────────────────────────────────────────────────

@app.get("/")
def index(request: Request):
    records = _records_as_dicts()
    return templates.TemplateResponse(request, "index.html", {
        "records": records,
        "has_records": bool(records),
        "sidebar": _sidebar_status(),
        **_run_history_context(records),
    })


# ── Routes: partials (HTMX targets, each self-polling) ─────────────────────

@app.get("/partials/sidebar")
def partial_sidebar(request: Request):
    return templates.TemplateResponse(request, "partials/sidebar.html", {"sidebar": _sidebar_status()})


def _group_by_run(view: list) -> list:
    """Groups records by (repo, created_at truncated to the minute).

    TrackingRecord has no explicit run/batch id -- this is a proxy for "came
    from the same scan trigger". Records from one _do_fresh_scan() call are
    all created back-to-back in a synchronous loop with no I/O between them
    (classify -> make_fresh_record per finding), so they share created_at
    down to the second in practice; truncating to the minute is forgiving of
    any small variance while still separating genuinely different runs.
    Keyed by repo too, so two fixers running against two different repos in
    the same minute produce two groups, not one merged group.
    """
    groups: dict = {}
    order: list = []
    for r in view:
        minute = (r.get("created_at") or "")[:16]
        key = (r.get("repo", ""), minute)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)

    result = []
    for key in order:
        recs = groups[key]
        repo, minute = key
        result.append({
            "repo": repo,
            "run_label": minute.replace("T", " ") if minute else "unknown time",
            "records": recs,
            "count": len(recs),
            "ok_count": sum(1 for r in recs if r["status_class"] == "ok"),
            "warn_count": sum(1 for r in recs if r["status_class"] == "warn"),
            "err_count": sum(1 for r in recs if r["status_class"] == "err"),
        })
    return result


def _run_history_context(records: list, status: str = "", component: str = "", repo: str = "") -> dict:
    statuses = sorted({r["status"] for r in records if r.get("status")})
    components = sorted({r["component_name"] for r in records if r.get("component_name")})
    repos = sorted({r["repo"] for r in records if r.get("repo")})

    view = records
    if status:
        view = [r for r in view if r["status"] == status]
    if component:
        view = [r for r in view if r["component_name"] == component]
    if repo:
        view = [r for r in view if r["repo"] == repo]
    view = sorted(view, key=lambda r: r.get("created_at") or "", reverse=True)

    return {
        "view": view,
        "groups": _group_by_run(view),
        "statuses": statuses,
        "components": components,
        "repos": repos,
        "selected_status": status,
        "selected_component": component,
        "selected_repo": repo,
        "total_count": len(records),
    }


@app.get("/partials/run-history")
def partial_run_history(request: Request, status: str = "", component: str = "", repo: str = ""):
    records = _records_as_dicts()
    ctx = _run_history_context(records, status, component, repo)
    return templates.TemplateResponse(request, "partials/run_history.html", ctx)


@app.get("/partials/retry-lineage")
def partial_retry_lineage(request: Request, pr_number: str = ""):
    records = _records_as_dicts()
    pr_numbers = sorted({int(r["pr_number"]) for r in records if r.get("pr_number") is not None})

    selected_pr = int(pr_number) if pr_number else (pr_numbers[-1] if pr_numbers else None)
    lineage = []
    if selected_pr is not None:
        lineage = sorted(
            (r for r in records if r.get("pr_number") == selected_pr),
            key=lambda r: r.get("attempt_number") or 0,
        )

    return templates.TemplateResponse(request, "partials/retry_lineage.html", {
        "pr_numbers": pr_numbers,
        "selected_pr": selected_pr,
        "lineage": lineage,
    })


@app.get("/partials/metrics")
def partial_metrics(request: Request):
    records = _records_as_dicts()

    latest_by_pr = {}
    for r in sorted(records, key=lambda r: r.get("attempt_number") or 0):
        if r.get("pr_number") is not None:
            latest_by_pr[r["pr_number"]] = r
    latest = list(latest_by_pr.values())

    total_prs = len(latest)
    resolved = sum(1 for r in latest if r["status"] == TrackingStatus.CI_PASSED.value)
    escalated = sum(1 for r in latest if r["status"] in _ESCALATED_STATUSES)
    in_progress = total_prs - resolved - escalated
    resolution_rate = (resolved / total_prs * 100) if total_prs else 0.0

    resolved_times = sorted(
        r["time_to_resolution_seconds"] for r in latest
        if r["status"] == TrackingStatus.CI_PASSED.value and r.get("time_to_resolution_seconds") is not None
    )
    avg_resolution = (sum(resolved_times) / len(resolved_times) / 60) if resolved_times else None
    p50_resolution = _percentile(resolved_times, 0.50) / 60 if resolved_times else None
    p95_resolution = _percentile(resolved_times, 0.95) / 60 if resolved_times else None

    total_tokens = sum(r["total_tokens"] for r in records)
    tokens_per_pr = {}
    for r in records:
        if r.get("pr_number") is not None:
            tokens_per_pr[r["pr_number"]] = tokens_per_pr.get(r["pr_number"], 0) + r["total_tokens"]
    avg_tokens_per_pr = (sum(tokens_per_pr.values()) / len(tokens_per_pr)) if tokens_per_pr else None

    tokens_by_attempt: dict = {}
    for r in records:
        n = r.get("attempt_number") or 1
        tokens_by_attempt[n] = tokens_by_attempt.get(n, 0) + r["total_tokens"]
    tokens_by_attempt_bars = _bars(sorted(tokens_by_attempt.items()))

    status_counts: dict = {}
    for r in records:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    status_bars = _bars(sorted(status_counts.items(), key=lambda kv: -kv[1]))
    for b in status_bars:
        b["title"] = STATUS_DESCRIPTIONS.get(b["label"], "")

    depth_per_pr: dict = {}
    for r in records:
        if r.get("pr_number") is not None:
            depth_per_pr[r["pr_number"]] = max(depth_per_pr.get(r["pr_number"], 0), r.get("attempt_number") or 0)
    depth_counts: dict = {}
    for depth in depth_per_pr.values():
        depth_counts[depth] = depth_counts.get(depth, 0) + 1
    depth_bars = _bars(sorted(depth_counts.items()))

    return templates.TemplateResponse(request, "partials/metrics.html", {
        "has_records": bool(records),
        "total_prs": total_prs,
        "resolved": resolved,
        "in_progress": in_progress,
        "escalated": escalated,
        "resolution_rate": resolution_rate,
        "avg_resolution": avg_resolution,
        "p50_resolution": p50_resolution,
        "p95_resolution": p95_resolution,
        "total_tokens": total_tokens,
        "avg_tokens_per_pr": avg_tokens_per_pr,
        "tokens_by_attempt_bars": tokens_by_attempt_bars,
        "status_bars": status_bars,
        "depth_bars": depth_bars,
    })


def _bars(items: list) -> list:
    """items: [(label, value), ...] -> bars with width as a % of the max value,
    rendered as inline SVG/CSS in the template -- no charting library.
    """
    if not items:
        return []
    max_val = max(v for _, v in items) or 1
    return [{"label": str(label), "value": value, "pct": round(value / max_val * 100, 1)} for label, value in items]


def _kb_import_status() -> dict:
    """Proxies fixer-server's GET /import-kb/status. Fails soft -- an
    unreachable fixer-server (not started, wrong URL, etc.) renders as a
    clear "unreachable" state in the UI rather than a broken dashboard page.
    """
    try:
        with urllib.request.urlopen(f"{FIXER_SERVER_URL}/import-kb/status", timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        logger.warning("Could not reach fixer-server for KB import status: %s", exc)
        return {"status": "unreachable", "current": 0, "total": 0, "message": str(exc)}


@app.post("/actions/import-kb")
def trigger_kb_import(request: Request):
    """Proxies fixer-server's POST /import-kb -- the dashboard itself never
    touches GCP/GitHub credentials or runs the LLM call; it only tells
    fixer-server (which already has those credentials mounted) to start.
    """
    try:
        req = urllib.request.Request(f"{FIXER_SERVER_URL}/import-kb", method="POST", data=b"")
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        logger.warning("Could not trigger KB import on fixer-server: %s", exc)
    # just_triggered=True: the background thread on fixer-server may not have
    # flipped status to "running" yet by the time we check -- without this,
    # that race would render the "idle" branch (no polling attached) and the
    # UI would silently never refresh again despite a job actually running.
    return templates.TemplateResponse(request, "partials/kb_import_progress.html", {
        "progress": _kb_import_status(),
        "just_triggered": True,
    })


@app.get("/partials/kb-import-progress")
def kb_import_progress(request: Request):
    return templates.TemplateResponse(request, "partials/kb_import_progress.html", {"progress": _kb_import_status()})


@app.get("/partials/kb")
def partial_kb(request: Request, source: str = ""):
    try:
        store = _get_kb_store()
        entries = store.get_all()
    except Exception:
        entries = []

    source_counts = {"tier1_learned": 0, "tier2_playbook": 0, "knowledge_agent": 0}
    for e in entries:
        source_counts[e.source] = source_counts.get(e.source, 0) + 1

    filtered = entries if not source else [e for e in entries if e.source == source]
    tier_order = {"tier1_learned": 3, "tier2_playbook": 2, "knowledge_agent": 1}
    filtered = sorted(filtered, key=lambda e: tier_order.get(e.source, 0), reverse=True)

    return templates.TemplateResponse(request, "partials/knowledge_base.html", {
        "entries": filtered,
        "has_entries": bool(entries),
        "source_counts": source_counts,
        "selected_source": source,
        "sources": sorted({e.source for e in entries}),
        "confidence_help": KB_CONFIDENCE_HELP,
    })
