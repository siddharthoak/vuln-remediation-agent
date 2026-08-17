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
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents"))

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from common.tracking_store import make_tracking_store, TrackingStatus  # noqa: E402
from common.knowledge_store import make_knowledge_store  # noqa: E402

app = FastAPI(title="OSS Remediation Agent Dashboard")

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

TRACKING_PATH = Path(os.environ.get("TRACKING_STORE_PATH", "./data/tracking.json"))
DATA_DIR = TRACKING_PATH.parent
CHECKPOINT_PATH = DATA_DIR / "scan_poll_checkpoint.json"
SCAN_DIR = Path(os.environ.get("SCAN_REPORT_PATH", "./scan-reports"))

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

_ESCALATED_STATUSES = {
    TrackingStatus.FAILED_MAX_RETRIES.value,
    TrackingStatus.ESCALATED.value,
    TrackingStatus.ENGINE_ERROR.value,
}


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
    for r in store.get_all():
        d = asdict(r)
        tu = d.get("token_usage")
        prompt_tokens = (tu or {}).get("prompt_tokens") or 0
        completion_tokens = (tu or {}).get("completion_tokens") or 0
        d["prompt_tokens"] = prompt_tokens
        d["completion_tokens"] = completion_tokens
        d["total_tokens"] = prompt_tokens + completion_tokens
        d["status_icon"] = STATUS_ICONS.get(d["status"], "•")
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
    })
