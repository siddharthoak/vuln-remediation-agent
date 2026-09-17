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
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents"))

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from common.tracking_store import make_tracking_store, TrackingStatus  # noqa: E402
from common.knowledge_store import make_knowledge_store  # noqa: E402
from common.config import (  # noqa: E402
    get_target_repo,
    get_target_repos,
    get_github_pat,
    save_config,
    normalize_repo_name,
    get_upload_dir,
    get_download_dir,
    resolve_repo_source,
    is_nightly_run_enabled,
    set_nightly_run_enabled,
    set_scan_requested,
    get_nightly_run_time,
    get_nightly_scan_max_wait_seconds,
    set_nightly_schedule,
)
from common.github_auth import get_auth_mode  # noqa: E402
from common.reset_ops import reset_repository_state  # noqa: E402

logger = logging.getLogger(__name__)

app = FastAPI(title="OSS Remediation Agent Dashboard")

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def _to_local_str(iso_str: str | None, tz_name: str | None = None) -> str:
    """Convert an ISO-8601 UTC timestamp string to a formatted local time string.

    Defaults to NIGHTLY_RUN_TIMEZONE (or 'Asia/Kolkata') if tz_name is not provided.
    Returns format 'YYYY-MM-DD HH:MM'.
    """
    if not iso_str:
        return ""
    try:
        target_tz_name = tz_name or os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata")
        try:
            tz = ZoneInfo(target_tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            tz = datetime.now().astimezone().tzinfo or timezone.utc

        s = str(iso_str).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")
    except Exception as e:
        logger.warning("Failed to convert timestamp %r to local time: %s", iso_str, e)
        return str(iso_str)[:16].replace("T", " ")


templates.env.filters["localtime"] = _to_local_str

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
    pat = get_github_pat(repo=repo)

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
        d["model_name"] = (tu or {}).get("model_name")
        d["total_tokens"] = prompt_tokens + completion_tokens
        d["status_icon"] = STATUS_ICONS.get(d["status"], "•")
        d["status_class"] = _status_class(d["status"])
        d["created_at_local"] = _to_local_str(d.get("created_at"))
        d["updated_at_local"] = _to_local_str(d.get("updated_at"))

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


def _repo_config_context(notice: dict = None) -> dict:
    repo = get_target_repo()
    repos = get_target_repos()
    pat = get_github_pat()
    auth_info = get_auth_mode()
    masked_pat = ""
    if pat:
        masked_pat = pat[:4] + "*" * max(0, len(pat) - 8) + pat[-4:] if len(pat) > 8 else "****"
    repo_display = ", ".join(repos) if len(repos) > 1 else repo

    download_dir = get_download_dir()
    downloadable_zips = []
    if download_dir.exists():
        for z in sorted(download_dir.glob("*.zip"), key=lambda f: f.stat().st_mtime, reverse=True):
            size_kb = z.stat().st_size / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"
            downloadable_zips.append({
                "name": z.name,
                "clean_name": z.name.replace("-remediated.zip", "").replace(".zip", ""),
                "size": size_str,
            })

    return {
        "config": {
            "repo": repo_display,
            "pat": pat,
            "masked_pat": masked_pat,
            "has_pat": bool(pat),
            "is_multi_repo": len(repos) > 1,
            "repo_chain": repos,
            "downloadable_zips": downloadable_zips,
            "auth_mode": auth_info["mode"],
            "auth_label": auth_info["label"],
            "auth_desc": auth_info["description"],
            "is_github_app": auth_info["mode"] == "github_app",
            "app_id": auth_info.get("app_id"),
            "nightly_run_enabled": is_nightly_run_enabled(),
            "nightly_run_time": get_nightly_run_time(),
            "nightly_duration_hours": get_nightly_scan_max_wait_seconds() // 3600,
            "nightly_timezone": os.environ.get("NIGHTLY_RUN_TIMEZONE", "Asia/Kolkata"),
        },
        "notice": notice,
    }



# ── Routes: full page ──────────────────────────────────────────────────────

@app.get("/")
def index(request: Request):
    records = _records_as_dicts()
    return templates.TemplateResponse(request, "index.html", {
        "records": records,
        "has_records": bool(records),
        "sidebar": _sidebar_status(),
        **_repo_config_context(),
        **_run_history_context(records),
    })


# ── Routes: partials & API actions ──────────────────────────────────────────

@app.get("/partials/repo-config")
def partial_repo_config(request: Request):
    return templates.TemplateResponse(request, "partials/repo_config.html", _repo_config_context())


@app.post("/api/config")
async def api_save_config(request: Request):
    body = await request.body()
    form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    repo_val = form_data.get("repo", [""])[0].strip()
    pat_val = form_data.get("pat", [""])[0].strip()
    run_time = form_data.get("nightly_run_time", [get_nightly_run_time()])[0].strip()
    duration_value = form_data.get("nightly_duration_hours", [str(get_nightly_scan_max_wait_seconds() // 3600)])[0].strip()

    if not repo_val:
        ctx = _repo_config_context(notice={"type": "err", "message": "Repository cannot be empty."})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)
    try:
        duration_hours = int(duration_value)
        set_nightly_schedule(run_time, duration_hours)
    except ValueError as exc:
        ctx = _repo_config_context(notice={"type": "err", "message": str(exc)})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)

    # Check if multiple repos were supplied (e.g. Repo A, Repo B, Repo C)
    if "," in repo_val or "\n" in repo_val:
        raw_parts = [r.strip() for r in re.split(r"[,;\n]+", repo_val) if r.strip()]
        clean_chain = [normalize_repo_name(r) for r in raw_parts if normalize_repo_name(r)]
        clean_repo = clean_chain[0] if clean_chain else normalize_repo_name(repo_val)
        save_config(repo=clean_repo, pat=pat_val if pat_val else None, repo_chain=clean_chain)
        notice_msg = f"Multi-repository chain configured ({len(clean_chain)} repos: {' → '.join(clean_chain)})!"
    else:
        clean_repo = normalize_repo_name(repo_val)
        save_config(clean_repo, pat_val if pat_val else None, repo_chain=[clean_repo])
        notice_msg = f"Target repository switched to '{clean_repo}'!"

    _PR_STATE_CACHE.clear()

    ctx = _repo_config_context(notice={"type": "ok", "message": notice_msg})
    return templates.TemplateResponse(request, "partials/repo_config.html", ctx)


def _safe_extract_zip(zip_path: Path, target_dir: Path) -> None:
    """Safely extracts zip_path into target_dir preventing Zip Slip."""
    target_dir.mkdir(parents=True, exist_ok=True)
    target_dir_resolved = target_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = (target_dir / member.filename).resolve()
            if not str(member_path).startswith(str(target_dir_resolved)):
                raise ValueError(f"Zip path traversal detected: {member.filename}")
        zf.extractall(target_dir)

    # If the zip archive has a single wrapper folder (e.g. repo-main/...), unwrap it
    entries = [e for e in target_dir.iterdir() if e.name not in ("__MACOSX",)]
    if len(entries) == 1 and entries[0].is_dir() and entries[0].name not in (".git", "src", "target", "build"):
        nested = entries[0]
        temp_dest = target_dir.parent / f"{target_dir.name}_unwrap_{int(time.time())}"
        nested.rename(temp_dest)
        shutil.rmtree(target_dir, ignore_errors=True)
        temp_dest.rename(target_dir)

    # Initialize git repo if not already present
    git_dir = target_dir / ".git"
    if not git_dir.exists():
        try:
            import git
            repo = git.Repo.init(str(target_dir))
            with repo.config_writer() as config:
                config.set_value("user", "name", "OSS Remediation Agent")
                config.set_value("user", "email", "agent@remediation.local")
            repo.git.add(A=True)
            if not repo.heads:
                repo.index.commit("Initial commit from uploaded zip archive")
        except Exception as exc:
            logger.warning("Could not initialize git for %s: %s", target_dir, exc)


@app.post("/api/upload-zips")
async def api_upload_zips(request: Request, repo_zips: list[UploadFile] = File(...)):
    if not repo_zips:
        ctx = _repo_config_context(notice={"type": "err", "message": "No files selected for upload."})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)

    upload_dir = get_upload_dir()
    extracted_repos = []
    errors = []

    for file_obj in repo_zips:
        filename = file_obj.filename or "repo.zip"
        if not filename.lower().endswith(".zip"):
            errors.append(f"{filename}: only .zip files are supported.")
            continue

        clean_name = normalize_repo_name(filename)
        dest_repo_dir = upload_dir / clean_name

        temp_zip = upload_dir / f"{clean_name}_temp_{int(time.time())}.zip"
        try:
            content = await file_obj.read()
            temp_zip.write_bytes(content)
            _safe_extract_zip(temp_zip, dest_repo_dir)
            extracted_repos.append(clean_name)
        except Exception as exc:
            logger.exception("Failed extracting zip %s: %s", filename, exc)
            errors.append(f"{filename}: {exc}")
        finally:
            if temp_zip.exists():
                try:
                    temp_zip.unlink()
                except Exception:
                    pass

    if not extracted_repos:
        msg = "Upload failed: " + "; ".join(errors) if errors else "No valid repositories extracted."
        ctx = _repo_config_context(notice={"type": "err", "message": msg})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)

    # Set uploaded repos as active chain (or combine)
    existing_repos = get_target_repos()
    # If existing repos were just the default test repo, replace with uploaded repos
    if len(existing_repos) == 1 and ("Test_repo_1" in existing_repos[0] or "vuln-remediation-agent" in existing_repos[0]):
        combined_chain = extracted_repos
    else:
        combined_chain = list(dict.fromkeys(existing_repos + extracted_repos))

    save_config(repo=combined_chain[0], pat=get_github_pat() or None, repo_chain=combined_chain)
    _PR_STATE_CACHE.clear()

    notice_msg = f"Successfully uploaded and extracted {len(extracted_repos)} repository archive(s): {', '.join(extracted_repos)}!"
    if errors:
        notice_msg += f" (Warnings: {'; '.join(errors)})"

    ctx = _repo_config_context(notice={"type": "ok", "message": notice_msg})
    return templates.TemplateResponse(request, "partials/repo_config.html", ctx)


@app.get("/api/download-zip/{repo_name}")
def download_remediated_zip(repo_name: str):
    clean_name = normalize_repo_name(repo_name).replace("/", "_")
    download_dir = get_download_dir()

    # Direct zip file match in data/downloads
    cands = [
        download_dir / f"{clean_name}-remediated.zip",
        download_dir / f"{clean_name}.zip",
        download_dir / f"{repo_name}.zip",
        download_dir / repo_name,
    ]
    for cand in cands:
        if cand.is_file():
            return FileResponse(
                path=str(cand.resolve()),
                filename=cand.name,
                media_type="application/zip",
            )

    # Check if directory exists in uploads and zip it on the fly
    upload_dir = get_upload_dir()
    repo_path = upload_dir / clean_name
    if not repo_path.is_dir():
        repo_path = upload_dir / repo_name
    if repo_path.is_dir():
        out_zip = download_dir / f"{clean_name}-remediated.zip"
        with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, filenames in os.walk(repo_path):
                for filename in filenames:
                    full_p = os.path.join(root, filename)
                    rel_p = os.path.relpath(full_p, repo_path)
                    if not rel_p.startswith(".git"):
                        zf.write(full_p, rel_p)
        return FileResponse(
            path=str(out_zip.resolve()),
            filename=out_zip.name,
            media_type="application/zip",
        )

    raise HTTPException(status_code=404, detail=f"Archive for repository '{repo_name}' not found.")


@app.post("/api/reset")
async def api_reset(request: Request):
    repos = get_target_repos()
    repo = repos[0] if repos else get_target_repo()

    if not repo:
        ctx = _repo_config_context(notice={"type": "err", "message": "No target repository configured."})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)

    try:
        res = reset_repository_state(
            repo=None if repos else repo,
            keep_kb=True,
        )
        _PR_STATE_CACHE.clear()

        reset_repos = res.get("repos", repos or [repo])
        msg_parts = [f"Reset complete for all configured repositories: {', '.join(reset_repos)}."]
        if res["prs_closed"]:
            msg_parts.append(f"Closed PR(s): {', '.join(map(str, res['prs_closed']))}.")
        if res["branches_deleted"]:
            msg_parts.append(f"Deleted branch(es): {', '.join(res['branches_deleted'])}.")
        if res["triage_issues_closed"]:
            msg_parts.append(f"Closed triage issue(s): {', '.join(map(str, res['triage_issues_closed']))}.")
        msg_parts.append("Shared tracking state, checkpoints, and scan reports cleared once.")
        msg_parts.append("Knowledge Base (kb.json) preserved!")
        if res["errors"]:
            msg_parts.append(f"Warnings: {'; '.join(res['errors'])}")

        ctx = _repo_config_context(notice={"type": "ok", "message": " ".join(msg_parts)})
    except Exception as exc:
        logger.error("Reset failed: %s", exc, exc_info=True)
        ctx = _repo_config_context(notice={"type": "err", "message": f"Reset failed: {exc}"})

    return templates.TemplateResponse(request, "partials/repo_config.html", ctx)


@app.post("/api/trigger-scan")
async def api_trigger_scan(request: Request):
    repo = get_target_repo()
    pat = get_github_pat(repo=repo)

    if not repo:
        ctx = _repo_config_context(notice={"type": "err", "message": "No target repository configured."})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)
    if not pat:
        ctx = _repo_config_context(notice={"type": "err", "message": "GitHub authentication (GitHub App or PAT) required to trigger scan workflow."})
        return templates.TemplateResponse(request, "partials/repo_config.html", ctx)

    url = f"https://api.github.com/repos/{repo}/actions/workflows/security-scan.yml/dispatches"
    req = urllib.request.Request(
        url,
        data=json.dumps({"ref": "main"}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "vuln-remediation-agent",
        },
        method="POST",
    )
    try:
        set_scan_requested(True)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 204):
                set_scan_requested(False)
                msg = f"Dispatched security-scan.yml on GitHub Actions for '{repo}' (ref: main)! ScanPoller will detect it once complete."
                ctx = _repo_config_context(notice={"type": "ok", "message": msg})
            else:
                set_scan_requested(False)
                ctx = _repo_config_context(notice={"type": "warn", "message": f"Workflow dispatch returned status {resp.status}."})
    except urllib.error.HTTPError as he:
        set_scan_requested(False)
        err_body = he.read().decode("utf-8", errors="ignore")
        msg = f"Failed to trigger scan workflow (HTTP {he.code}): {he.reason}. {err_body}"
        ctx = _repo_config_context(notice={"type": "err", "message": msg})
    except Exception as exc:
        set_scan_requested(False)
        ctx = _repo_config_context(notice={"type": "err", "message": f"Failed to trigger workflow: {exc}"})

    return templates.TemplateResponse(request, "partials/repo_config.html", ctx)


@app.post("/api/toggle-night-mode")
async def api_toggle_night_mode(request: Request):
    current_state = is_nightly_run_enabled()
    new_state = not current_state
    set_nightly_run_enabled(new_state)

    if new_state:
        msg = f"Night Mode ENABLED: Agent scheduled daily at {get_nightly_run_time()} ({os.environ.get('NIGHTLY_RUN_TIMEZONE', 'Asia/Kolkata')}) for up to {get_nightly_scan_max_wait_seconds() // 3600} hour(s)."
    else:
        msg = "Night Mode DISABLED: Agent switched to Immediate Execution mode!"
        # Attempt to dispatch immediate scan call to fixer server
        try:
            for target_url in ["http://fixer-server:8080/scan", "http://localhost:8080/scan"]:
                try:
                    req = urllib.request.Request(
                        target_url,
                        data=json.dumps({}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status in (200, 202):
                            msg += " Dispatched immediate scan execution!"
                            break
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("Could not dispatch immediate scan: %s", exc)

    ctx = _repo_config_context(notice={"type": "ok", "message": msg})
    return templates.TemplateResponse(request, "partials/repo_config.html", ctx)


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
        minute = r.get("created_at_local") or _to_local_str(r.get("created_at"))
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
            "run_label": minute if minute else "unknown time",
            "records": recs,
            "count": len(recs),
            "ok_count": sum(1 for r in recs if r["status_class"] == "ok"),
            "warn_count": sum(1 for r in recs if r["status_class"] == "warn"),
            "err_count": sum(1 for r in recs if r["status_class"] == "err"),
        })
    return result


def _run_history_context(records: list, status: str = "", component: str = "", repo: str = "", locality: str = "") -> dict:
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
    if locality == "transitive":
        view = [r for r in view if r.get("is_transitive")]
    elif locality == "direct":
        view = [r for r in view if not r.get("is_transitive")]
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
        "selected_locality": locality,
        "total_count": len(records),
    }


@app.get("/partials/run-history")
def partial_run_history(request: Request, status: str = "", component: str = "", repo: str = "", locality: str = ""):
    records = _records_as_dicts()
    ctx = _run_history_context(records, status, component, repo, locality)
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

    # Count distinct PRs opened
    unique_prs = {r["pr_number"] for r in records if r.get("pr_number") is not None}
    total_prs = len(unique_prs)

    # Compute latest status per component/vulnerability (avoids collapsing batched combined PRs)
    latest_by_component = {}
    for r in sorted(records, key=lambda x: (x.get("created_at") or "", x.get("attempt_number") or 0)):
        key = (r.get("repo"), r.get("component_name") or r.get("vulnerability_id"))
        latest_by_component[key] = r
    latest = list(latest_by_component.values())

    total_findings = len(latest)
    resolved = sum(1 for r in latest if r["status"] == TrackingStatus.CI_PASSED.value)
    escalated = sum(1 for r in latest if r["status"] in _ESCALATED_STATUSES)
    in_progress = max(0, total_findings - resolved - escalated)
    resolution_rate = (resolved / total_findings * 100) if total_findings else 0.0

    eval_set = latest if latest else records
    transitive_count = sum(1 for r in eval_set if r.get("is_transitive"))
    direct_count = sum(1 for r in eval_set if not r.get("is_transitive"))
    chain_count = sum(1 for r in eval_set if r.get("chain_step"))

    resolved_times = sorted(
        r["time_to_resolution_seconds"] for r in latest
        if r["status"] == TrackingStatus.CI_PASSED.value and r.get("time_to_resolution_seconds") is not None
    )
    avg_resolution = (sum(resolved_times) / len(resolved_times) / 60) if resolved_times else None
    p50_resolution = _percentile(resolved_times, 0.50) / 60 if resolved_times else None
    p95_resolution = _percentile(resolved_times, 0.95) / 60 if resolved_times else None

    total_tokens = sum(r["total_tokens"] for r in records)
    tokens_per_issue = {}
    for r in records:
        vid = r.get("vulnerability_id") or r.get("component_name") or r.get("tracking_id")
        if vid:
            tokens_per_issue[vid] = tokens_per_issue.get(vid, 0) + r["total_tokens"]
    avg_tokens_per_issue = (sum(tokens_per_issue.values()) / len(tokens_per_issue)) if tokens_per_issue else None

    tokens_by_attempt: dict = {}
    for r in records:
        n = r.get("attempt_number") or 1
        tokens_by_attempt[n] = tokens_by_attempt.get(n, 0) + r["total_tokens"]
    tokens_by_attempt_bars = _bars(sorted(tokens_by_attempt.items()))

    tokens_by_component: dict = {}
    for r in records:
        comp = r.get("component_name") or "Unknown"
        tokens_by_component[comp] = tokens_by_component.get(comp, 0) + (r.get("total_tokens") or 0)
    
    sorted_comps = sorted(tokens_by_component.items(), key=lambda x: x[1], reverse=True)
    tokens_by_component_bars = _bars(sorted_comps[:15])

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
        "transitive_count": transitive_count,
        "direct_count": direct_count,
        "chain_count": chain_count,
        "avg_resolution": avg_resolution,
        "p50_resolution": p50_resolution,
        "p95_resolution": p95_resolution,
        "total_tokens": total_tokens,
        "avg_tokens_per_issue": avg_tokens_per_issue,
        "tokens_by_attempt_bars": tokens_by_attempt_bars,
        "tokens_by_component_bars": tokens_by_component_bars,
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
        "confidence_help": KB_CONFIDENCE_HELP,
    })
