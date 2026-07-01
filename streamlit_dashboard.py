"""
OSS Remediation Agent — observability dashboard.

Local-only, read-only. Reads tracking state directly from the bind-mounted
./data/tracking.json file written by fixer-server and watcher.

Usage:
    # Default (reads ./data/tracking.json):
    streamlit run streamlit_dashboard.py

    # Custom tracking file location:
    TRACKING_STORE_PATH=./data/tracking.json streamlit run streamlit_dashboard.py
"""

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
# pandas 3.0 defaults to Arrow-backed StringDtype which conflicts with
# Streamlit's PyArrow cache serialization on macOS, causing SIGBUS.
pd.set_option("future.infer_string", False)
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agents"))
sys.path.insert(0, os.path.dirname(__file__))

from common.tracking_store import make_tracking_store, TrackingStatus  # noqa: E402
from common.knowledge_store import make_knowledge_store                # noqa: E402


# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="OSS Remediation Agent",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ OSS Remediation Agent — Dashboard")


# ── Agent status sidebar ──────────────────────────────────────────────────────

with st.sidebar:
    st.header("Agent status")

    # Fixer-server heartbeat: check scan_poll_checkpoint.json last-modified time
    tracking_path = os.environ.get("TRACKING_STORE_PATH", "./data/tracking.json")
    data_dir = Path(tracking_path).parent
    checkpoint_path = data_dir / "scan_poll_checkpoint.json"

    if checkpoint_path.exists():
        mtime = datetime.fromtimestamp(checkpoint_path.stat().st_mtime, tz=timezone.utc)
        age_s = (datetime.now(tz=timezone.utc) - mtime).total_seconds()
        poll_interval = 60
        if age_s < poll_interval * 2:
            st.success(f"Fixer-server polling ✓  \n_last seen {int(age_s)}s ago_")
        else:
            st.warning(f"Fixer-server may be idle  \n_checkpoint {int(age_s / 60)}m old_")
        try:
            cp = json.loads(checkpoint_path.read_text())
            st.caption(f"Last processed run: `{cp.get('last_run_id', '—')}`")
        except Exception:
            pass
    else:
        st.info("Fixer-server: no checkpoint yet  \n_waiting for first scan_")

    st.divider()

    # Scan reports present
    st.subheader("Scan reports")
    scan_dir = Path("./scan-reports")
    report_files = {
        "Trivy":  scan_dir / "trivy-report.json",
        "Grype":  scan_dir / "grype-report.json",
        "OWASP":  scan_dir / "dependency-check-report" / "dependency-check-report.json",
    }
    for label, path in report_files.items():
        if path.exists():
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            age_m = (datetime.now(tz=timezone.utc) - mtime).total_seconds() / 60
            st.success(f"{label} ✓  \n_{int(age_m)}m ago_")
        else:
            st.error(f"{label} — not found")

    st.divider()
    st.caption("Auto-refreshes every 30s via cache TTL.  \nClick **↺ Refresh** to force.")


# ── Activity detection helpers ────────────────────────────────────────────────

tracking_path_used = os.environ.get("TRACKING_STORE_PATH", "./data/tracking.json")
tracking_file      = Path(tracking_path_used)

def _fixer_active() -> bool:
    """Return True if fixer wrote to any data file in the last 5 minutes."""
    for p in [checkpoint_path, tracking_file]:
        try:
            if p.exists():
                age = (datetime.now(tz=timezone.utc) -
                       datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)).total_seconds()
                if age < 300:
                    return True
        except OSError:
            pass
    return False

def _scan_finding_count() -> int:
    """Return total findings across all present scan reports (best-effort)."""
    count = 0
    trivy = report_files.get("Trivy")
    if trivy and trivy.exists():
        try:
            data = json.loads(trivy.read_text())
            for result in data.get("Results", []):
                count += len(result.get("Vulnerabilities") or [])
        except Exception:
            pass
    grype = report_files.get("Grype")
    if grype and grype.exists():
        try:
            data = json.loads(grype.read_text())
            count = max(count, len(data.get("matches", [])))
        except Exception:
            pass
    return count


# ── Data loading ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=30)
def load_records() -> pd.DataFrame:
    # Default TRACKING_STORE_PATH to the bind-mount location used by docker-compose
    if not os.environ.get("TRACKING_STORE_PATH") and not os.environ.get("FIRESTORE_PROJECT"):
        os.environ["TRACKING_STORE_PATH"] = "./data/tracking.json"

    store = make_tracking_store()
    records = store.get_all()
    if not records:
        return pd.DataFrame()

    df = pd.DataFrame([asdict(r) for r in records])
    # Keep created_at/updated_at as strings — pandas 3.0 + pyarrow causes SIGBUS
    # on macOS ARM64 when boolean-indexing DataFrames with tz-aware datetime columns.
    # Streamlit's DatetimeColumn config handles ISO-8601 strings natively.

    if "token_usage" in df.columns:
        df["prompt_tokens"]     = df["token_usage"].apply(lambda x: x.get("prompt_tokens", 0)     if isinstance(x, dict) else 0)
        df["completion_tokens"] = df["token_usage"].apply(lambda x: x.get("completion_tokens", 0) if isinstance(x, dict) else 0)
        df["total_tokens"]      = df["prompt_tokens"] + df["completion_tokens"]

    return df


df = load_records()

col_refresh, col_count = st.columns([1, 9])
with col_refresh:
    if st.button("↺ Refresh"):
        load_records.clear()
        st.rerun()

active = _fixer_active()

# ── Top-of-page status banner ─────────────────────────────────────────────────
if df.empty:
    if active:
        n = _scan_finding_count()
        finding_str = f"{n} finding(s) detected — " if n else ""
        st.info(
            f"⚙️ **Fixer is initializing** — {finding_str}building the knowledge base "
            "and preparing fix branches.  \n"
            "Tracking records appear once PRs are opened. "
            "**Auto-refreshing every 10 s.**"
        )
        # Inject a client-side meta-refresh so the page reloads automatically.
        import streamlit.components.v1 as components
        components.html("<meta http-equiv='refresh' content='10'>", height=0)
    else:
        st.info(
            "No tracking records yet.  \n\n"
            "Start the agents with `docker compose up -d`, trigger the security scan on your "
            "target repo, and records will appear here once the fixer picks up the reports.  \n\n"
            f"Reading from: `{tracking_path_used}`"
        )
else:
    created_df = df[df["status"] == TrackingStatus.CREATED.value]
    if not created_df.empty:
        st.info(
            f"⚙️ **Fixer is processing** — {len(created_df)} finding(s) across "
            f"{created_df['component_name'].nunique()} component(s) are queued or in flight.  \n"
            "Records will update as PRs are opened. "
            "**Auto-refreshing every 10 s.**"
        )
        import streamlit.components.v1 as components
        components.html("<meta http-equiv='refresh' content='10'>", height=0)

if not df.empty:
    with col_count:
        pr_col = df["pr_number"].dropna() if "pr_number" in df.columns else pd.Series([], dtype=float)
        st.caption(f"{len(df)} total record(s) across {pr_col.nunique()} PR(s)")


# ── Tabs (always rendered; history/lineage/metrics gracefully handle empty df) ─

tab_history, tab_lineage, tab_metrics, tab_kb = st.tabs([
    "Run History",
    "Retry Lineage",
    "Metrics",
    "Knowledge Base",
])


# ── Tab 1: Run History ────────────────────────────────────────────────────────

with tab_history:
    st.subheader("All Fix Attempts")

    if df.empty:
        st.info("No fix attempts recorded yet. The fixer has not opened any PRs.")
    else:
        col_status, col_component, col_repo = st.columns(3)

        with col_status:
            statuses = ["(all)"] + sorted(df["status"].dropna().unique().tolist())
            status_filter = st.selectbox("Status", statuses)

        with col_component:
            comps = ["(all)"] + sorted(df["component_name"].dropna().unique().tolist())
            component_filter = st.selectbox("Component", comps)

        with col_repo:
            repos = ["(all)"] + sorted(df["repo"].dropna().unique().tolist())
            repo_filter = st.selectbox("Repository", repos)

        view = df.copy()
        if status_filter != "(all)":
            view = view[view["status"] == status_filter]
        if component_filter != "(all)":
            view = view[view["component_name"] == component_filter]
        if repo_filter != "(all)":
            view = view[view["repo"] == repo_filter]

        display_cols = [
            "created_at", "component_name", "old_version", "new_version",
            "status", "attempt_number", "pr_number", "branch_name",
            "time_to_resolution_seconds", "total_tokens", "tracking_id",
        ]
        display_cols = [c for c in display_cols if c in view.columns]

        STATUS_COLORS = {
            TrackingStatus.CI_PASSED.value:          "🟢",
            TrackingStatus.CI_PENDING.value:         "🟡",
            TrackingStatus.CI_FAILED.value:          "🔴",
            TrackingStatus.RETRY_REQUESTED.value:    "🔵",
            TrackingStatus.FAILED_MAX_RETRIES.value: "⛔",
            TrackingStatus.ESCALATED.value:          "⚠️",
            TrackingStatus.CREATED.value:            "⚪",
            TrackingStatus.PR_OPENED.value:          "🟤",
        }
        view = view.copy()
        view["status"] = view["status"].apply(lambda s: f"{STATUS_COLORS.get(s, '•')} {s}")

        st.dataframe(
            view[display_cols].sort_values("created_at", ascending=False),
            use_container_width=True,
            hide_index=True,
            column_config={
                "created_at":                 st.column_config.DatetimeColumn("Created", format="MMM D, HH:mm"),
                "time_to_resolution_seconds": st.column_config.NumberColumn("Resolution (s)", format="%d s"),
                "total_tokens":               st.column_config.NumberColumn("Tokens"),
                "pr_number":                  st.column_config.NumberColumn("PR #", format="%d"),
                "attempt_number":             st.column_config.NumberColumn("Attempt"),
            },
        )
        st.caption(f"{len(view)} record(s) shown of {len(df)} total.")


# ── Tab 2: Retry Lineage ──────────────────────────────────────────────────────

with tab_lineage:
    st.subheader("Retry Lineage by PR")

    pr_numbers = (
        sorted(df["pr_number"].dropna().astype(int).unique().tolist())
        if "pr_number" in df.columns else []
    )
    if not pr_numbers:
        st.info("No PRs with tracking records yet.")
    else:
        selected_pr = st.selectbox("Select PR number", pr_numbers, format_func=lambda n: f"PR #{n}")

        lineage = df[df["pr_number"] == selected_pr].sort_values("attempt_number")
        st.markdown(f"**{len(lineage)} attempt(s)** for PR #{selected_pr}")

        ICONS = {
            TrackingStatus.CI_PASSED.value:          "✅",
            TrackingStatus.CI_FAILED.value:          "❌",
            TrackingStatus.RETRY_REQUESTED.value:    "🔄",
            TrackingStatus.FAILED_MAX_RETRIES.value: "🚫",
            TrackingStatus.ESCALATED.value:          "⚠️",
            TrackingStatus.CI_PENDING.value:         "⏳",
            TrackingStatus.PR_OPENED.value:          "📬",
            TrackingStatus.CREATED.value:            "🆕",
        }

        for _, row in lineage.iterrows():
            status = row["status"]
            icon   = ICONS.get(status, "•")
            with st.expander(
                f"{icon} Attempt {int(row['attempt_number'])} — {status} "
                f"({pd.to_datetime(row['created_at']).strftime('%Y-%m-%d %H:%M UTC')})"
            ):
                c1, c2 = st.columns(2)
                c1.metric("Component",      row["component_name"])
                c1.metric("Version change", f"{row['old_version']} → {row['new_version']}")
                c2.metric("Branch",         row.get("branch_name") or "—")
                c2.metric("Tracking ID",    str(row["tracking_id"])[:8] + "…")

                if row.get("parent_tracking_id"):
                    st.caption(f"Parent attempt: `{str(row['parent_tracking_id'])[:8]}…`")

                if row.get("time_to_resolution_seconds") is not None:
                    st.metric("Time to this outcome", f"{row['time_to_resolution_seconds'] / 60:.1f} min")

                if isinstance(row.get("token_usage"), dict):
                    tu = row["token_usage"]
                    total = tu.get("prompt_tokens", 0) + tu.get("completion_tokens", 0)
                    st.metric(
                        "Token usage", f"{total:,}",
                        help=f"Prompt: {tu.get('prompt_tokens', 0):,}  |  Completion: {tu.get('completion_tokens', 0):,}",
                    )

                if row.get("failure_log_excerpt"):
                    st.markdown("**CI failure excerpt passed to retry prompt:**")
                    st.code(row["failure_log_excerpt"][:2000], language="text")


# ── Tab 3: Metrics ────────────────────────────────────────────────────────────

with tab_metrics:
    st.subheader("Run Metrics")

    if df.empty:
        st.info("No metrics yet — run data will appear here once PRs are opened.")
    else:
        latest = (
            df.sort_values("attempt_number")
              .groupby("pr_number")
              .last()
              .reset_index()
        )

        total_prs   = len(latest)
        resolved    = (latest["status"] == TrackingStatus.CI_PASSED.value).sum()
        escalated   = latest["status"].isin([
            TrackingStatus.FAILED_MAX_RETRIES.value,
            TrackingStatus.ESCALATED.value,
        ]).sum()
        in_progress = total_prs - resolved - escalated
        resolution_rate = resolved / total_prs * 100 if total_prs else 0.0

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("PRs opened",      total_prs)
        m2.metric("Resolved ✅",      resolved,   help="Status = CI_PASSED")
        m3.metric("In progress ⏳",   in_progress)
        m4.metric("Escalated ⛔",     escalated,  help="FAILED_MAX_RETRIES or ESCALATED")
        m5.metric("Resolution rate", f"{resolution_rate:.1f}%")

        st.divider()

        resolved_df = latest[latest["status"] == TrackingStatus.CI_PASSED.value]
        if not resolved_df.empty and "time_to_resolution_seconds" in resolved_df.columns:
            valid = resolved_df["time_to_resolution_seconds"].dropna()
            if not valid.empty:
                t1, t2, t3 = st.columns(3)
                t1.metric("Avg time-to-resolution", f"{valid.mean() / 60:.1f} min")
                t2.metric("p50",                    f"{valid.median() / 60:.1f} min")
                t3.metric("p95",                    f"{valid.quantile(0.95) / 60:.1f} min")
                st.divider()

        if "total_tokens" in df.columns:
            total_tokens = int(df["total_tokens"].sum())
            avg_per_pr   = df.groupby("pr_number")["total_tokens"].sum().mean()
            tk1, tk2 = st.columns(2)
            tk1.metric("Total tokens consumed", f"{total_tokens:,}")
            tk2.metric("Avg tokens per PR",     f"{avg_per_pr:,.0f}" if not pd.isna(avg_per_pr) else "—")

            st.markdown("**Token usage by attempt number**")
            token_by_attempt = (
                df.groupby("attempt_number")["total_tokens"]
                  .sum()
                  .reset_index()
                  .rename(columns={"attempt_number": "Attempt", "total_tokens": "Total tokens"})
            )
            st.bar_chart(token_by_attempt.set_index("Attempt"))
            st.divider()

        st.markdown("**Attempt status distribution**")
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        st.bar_chart(status_counts.set_index("Status"))

        if "attempt_number" in df.columns:
            st.markdown("**Retry depth per PR** (max attempts used)")
            depth = (
                df.groupby("pr_number")["attempt_number"]
                  .max()
                  .value_counts()
                  .sort_index()
                  .reset_index()
            )
            depth.columns = ["Max attempts", "PR count"]
            st.bar_chart(depth.set_index("Max attempts"))


# ── Tab 4: Knowledge Base ─────────────────────────────────────────────────────

with tab_kb:
    st.subheader("Knowledge Base")

    @st.cache_data(ttl=60)
    def load_kb_entries():
        if not os.environ.get("KB_STORE_PATH") and not os.environ.get("FIRESTORE_PROJECT"):
            os.environ["KB_STORE_PATH"] = "./data/kb.json"
        try:
            store = make_knowledge_store()
            return store.get_all()
        except Exception:
            return []

    kb_entries = load_kb_entries()

    SOURCE_ICONS = {
        "tier1_learned":   "🟢 tier1_learned",
        "tier2_playbook":  "📖 tier2_playbook",
        "knowledge_agent": "🤖 knowledge_agent",
    }
    CONFIDENCE_ICONS = {"high": "🔵", "medium": "🟡", "low": "🔴"}

    if not kb_entries:
        st.info(
            "No KB entries yet.  \n\n"
            "Tier 2 playbook entries appear once the fixer runs (they're loaded "
            "from `playbooks/*.yaml` at startup).  \n"
            "Knowledge Agent entries are added during each fresh scan.  \n"
            "Tier 1 learned entries are added by the Watcher after a PR passes CI."
        )
    else:
        source_counts = {}
        for e in kb_entries:
            source_counts[e.source] = source_counts.get(e.source, 0) + 1

        c1, c2, c3 = st.columns(3)
        c1.metric("Tier 1 (learned)",   source_counts.get("tier1_learned", 0))
        c2.metric("Tier 2 (playbooks)", source_counts.get("tier2_playbook", 0))
        c3.metric("Knowledge Agent",    source_counts.get("knowledge_agent", 0))

        st.divider()

        source_filter = st.selectbox(
            "Filter by source",
            ["(all)"] + sorted(set(e.source for e in kb_entries)),
        )
        filtered = kb_entries if source_filter == "(all)" else [
            e for e in kb_entries if e.source == source_filter
        ]

        _tier_order = {"tier1_learned": 3, "tier2_playbook": 2, "knowledge_agent": 1}
        for entry in sorted(filtered, key=lambda e: _tier_order.get(e.source, 0), reverse=True):
            label = (
                f"{SOURCE_ICONS.get(entry.source, entry.source)}  |  "
                f"{entry.component_name}  |  "
                f"{entry.from_version or f'major {entry.from_major}'} → "
                f"{entry.to_version or f'major {entry.to_major}'}  |  "
                f"{CONFIDENCE_ICONS.get(entry.confidence, '')} {entry.confidence}"
            )
            with st.expander(label):
                c1, c2 = st.columns(2)
                c1.write(f"**Entry ID:** `{entry.entry_id[:8]}…`")
                c2.write(f"**Source:** `{entry.source}`")

                if entry.breaking_changes:
                    st.markdown("**Breaking changes:**")
                    for bc in entry.breaking_changes:
                        st.markdown(f"- {bc}")

                if entry.migration_steps:
                    st.markdown("**Migration steps:**")
                    for i, step in enumerate(entry.migration_steps, 1):
                        st.markdown(f"{i}. {step}")

                if entry.patterns:
                    st.markdown(f"**Find→replace patterns ({len(entry.patterns)}):**")
                    for p in entry.patterns:
                        col_f, col_r = st.columns(2)
                        col_f.code(p.get("find", ""), language="java")
                        col_r.code(p.get("replace", ""), language="java")
                        if p.get("description"):
                            st.caption(p["description"])

                if entry.api_removals:
                    st.markdown("**Removed APIs:**")
                    st.code("\n".join(entry.api_removals), language="text")

