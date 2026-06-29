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
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agents"))

from common.tracking_store import make_tracking_store, TrackingStatus  # noqa: E402


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
    df["created_at"] = pd.to_datetime(df["created_at"], utc=True)
    df["updated_at"]  = pd.to_datetime(df["updated_at"],  utc=True)

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

if df.empty:
    st.info(
        "No tracking records yet.  \n\n"
        "Start the agents with `docker compose up -d`, trigger the security scan on your "
        "target repo, and records will appear here once the fixer picks up the reports.  \n\n"
        f"Reading from: `{os.environ.get('TRACKING_STORE_PATH', './data/tracking.json')}`"
    )
    st.stop()

with col_count:
    st.caption(f"{len(df)} total record(s) across {df['pr_number'].nunique()} PR(s)")


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_history, tab_lineage, tab_metrics = st.tabs([
    "Run History",
    "Retry Lineage",
    "Metrics",
])


# ── Tab 1: Run History ────────────────────────────────────────────────────────

with tab_history:
    st.subheader("All Fix Attempts")

    col_status, col_component, col_repo = st.columns(3)

    with col_status:
        statuses = ["(all)"] + sorted(df["status"].dropna().unique().tolist())
        status_filter = st.selectbox("Status", statuses)

    with col_component:
        components = ["(all)"] + sorted(df["component_name"].dropna().unique().tolist())
        component_filter = st.selectbox("Component", components)

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

    pr_numbers = sorted(df["pr_number"].dropna().astype(int).unique().tolist())
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
                f"({row['created_at'].strftime('%Y-%m-%d %H:%M UTC')})"
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
    m1.metric("PRs opened",       total_prs)
    m2.metric("Resolved ✅",       resolved,    help="Status = CI_PASSED")
    m3.metric("In progress ⏳",    in_progress)
    m4.metric("Escalated ⛔",      escalated,   help="FAILED_MAX_RETRIES or ESCALATED")
    m5.metric("Resolution rate",  f"{resolution_rate:.1f}%")

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
