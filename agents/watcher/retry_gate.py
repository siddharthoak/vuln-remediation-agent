"""
Watcher retry gate — migrated from nexus-remediation-agent.

What changed:
  - AafFixerInvoker (azure.ai.projects) → AdkFixerInvoker (google-cloud-run v2)
  - make_fixer_invoker() checks GOOGLE_CLOUD_PROJECT instead of FIXER_AGENT_ID

What is UNCHANGED (verbatim):
  - RetryGate class and all its methods
  - HttpFixerInvoker (local dev)
  - make_retry_record() call pattern
  - Retry bound enforcement logic
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from common.tracking_store import TrackingStatus, make_retry_record

logger = logging.getLogger(__name__)


class RetryGate:
    """
    The Watcher's sole decision-making component for CI failures.
    Reads/writes the tracking store and invokes the Fixer — nothing else.
    UNCHANGED from nexus-remediation-agent.
    """

    def __init__(
        self,
        tracking_store,
        pr_client,
        fixer_invoker,
        max_retry_attempts: Optional[int] = None,
    ):
        self._store = tracking_store
        self._pr_client = pr_client
        self._invoker = fixer_invoker
        self._max_attempts = max_retry_attempts or int(os.environ.get("MAX_RETRY_ATTEMPTS", "3"))

    def process_ci_failure(self, ci_result, current_tracking_record) -> None:
        pr_number = current_tracking_record.pr_number
        if pr_number is None:
            logger.error(
                "Tracking record %s has no pr_number — cannot process CI failure.",
                current_tracking_record.tracking_id[:8],
            )
            return

        terminal_statuses = {
            TrackingStatus.FAILED_MAX_RETRIES.value,
            TrackingStatus.ESCALATED.value,
        }
        if current_tracking_record.status in terminal_statuses:
            logger.error(
                "PR #%d: tracking record already has terminal status=%s. "
                "Refusing to create any further retry requests.",
                pr_number, current_tracking_record.status,
            )
            return

        attempt_count = self._store.count_attempts_for_pr(pr_number)
        logger.info(
            "PR #%d: CI failed. Attempt %d/%d completed.",
            pr_number, attempt_count, self._max_attempts,
        )

        if attempt_count >= self._max_attempts:
            self._handle_limit_reached(pr_number, current_tracking_record, ci_result)
            return

        failure_excerpt = ci_result.failure_log_text
        if not failure_excerpt:
            logger.warning(
                "PR #%d: CI result has no failure log text. "
                "Retry will have reduced context.", pr_number
            )

        retry_record = make_retry_record(
            parent=current_tracking_record,
            failure_log_excerpt=failure_excerpt,
        )
        self._store.create(retry_record)
        logger.info(
            "PR #%d: created RETRY_REQUESTED record %s (attempt %d/%d).",
            pr_number, retry_record.tracking_id[:8],
            retry_record.attempt_number, self._max_attempts,
        )

        try:
            self._invoker.trigger_retry(retry_record.tracking_id)
            logger.info(
                "PR #%d: Fixer invoked with tracking_id=%s.",
                pr_number, retry_record.tracking_id[:8],
            )
        except Exception as exc:
            logger.error(
                "PR #%d: Failed to invoke Fixer: %s. Marking as ESCALATED.", pr_number, exc
            )
            retry_record.status = TrackingStatus.ESCALATED.value
            self._store.update(retry_record)
            self._post_escalation_comment(
                pr_number,
                f"The Watcher agent could not invoke the Fixer for retry "
                f"(tracking={retry_record.tracking_id[:8]}): {exc}\n\n"
                "Human intervention required."
            )

    def _handle_limit_reached(self, pr_number: int, record, ci_result) -> None:
        logger.warning(
            "PR #%d: MAX_RETRY_ATTEMPTS=%d reached. Stopping all automatic retries.",
            pr_number, self._max_attempts,
        )
        try:
            created_dt = datetime.fromisoformat(record.created_at)
            now = datetime.now(timezone.utc)
            resolution_seconds = (now - created_dt).total_seconds()
        except Exception:
            resolution_seconds = None

        record.status = TrackingStatus.FAILED_MAX_RETRIES.value
        record.time_to_resolution_seconds = resolution_seconds
        self._store.update(record)

        self._post_escalation_comment(
            pr_number,
            f"## OSS Remediation Agent — Retry Limit Reached\n\n"
            f"This PR has exhausted all **{self._max_attempts}** automatic fix attempts. "
            f"No further automatic fixes will be applied.\n\n"
            f"**Latest CI failure:**\n```\n{ci_result.failure_log_text[:1000]}\n```\n\n"
            "Please investigate the CI failure and apply a manual fix before merging."
        )

    def _post_escalation_comment(self, pr_number: int, comment: str) -> None:
        try:
            self._pr_client.add_comment(pr_number, comment)
        except Exception as exc:
            logger.error(
                "Could not post escalation comment on PR #%d: %s", pr_number, exc
            )


# ── Fixer invokers ────────────────────────────────────────────────────────────

class AdkFixerInvoker:
    """
    Triggers a new Fixer agent run by executing a Google Cloud Run Job
    with RETRY_TRACKING_ID set as an environment override.

    Replaces AafFixerInvoker from nexus-remediation-agent which used
    azure.ai.projects.AIProjectClient.agents.create_run().
    """

    def __init__(
        self,
        job_name: Optional[str] = None,
        project: Optional[str] = None,
        region: Optional[str] = None,
    ):
        self._job_name = job_name or os.environ["FIXER_JOB_NAME"]
        self._project  = project  or os.environ["GOOGLE_CLOUD_PROJECT"]
        self._region   = region   or os.environ.get("CLOUD_RUN_REGION", "us-central1")

    def trigger_retry(self, tracking_id: str) -> None:
        from google.cloud import run_v2

        client   = run_v2.JobsClient()
        job_name = (
            f"projects/{self._project}"
            f"/locations/{self._region}"
            f"/jobs/{self._job_name}"
        )

        request = run_v2.RunJobRequest(
            name=job_name,
            overrides=run_v2.RunJobRequest.Overrides(
                container_overrides=[
                    run_v2.RunJobRequest.Overrides.ContainerOverride(
                        env=[run_v2.EnvVar(name="RETRY_TRACKING_ID", value=tracking_id)]
                    )
                ]
            ),
        )

        client.run_job(request=request)
        logger.info(
            "GCP: triggered Cloud Run Job %s with RETRY_TRACKING_ID=%s",
            self._job_name, tracking_id[:8],
        )


class HttpFixerInvoker:
    """
    Local development invoker — POSTs to the Fixer's HTTP endpoint.
    Unchanged from nexus-remediation-agent.
    """

    def __init__(self, fixer_retry_url: Optional[str] = None):
        self._url = fixer_retry_url or os.environ["FIXER_RETRY_URL"]

    def trigger_retry(self, tracking_id: str) -> None:
        import requests
        resp = requests.post(
            self._url,
            json={"tracking_id": tracking_id},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info(
            "HTTP: triggered Fixer retry at %s for tracking_id=%s",
            self._url, tracking_id[:8],
        )


def make_fixer_invoker():
    """Return the appropriate invoker based on environment."""
    if os.environ.get("FIXER_RETRY_URL"):
        return HttpFixerInvoker()
    return AdkFixerInvoker()
