"""
Shared tracking store — GCP version.

Migrated from nexus-remediation-agent/agents/common/tracking_store.py.

What changed:
  - CosmosTrackingStore removed (Azure-only)
  - FirestoreTrackingStore added (google-cloud-firestore, ADC)
  - make_tracking_store() checks FIRESTORE_PROJECT instead of COSMOS_ENDPOINT

What is UNCHANGED (verbatim):
  - TrackingRecord dataclass and all fields
  - TrackingStatus enum and full state machine
  - make_fresh_record() and make_retry_record() factory functions
  - InMemoryTrackingStore (explicit testing backend)
  - TrackingStoreProtocol
"""

import json
import logging
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ── Status enum (UNCHANGED) ───────────────────────────────────────────────────

class TrackingStatus(str, Enum):
    CREATED              = "CREATED"
    PR_OPENED            = "PR_OPENED"
    CI_PENDING           = "CI_PENDING"
    CI_PASSED            = "CI_PASSED"
    CI_FAILED            = "CI_FAILED"
    RETRY_REQUESTED      = "RETRY_REQUESTED"
    FAILED_MAX_RETRIES   = "FAILED_MAX_RETRIES"
    ESCALATED            = "ESCALATED"
    # The FixEngine itself failed to run (CLI crash/timeout/missing binary --
    # see engines.base.EngineExecutionError) -- distinct from a fix attempt
    # that ran and produced bad code (that's still CI_FAILED -> RETRY_REQUESTED).
    # Terminal, like ESCALATED: needs human attention, not an automatic retry.
    ENGINE_ERROR         = "ENGINE_ERROR"


# ── Data model (UNCHANGED) ────────────────────────────────────────────────────

@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class TrackingRecord:
    tracking_id: str
    vulnerability_id: str
    repo: str
    component_name: str
    old_version: str
    new_version: str
    status: str
    created_at: str
    updated_at: str

    parent_tracking_id: Optional[str] = None
    pr_number: Optional[int] = None
    branch_name: str = ""
    attempt_number: int = 1

    time_to_resolution_seconds: Optional[float] = None
    token_usage: Optional[dict] = None
    failure_log_excerpt: Optional[str] = None

    # Phase 2 — Classifier output (Optional for backward compat with existing records)
    kb_bucket: Optional[int] = None      # 1=no-fix 2=patch/minor 3=major+KB 4=complex
    kb_entry_id: Optional[str] = None    # KnowledgeEntry.entry_id used for this fix
    classifier_rationale: Optional[str] = None  # Classifier.classify()'s per-finding "why this bucket" explanation

    # Transitive & Multi-repo chain tracking
    is_transitive: bool = False
    introduced_by: Optional[str] = None
    transitive_depth: Optional[int] = None
    chain_step: Optional[int] = None
    chain_total: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> "TrackingRecord":
        import dataclasses
        valid_fields = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


# ── Protocol (UNCHANGED) ──────────────────────────────────────────────────────

@runtime_checkable
class TrackingStoreProtocol(Protocol):
    def create(self, record: TrackingRecord) -> None: ...
    def get(self, tracking_id: str) -> Optional[TrackingRecord]: ...
    def get_latest_for_pr(self, pr_number: int) -> Optional[TrackingRecord]: ...
    def get_lineage(self, pr_number: int) -> list: ...
    def get_all(self) -> list: ...
    def count_attempts_for_pr(self, pr_number: int) -> int: ...
    def update(self, record: TrackingRecord) -> None: ...


# ── Factory helpers (UNCHANGED) ───────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_tracking_id() -> str:
    return str(uuid.uuid4())


def make_fresh_record(
    vulnerability_id: str,
    repo: str,
    component_name: str,
    old_version: str,
    new_version: str,
    is_transitive: bool = False,
    introduced_by: Optional[str] = None,
    transitive_depth: Optional[int] = None,
    chain_step: Optional[int] = None,
    chain_total: Optional[int] = None,
) -> TrackingRecord:
    now = _now()
    return TrackingRecord(
        tracking_id=new_tracking_id(),
        vulnerability_id=vulnerability_id,
        repo=repo,
        component_name=component_name,
        old_version=old_version,
        new_version=new_version,
        status=TrackingStatus.CREATED.value,
        created_at=now,
        updated_at=now,
        parent_tracking_id=None,
        attempt_number=1,
        is_transitive=is_transitive,
        introduced_by=introduced_by,
        transitive_depth=transitive_depth,
        chain_step=chain_step,
        chain_total=chain_total,
    )


def make_retry_record(parent: TrackingRecord, failure_log_excerpt: str) -> TrackingRecord:
    now = _now()
    return TrackingRecord(
        tracking_id=new_tracking_id(),
        vulnerability_id=parent.vulnerability_id,
        repo=parent.repo,
        component_name=parent.component_name,
        old_version=parent.old_version,
        new_version=parent.new_version,
        status=TrackingStatus.RETRY_REQUESTED.value,
        created_at=now,
        updated_at=now,
        parent_tracking_id=parent.tracking_id,
        pr_number=parent.pr_number,
        branch_name=parent.branch_name,
        attempt_number=parent.attempt_number + 1,
        failure_log_excerpt=failure_log_excerpt[:4000] if failure_log_excerpt else None,
        kb_bucket=parent.kb_bucket,
        kb_entry_id=parent.kb_entry_id,
        classifier_rationale=parent.classifier_rationale,
        is_transitive=parent.is_transitive,
        introduced_by=parent.introduced_by,
        transitive_depth=parent.transitive_depth,
        chain_step=parent.chain_step,
        chain_total=parent.chain_total,
    )


# ── In-memory backend (UNCHANGED) ─────────────────────────────────────────────

class InMemoryTrackingStore:
    """Testing backend — no external dependencies. Not safe across container restarts."""

    def __init__(self):
        self._records: dict = {}

    def create(self, record: TrackingRecord) -> None:
        self._records[record.tracking_id] = record

    def get(self, tracking_id: str) -> Optional[TrackingRecord]:
        return self._records.get(tracking_id)

    def get_latest_for_pr(self, pr_number: int) -> Optional[TrackingRecord]:
        matches = [r for r in self._records.values() if r.pr_number == pr_number]
        if not matches:
            return None
        return sorted(matches, key=lambda r: r.attempt_number, reverse=True)[0]

    def get_all_for_pr(self, pr_number: int) -> list:
        return [r for r in self._records.values() if r.pr_number == pr_number]


    def get_lineage(self, pr_number: int) -> list:
        matches = [r for r in self._records.values() if r.pr_number == pr_number]
        return sorted(matches, key=lambda r: r.attempt_number)

    def get_all(self) -> list:
        return list(self._records.values())

    def count_attempts_for_pr(self, pr_number: int) -> int:
        attempts = [r.attempt_number for r in self._records.values() if r.pr_number == pr_number and r.status != TrackingStatus.ENGINE_ERROR.value]
        return max(attempts) if attempts else 0

    def update(self, record: TrackingRecord) -> None:
        record.updated_at = _now()
        self._records[record.tracking_id] = record

    def all_with_status(self, status: str) -> list:
        return [r for r in self._records.values() if r.status == status]


# ── Firestore backend (production / GCP) ──────────────────────────────────────

_FIRESTORE_COLLECTION = "oss-remediation-tracking"


class FirestoreTrackingStore:
    """
    Production backend backed by Google Cloud Firestore (Native mode).
    Uses Application Default Credentials — no key files needed when running
    on Cloud Run with a service account that has Firestore access.

    Document ID = tracking_id (UUID)
    Collection  = oss-remediation-tracking

    Replaces CosmosTrackingStore from nexus-remediation-agent.
    The TrackingStoreProtocol interface is identical.
    """

    def __init__(self, project: Optional[str] = None):
        from google.cloud import firestore as fs
        project_id = project or os.environ["FIRESTORE_PROJECT"]
        self._db  = fs.Client(project=project_id)
        self._col = self._db.collection(_FIRESTORE_COLLECTION)

    def create(self, record: TrackingRecord) -> None:
        self._col.document(record.tracking_id).set(asdict(record))
        logger.debug(
            "FirestoreStore: created %s status=%s",
            record.tracking_id[:8], record.status,
        )

    def get(self, tracking_id: str) -> Optional[TrackingRecord]:
        doc = self._col.document(tracking_id).get()
        if not doc.exists:
            return None
        return TrackingRecord.from_dict(doc.to_dict())

    def get_latest_for_pr(self, pr_number: int) -> Optional[TrackingRecord]:
        from google.cloud.firestore_v1 import Query
        docs = list(
            self._col
            .where("pr_number", "==", pr_number)
            .order_by("attempt_number", direction=Query.DESCENDING)
            .limit(1)
            .stream()
        )
        return TrackingRecord.from_dict(docs[0].to_dict()) if docs else None

    def get_all_for_pr(self, pr_number: int) -> list:
        docs = self._col.where("pr_number", "==", pr_number).stream()
        return [TrackingRecord.from_dict(d.to_dict()) for d in docs]


    def get_lineage(self, pr_number: int) -> list:
        docs = list(
            self._col
            .where("pr_number", "==", pr_number)
            .order_by("attempt_number")
            .stream()
        )
        return [TrackingRecord.from_dict(d.to_dict()) for d in docs]

    def get_all(self) -> list:
        return [TrackingRecord.from_dict(d.to_dict()) for d in self._col.stream()]

    def count_attempts_for_pr(self, pr_number: int) -> int:
        docs = self._col.where("pr_number", "==", pr_number).stream()
        attempts = [d.to_dict().get("attempt_number", 1) for d in docs if d.to_dict().get("status") != TrackingStatus.ENGINE_ERROR.value]
        return max(attempts) if attempts else 0

    def update(self, record: TrackingRecord) -> None:
        record.updated_at = _now()
        self._col.document(record.tracking_id).set(asdict(record))


# ── File-based backend (local Docker / dev) ───────────────────────────────────

from .file_lock import FileLock

class FileTrackingStore:
    """
    JSON file backend for local development and Docker Compose runs.

    All records are stored in a single JSON file on a mounted volume so state
    survives container restarts. Safe for concurrent writes using a file lock.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path or os.environ["TRACKING_STORE_PATH"]
        self._lock_path = self._path + ".lock"

    def _load(self) -> dict:
        import time
        for attempt in range(3):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except FileNotFoundError:
                return {}
            except json.JSONDecodeError:
                if attempt < 2:
                    time.sleep(0.05)
                    continue
                return {}
        return {}

    def _save(self, records: dict) -> None:
        import time
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        temp_path = f"{self._path}.tmp.{os.getpid()}_{uuid.uuid4().hex[:8]}"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        try:
            os.replace(temp_path, self._path)
        except OSError:
            time.sleep(0.05)
            os.replace(temp_path, self._path)

    def create(self, record: TrackingRecord) -> None:
        with FileLock(self._lock_path):
            records = self._load()
            records[record.tracking_id] = asdict(record)
            self._save(records)

    def get(self, tracking_id: str) -> Optional[TrackingRecord]:
        with FileLock(self._lock_path):
            records = self._load()
            data = records.get(tracking_id)
            return TrackingRecord.from_dict(data) if data else None

    def get_latest_for_pr(self, pr_number: int) -> Optional[TrackingRecord]:
        with FileLock(self._lock_path):
            matches = [
                TrackingRecord.from_dict(v) for v in self._load().values()
                if v.get("pr_number") == pr_number
            ]
            if not matches:
                return None
            return sorted(matches, key=lambda r: r.attempt_number, reverse=True)[0]

    def get_all_for_pr(self, pr_number: int) -> list:
        with FileLock(self._lock_path):
            return [
                TrackingRecord.from_dict(v) for v in self._load().values()
                if v.get("pr_number") == pr_number
            ]


    def get_lineage(self, pr_number: int) -> list:
        with FileLock(self._lock_path):
            matches = [
                TrackingRecord.from_dict(v) for v in self._load().values()
                if v.get("pr_number") == pr_number
            ]
            return sorted(matches, key=lambda r: r.attempt_number)

    def get_all(self) -> list:
        with FileLock(self._lock_path):
            return [TrackingRecord.from_dict(v) for v in self._load().values()]

    def count_attempts_for_pr(self, pr_number: int) -> int:
        with FileLock(self._lock_path):
            attempts = [v.get("attempt_number", 1) for v in self._load().values() if v.get("pr_number") == pr_number and v.get("status") != TrackingStatus.ENGINE_ERROR.value]
            return max(attempts) if attempts else 0

    def update(self, record: TrackingRecord) -> None:
        record.updated_at = _now()
        with FileLock(self._lock_path):
            records = self._load()
            records[record.tracking_id] = asdict(record)
            self._save(records)


# ── Store factory ─────────────────────────────────────────────────────────────

def make_tracking_store():
    """
    Return the appropriate store based on environment.

    FIRESTORE_PROJECT set    → FirestoreTrackingStore  (production GCP)
    TRACKING_STORE_PATH set  → FileTrackingStore       (local Docker / dev)
    TRACKING_STORE_BACKEND=memory → InMemoryTrackingStore (explicit tests)
    Neither set              → FileTrackingStore       (local project default)

    The local default must be persistent: the dashboard is a separate process
    and reads the same data file after a one-shot fixer run.
    """
    if os.environ.get("FIRESTORE_PROJECT"):
        return FirestoreTrackingStore()
    if os.environ.get("TRACKING_STORE_BACKEND", "").lower() == "memory":
        logger.info("Using InMemoryTrackingStore (explicitly requested).")
        return InMemoryTrackingStore()

    default_path = Path(__file__).resolve().parents[2] / "data" / "tracking.json"
    path = os.environ.get("TRACKING_STORE_PATH") or str(default_path)
    logger.info("Using FileTrackingStore at %s", path)
    return FileTrackingStore(path)
