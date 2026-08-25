"""
Knowledge Store — persists KB entries for (component, from_version, to_version) tuples.

Three tiers, all stored in the same backend:
  tier2_playbook    — loaded at startup from playbooks/*.yaml (engineer-authored)
  knowledge_agent   — written by the Knowledge Agent from web-fetched release notes
  tier1_learned     — written by the Watcher after a CI_PASSED fix is confirmed

Lookup priority: tier1_learned > tier2_playbook > knowledge_agent

Backends:
  FileKnowledgeStore   — ./data/kb.json (local Docker / dev)
  FirestoreKBStore     — GCP Firestore (production)
  InMemoryKBStore      — unit tests only
"""

import json
import logging
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

import yaml

logger = logging.getLogger(__name__)

PLAYBOOKS_DIR = Path(__file__).parent.parent.parent / "playbooks"
_FIRESTORE_COLLECTION = "oss-remediation-kb"
TIER_PRIORITY = {"tier1_learned": 3, "tier2_playbook": 2, "knowledge_agent": 1}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class KnowledgeEntry:
    entry_id: str
    component_name: str
    from_version: str           # exact from-version, or "" for major-version playbooks
    to_version: str             # exact to-version, or "" for major-version playbooks
    from_major: int             # parsed major version of from_version
    to_major: int               # parsed major version of to_version
    source: str                 # tier1_learned | tier2_playbook | knowledge_agent
    breaking_changes: list = field(default_factory=list)
    api_removals: list = field(default_factory=list)
    migration_steps: list = field(default_factory=list)
    patterns: list = field(default_factory=list)  # [{"find":"","replace":"","description":""}]
    confidence: str = "medium"  # high | medium | low
    created_at: str = ""


# ── Protocol ──────────────────────────────────────────────────────────────────

@runtime_checkable
class KnowledgeStoreProtocol(Protocol):
    def create(self, entry: KnowledgeEntry) -> None: ...
    def get(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]: ...
    def find_applicable(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]: ...
    def update(self, entry: KnowledgeEntry) -> None: ...
    def get_all(self) -> list: ...


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_major(version: str) -> int:
    try:
        return int(version.split(".")[0])
    except (ValueError, IndexError, AttributeError):
        return -1


def _component_stem(component_name: str) -> str:
    """Return just the artifactId part of a groupId:artifactId component name."""
    return component_name.split(":")[-1].lower()


def _load_playbooks() -> list:
    """Load all Tier 2 YAML playbooks from the playbooks/ directory into KnowledgeEntry objects."""
    entries = []
    if not PLAYBOOKS_DIR.exists():
        return entries
    for path in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            entry = KnowledgeEntry(
                entry_id=f"playbook:{path.stem}",
                component_name=data["component"],
                from_version="",
                to_version="",
                from_major=int(data.get("from_major", -1)),
                to_major=int(data.get("to_major", -1)),
                source="tier2_playbook",
                breaking_changes=data.get("breaking_changes", []),
                api_removals=data.get("api_removals", []),
                migration_steps=data.get("migration_steps", []),
                patterns=data.get("patterns", []),
                confidence=data.get("confidence", "high"),
                created_at=_now(),
            )
            entries.append(entry)
            logger.debug("Loaded playbook: %s", path.name)
        except Exception as exc:
            logger.warning("Could not load playbook %s: %s", path.name, exc)
    return entries


# ── In-memory backend ─────────────────────────────────────────────────────────

class InMemoryKBStore:
    def __init__(self):
        self._entries: dict = {}
        for e in _load_playbooks():
            self._entries[e.entry_id] = e

    def create(self, entry: KnowledgeEntry) -> None:
        self._entries[entry.entry_id] = entry

    def get(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]:
        for e in self._entries.values():
            if (e.component_name == component_name
                    and e.from_version == from_version
                    and e.to_version == to_version):
                return e
        return None

    def find_applicable(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]:
        return _find_best(list(self._entries.values()), component_name, from_version, to_version)

    def update(self, entry: KnowledgeEntry) -> None:
        self._entries[entry.entry_id] = entry

    def get_all(self) -> list:
        return list(self._entries.values())


# ── File backend ──────────────────────────────────────────────────────────────

class FileKnowledgeStore:
    """
    JSON file backend at KB_STORE_PATH (defaults to ./data/kb.json).
    Playbooks are merged at load time and win over file entries of the same tier.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = Path(path or os.environ.get("KB_STORE_PATH", "./data/kb.json"))

    def _load(self) -> dict:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {e["entry_id"]: KnowledgeEntry(**e) for e in data.get("entries", [])}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save(self, entries: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({"entries": [asdict(e) for e in entries.values()]}, indent=2),
            encoding="utf-8",
        )

    def _all_entries(self) -> dict:
        entries = self._load()
        for pb in _load_playbooks():
            entries.setdefault(pb.entry_id, pb)
        return entries

    def create(self, entry: KnowledgeEntry) -> None:
        if not entry.entry_id:
            entry.entry_id = str(uuid.uuid4())
        if not entry.created_at:
            entry.created_at = _now()
        entries = self._load()
        entries[entry.entry_id] = entry
        self._save(entries)
        logger.info("KB: created entry %s (%s)", entry.entry_id[:8], entry.component_name)

    def get(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]:
        for e in self._all_entries().values():
            if (e.component_name == component_name
                    and e.from_version == from_version
                    and e.to_version == to_version):
                return e
        return None

    def find_applicable(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]:
        return _find_best(list(self._all_entries().values()), component_name, from_version, to_version)

    def update(self, entry: KnowledgeEntry) -> None:
        entries = self._load()
        entries[entry.entry_id] = entry
        self._save(entries)

    def get_all(self) -> list:
        return list(self._all_entries().values())


# ── Firestore backend ─────────────────────────────────────────────────────────

class FirestoreKBStore:
    def __init__(self, project: Optional[str] = None):
        from google.cloud import firestore as fs
        project_id = project or os.environ["FIRESTORE_PROJECT"]
        self._db  = fs.Client(project=project_id)
        self._col = self._db.collection(_FIRESTORE_COLLECTION)

    def create(self, entry: KnowledgeEntry) -> None:
        if not entry.entry_id:
            entry.entry_id = str(uuid.uuid4())
        if not entry.created_at:
            entry.created_at = _now()
        self._col.document(entry.entry_id).set(asdict(entry))

    def get(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]:
        docs = list(
            self._col
            .where("component_name", "==", component_name)
            .where("from_version", "==", from_version)
            .where("to_version", "==", to_version)
            .limit(1)
            .stream()
        )
        return KnowledgeEntry(**docs[0].to_dict()) if docs else None

    def find_applicable(self, component_name: str, from_version: str, to_version: str) -> Optional[KnowledgeEntry]:
        docs = list(self._col.where("component_name", "==", component_name).stream())
        candidates = [KnowledgeEntry(**d.to_dict()) for d in docs]
        candidates.extend(_load_playbooks())
        return _find_best(candidates, component_name, from_version, to_version)

    def update(self, entry: KnowledgeEntry) -> None:
        self._col.document(entry.entry_id).set(asdict(entry))

    def get_all(self) -> list:
        entries = [KnowledgeEntry(**d.to_dict()) for d in self._col.stream()]
        for pb in _load_playbooks():
            if not any(e.entry_id == pb.entry_id for e in entries):
                entries.append(pb)
        return entries


# ── Lookup logic ──────────────────────────────────────────────────────────────

def _find_best(
    candidates: list,
    component_name: str,
    from_version: str,
    to_version: str,
) -> Optional[KnowledgeEntry]:
    """
    Priority:
      1. Exact (component_name, from_version, to_version) — highest specificity
      2. Same component_name, matching major-version range (playbooks / agent entries)
      3. Component stem match on major-version range (e.g. "spring-boot" ≈ "spring-boot-starter")

    Within each tier, tier1_learned > tier2_playbook > knowledge_agent.
    """
    from_major = _parse_major(from_version)
    to_major   = _parse_major(to_version)
    stem       = _component_stem(component_name)

    def score(e: KnowledgeEntry) -> int:
        tier = TIER_PRIORITY.get(e.source, 0)

        # Exact match
        if (e.component_name == component_name
                and e.from_version == from_version
                and e.to_version == to_version):
            return 1000 + tier

        # Same component + matching major range
        if (e.component_name == component_name
                and (e.from_major == -1 or e.from_major == from_major)
                and (e.to_major == -1 or e.to_major == to_major)):
            return 100 + tier

        # Stem match + major range (for e.g. "spring-boot-starter-web" matching "spring-boot")
        entry_stem = _component_stem(e.component_name)
        stems_match = stem.startswith(entry_stem) or entry_stem.startswith(stem)
        majors_match = (
            (e.from_major == -1 or e.from_major == from_major)
            and (e.to_major == -1 or e.to_major == to_major)
        )
        if stems_match and majors_match:
            return 10 + tier

        return 0

    scored = [(score(e), e) for e in candidates if score(e) > 0]
    if not scored:
        return None
    return max(scored, key=lambda x: x[0])[1]


# ── Factory ───────────────────────────────────────────────────────────────────

def make_knowledge_store():
    if os.environ.get("FIRESTORE_PROJECT"):
        return FirestoreKBStore()
    logger.info(
        "Using FileKnowledgeStore at %s",
        os.environ.get("KB_STORE_PATH", "./data/kb.json"),
    )
    return FileKnowledgeStore()
