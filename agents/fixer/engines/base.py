"""FixEngine protocol -- the pluggable LLM-backend contract for CodeFixer.

Lets CodeFixer swap its model-calling implementation (ADK/Vertex today,
others later, selected via FIX_ENGINE) without touching pom.xml handling,
tracking-store, or retry-gate logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Protocol


@dataclass
class FixResult:
    rationale: str
    files_changed: List[str] = field(default_factory=list)
    # None (not 0) when an engine can't reliably report token counts --
    # e.g. a CLI-based engine whose usage envelope isn't a stable contract.
    # 0 would misrepresent that as a confirmed zero-cost run.
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None


class EngineExecutionError(Exception):
    """Raised when the engine itself fails to run (crash, timeout, malformed
    output) -- distinct from the engine running successfully but producing a
    fix that later fails CI. Callers must not count this against a tracking
    record's retry budget.
    """


class FixEngine(Protocol):
    """Runs one fix attempt against a cloned repo and returns a FixResult.

    Implementations own their own tool loop and must leave the working tree
    in its final edited state -- CodeFixer only verifies compilation and
    prepends pom.xml to files_changed; it never re-derives what changed.
    """

    def run_fix(self, repo_path: Path, prompt: str) -> FixResult: ...
