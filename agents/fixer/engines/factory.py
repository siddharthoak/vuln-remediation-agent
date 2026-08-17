"""Selects a FixEngine implementation via the FIX_ENGINE env var.

Defaults to "adk" (Google ADK + Vertex AI) to preserve existing behavior --
"gemini_cli" is opt-in until it has been validated against real remediation
traffic (see the security caveats in engines/gemini_cli.py).

Imports are deferred into each branch so selecting one engine doesn't
require the other engine's dependencies (google-adk/vertexai vs. the
`gemini` CLI binary + GEMINI_API_KEY) to be present.
"""

from __future__ import annotations

import os
from typing import Optional

from engines.base import FixEngine

_VALID_ENGINES = ("adk", "gemini_cli")


def get_engine(model_deployment_name: Optional[str] = None) -> FixEngine:
    name = os.environ.get("FIX_ENGINE", "adk").strip().lower()

    if name == "adk":
        from engines.adk_vertex import AdkVertexEngine
        return AdkVertexEngine(model_name=model_deployment_name)

    if name == "gemini_cli":
        from engines.gemini_cli import GeminiCliEngine
        return GeminiCliEngine()

    raise ValueError(f"Unknown FIX_ENGINE={name!r}. Expected one of {_VALID_ENGINES}.")
