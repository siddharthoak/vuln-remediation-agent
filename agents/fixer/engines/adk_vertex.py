"""FixEngine backed by Google ADK + Vertex AI.

Extracted from code_fixer.py verbatim -- this is the CodeFixer's original
model-calling logic (ADK Agent + FunctionTool + Runner), unchanged in
behavior, moved behind the FixEngine protocol so it can be selected
alongside other engines via FIX_ENGINE.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import vertexai
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools import FunctionTool
from google.genai import types as genai_types

from ecosystems.maven import compile_repo
from engines.base import FixResult

logger = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 10  # Passed to ADK Runner as max_llm_calls to guard runaway loops


class CodeFixerError(Exception):
    """Raised when the model response cannot be parsed into the expected format."""


class AdkVertexEngine:
    """Runs a fix prompt through an ADK Agent on Vertex AI (Gemini), giving
    it four local FunctionTools (read/grep/apply_change/compile) to edit the
    cloned repo in place.
    """

    def __init__(self, model_name: Optional[str] = None):
        self._model_name = model_name or os.environ.get("VERTEX_MODEL", "gemini-2.5-flash")

        # Initialise Vertex AI -- region from env, project from ADC
        vertexai.init(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=os.environ.get("VERTEX_LOCATION", "us-central1"),
        )

    def run_fix(self, repo_path: Path, prompt: str) -> FixResult:
        self._repo_path = repo_path
        self._applied_changes: list = []

        # ADK derives tool names from func.__name__. Instance methods have names
        # like "_tool_grep_files" but the prompt tells the LLM to call "grep_files".
        # Wrap each handler in a local function whose __name__ matches the prompt.
        def read_file(relative_path: str) -> str:
            """Read the full contents of a file in the cloned repository."""
            return self._tool_read_file(relative_path)

        def grep_files(pattern: str, extensions: Optional[list] = None) -> str:
            """Search for a regex pattern across repository source files."""
            return self._tool_grep_files(pattern, extensions)

        def apply_file_change(
            relative_path: str, find: str, replace: str, change_description: str = ""
        ) -> str:
            """Apply a single find→replace edit to a file in the cloned repository."""
            return self._tool_apply_file_change(relative_path, find, replace, change_description)

        def run_maven_compile() -> str:
            """Compile the repository with 'mvn compile -q'. No tests are executed."""
            return self._tool_run_maven_compile()

        tools = [
            FunctionTool(func=read_file),
            FunctionTool(func=grep_files),
            FunctionTool(func=apply_file_change),
            FunctionTool(func=run_maven_compile),
        ]

        agent = Agent(
            name="code_fixer",
            model=self._model_name,
            instruction=prompt,
            tools=tools,
        )

        reasoning, prompt_tokens, completion_tokens = asyncio.run(self._run_agent_async(agent))
        return FixResult(
            rationale=reasoning.get("rationale", ""),
            files_changed=list(dict.fromkeys(self._applied_changes)),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    async def _run_agent_async(self, agent: Agent) -> tuple:
        """Async runner for the ADK agent. Called via asyncio.run() from run_fix."""
        session_service = InMemorySessionService()
        runner = Runner(
            agent=agent,
            app_name="vuln-code-fixer",
            session_service=session_service,
        )

        session = await session_service.create_session(
            app_name="vuln-code-fixer",
            user_id="fixer",
        )

        trigger = genai_types.Content(
            role="user",
            parts=[genai_types.Part(text="Execute the fix based on your instructions.")],
        )

        final_text = ""
        total_prompt_tokens = 0
        total_completion_tokens = 0

        async for event in runner.run_async(
            user_id="fixer",
            session_id=session.id,
            new_message=trigger,
        ):
            if event.is_final_response() and event.content:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text:
                        final_text += part.text

            usage = getattr(event, "usage_metadata", None)
            if usage:
                total_prompt_tokens     += getattr(usage, "prompt_token_count",     0) or 0
                total_completion_tokens += getattr(usage, "candidates_token_count", 0) or 0

        json_match = re.search(r"```json\s*(.*?)\s*```", final_text, re.DOTALL)
        json_str = json_match.group(1) if json_match else final_text.strip()
        try:
            reasoning = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise CodeFixerError(
                f"Model response could not be parsed as JSON: {exc}\n\nRaw:\n{final_text}"
            ) from exc

        return reasoning, total_prompt_tokens, total_completion_tokens

    # ── Tool handlers (verbatim from code_fixer.py) ────────────────────────

    def _tool_read_file(self, relative_path: str) -> str:
        """Read the full contents of a file in the cloned repository."""
        if not relative_path:
            return "ERROR: relative_path is required."
        target = self._repo_path / relative_path
        if not target.exists():
            return f"ERROR: File not found: {relative_path}"
        try:
            content = target.read_text(encoding="utf-8")
            if len(content) > 50_000:
                content = content[:50_000] + "\n... [truncated at 50 000 chars]"
            return content
        except Exception as exc:
            return f"ERROR reading {relative_path}: {exc}"

    def _tool_grep_files(self, pattern: str, extensions: Optional[list] = None) -> str:
        """Search for a regex pattern across repository source files."""
        if not pattern:
            return "ERROR: pattern is required."
        exts = set(extensions) if extensions else {".java", ".xml", ".properties", ".yml", ".yaml"}
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            return f"ERROR: invalid regex {pattern!r}: {exc}"

        results = []
        for f in sorted(self._repo_path.rglob("*")):
            if "target" in f.parts or f.suffix not in exts:
                continue
            try:
                lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
                matches = [
                    f"  {i + 1}: {line.rstrip()}"
                    for i, line in enumerate(lines)
                    if compiled.search(line)
                ]
                if matches:
                    rel = str(f.relative_to(self._repo_path))
                    results.append(f"{rel}:\n" + "\n".join(matches[:15]))
            except Exception:
                pass

        if not results:
            return "No matches found."
        return "\n\n".join(results[:30])

    def _tool_apply_file_change(
        self,
        relative_path: str,
        find: str,
        replace: str,
        change_description: str = "",
    ) -> str:
        """
        Apply a single find→replace edit to a file in the cloned repository.

        The 'find' string MUST be an exact substring of the file as returned by
        read_file -- never guess or paraphrase it.
        """
        if not relative_path or not find:
            return "ERROR: relative_path and find are both required."
        target = self._repo_path / relative_path
        if not target.exists():
            return f"ERROR: File not found: {relative_path}"
        content = target.read_text(encoding="utf-8")
        if find not in content:
            return (
                f"ERROR: find string not present in {relative_path}. "
                "It must be an exact substring of the file as returned by read_file. "
                "Call read_file again to check the current file state before retrying."
            )
        target.write_text(content.replace(find, replace, 1), encoding="utf-8")
        self._applied_changes.append(relative_path)
        logger.info("apply_file_change: modified %s", relative_path)
        return f"OK: change applied to {relative_path}"

    def _tool_run_maven_compile(self) -> str:
        """Compile the repository with 'mvn compile -q'. No tests are executed."""
        _, message = compile_repo(self._repo_path)
        return message
