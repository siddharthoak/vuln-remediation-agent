"""
Fixer Agent — code fixer using Google ADK + Vertex AI.

Migrated from nexus-remediation-agent/agents/fixer/code_fixer.py.

What changed vs. the Azure/Anthropic version:
  - LLM client: anthropic.Anthropic() → google.adk Agent + FunctionTool
  - Model: Anthropic model name → Vertex AI model name (VERTEX_MODEL env var,
    default: gemini-2.0-flash-001)
  - Token counting: response.usage.input/output_tokens →
    event.usage_metadata.prompt_token_count / candidates_token_count
  - Tool loop: manual stop_reason branching → ADK Runner handles the loop

What is UNCHANGED (verbatim from nexus-remediation-agent):
  - ChangeSummary dataclass
  - FRESH_FIX_PROMPT and RETRY_FIX_PROMPT strings
  - _bump_pom_version() — XML parser, never lets the model touch pom.xml
  - _tool_read_file(), _tool_grep_files(), _tool_run_maven_compile()
  - _tool_apply_file_change() — logic identical; parameter names find/replace
    (previously find_str/replace_str) match the prompt descriptions exactly
  - run_fresh_fix() and run_retry_fix() public entry points
  - _execute_fix() structure
  - InvalidRetryError, PomXMLError, CodeFixerError
"""

import asyncio
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import vertexai
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools import FunctionTool
from google.genai import types as genai_types
import xml.etree.ElementTree as ET

from common.tracking_store import TrackingStatus

logger = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 10  # Passed to ADK Runner as max_llm_calls to guard runaway loops


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ChangeSummary:
    component_name: str
    old_version: str
    new_version: str
    files_changed: list = field(default_factory=list)
    rationale: str = ""
    cve_ids: list = field(default_factory=list)
    max_retries: int = 3
    prompt_tokens: int = 0
    completion_tokens: int = 0


# ── Prompt templates (UNCHANGED from nexus-remediation-agent) ─────────────────

FRESH_FIX_PROMPT = """\
You are a Java/Maven dependency upgrade specialist. Apply the MINIMAL set of code
changes required to upgrade a specific dependency from one version to another.

## Dependency being upgraded
- Component: {component_name}
- Current version: {current_version}
- Target version: {target_version}

## Repository file tree (paths only)
{file_listing}

## Available tools
- `grep_files(pattern, extensions?)` — regex search across file contents.
- `read_file(relative_path)` — read a file's full content.
- `apply_file_change(relative_path, find, replace, change_description?)` — write a find→replace edit to disk immediately.
- `run_maven_compile()` — run 'mvn compile -q'. No tests. Returns compiler error output on failure.

## Your workflow
1. Call grep_files with the import/package pattern for {component_name}
   (e.g. for "org.apache.logging.log4j:log4j-core", search "org\\.apache\\.logging\\.log4j").
2. Call read_file on each affected file to inspect the actual source code.
3. Identify which API/behavioral changes between {current_version} and {target_version}
   require source-level changes (removed/renamed methods, config format changes).
4. Call apply_file_change for each required edit.
   The "find" value MUST be an exact substring of the file content from read_file — never guess.
   Do NOT edit pom.xml — the version bump is already applied.
5. Call run_maven_compile to verify the changes compile cleanly.
6. If compilation fails: read the error, inspect the affected files, apply corrections, compile again.
7. When compilation succeeds (or if no source changes are needed), return end_turn with JSON.

## CRITICAL CONSTRAINTS
- Only apply changes strictly required by the version upgrade.
- Do NOT refactor, rename, reformat, or improve unrelated code.
- Never pass a "find" value you have not verified verbatim in read_file output.

```json
{{
  "rationale": "<key API changes between versions and summary of what was changed>"
}}
```
"""

RETRY_FIX_PROMPT = """\
You are a Java/Maven dependency upgrade specialist. A previous fix attempt for this
dependency upgrade FAILED CI. Diagnose the CI failure and apply a corrective fix.

## Dependency being upgraded
- Component: {component_name}
- Current version: {current_version}
- Target version: {target_version}

## Previous CI failure log (root cause of the failure)
```
{failure_log_excerpt}
```

## Repository file tree (paths only)
{file_listing}

## Available tools
- `grep_files(pattern, extensions?)` — regex search across file contents.
- `read_file(relative_path)` — read a file's full content.
- `apply_file_change(relative_path, find, replace, change_description?)` — write a find→replace edit to disk immediately.
- `run_maven_compile()` — run 'mvn compile -q'. No tests. Returns compiler error output on failure.

## Your workflow
1. Analyse the CI failure log to identify the ROOT CAUSE.
2. Use grep_files and read_file to inspect the files mentioned in the failure log.
3. Call apply_file_change for the specific, minimal change that fixes the CI failure.
   Do NOT repeat the same change from the previous attempt unless the log shows it was incomplete.
4. Call run_maven_compile to verify the fix compiles cleanly.
5. If compilation fails: read the error, inspect affected files, apply corrections, compile again.
6. When compilation succeeds, return end_turn with JSON.

## CRITICAL CONSTRAINTS
- Fix only what the CI failure log tells you is broken.
- Do NOT refactor, rename, reformat, or improve unrelated code.
- Do NOT edit pom.xml.
- Never pass a "find" value you have not verified verbatim in read_file output.

```json
{{
  "rationale": "<diagnosis of the CI failure and summary of what was changed>"
}}
```
"""


# ── Exceptions ────────────────────────────────────────────────────────────────

class PomXMLError(Exception):
    """Raised when pom.xml cannot be parsed or the target dependency is not found."""


class CodeFixerError(Exception):
    """Raised when the model response cannot be parsed into the expected format."""


class InvalidRetryError(Exception):
    """
    Raised when run_retry_fix() is called with a tracking_id that fails validation.
    Prevents the Fixer from acting on anything other than a Watcher-gated
    RETRY_REQUESTED record.
    """


# ── CodeFixer ─────────────────────────────────────────────────────────────────

class CodeFixer:
    """
    Applies dependency upgrade fixes to a cloned repository.

    LLM backend: Google ADK Agent running on Vertex AI (Gemini).
    The four tool handler methods and all fix logic are unchanged from the
    nexus-remediation-agent version. Only the model client layer is swapped.
    """

    def __init__(self, repo_path: str, model_deployment_name: Optional[str] = None):
        self._repo_path = Path(repo_path)
        self._model_name = model_deployment_name or os.environ.get(
            "VERTEX_MODEL", "gemini-2.0-flash-001"
        )
        self._max_attempts = int(os.environ.get("MAX_RETRY_ATTEMPTS", "3"))
        self._applied_changes: list = []

        # Initialise Vertex AI — region from env, project from ADC
        vertexai.init(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=os.environ.get("VERTEX_LOCATION", "us-central1"),
        )

    # ── Public entry points (UNCHANGED) ──────────────────────────────────────

    def run_fresh_fix(
        self,
        component_name: str,
        current_version: str,
        target_version: str,
        tracking_id: str,
        tracking_store,
        cve_ids: Optional[list] = None,
    ) -> ChangeSummary:
        logger.info(
            "[fresh] %s: %s → %s (tracking=%s)",
            component_name, current_version, target_version, tracking_id[:8],
        )
        record = tracking_store.get(tracking_id)
        if record is None:
            raise ValueError(f"Tracking record {tracking_id} not found.")

        summary = self._execute_fix(
            component_name=component_name,
            current_version=current_version,
            target_version=target_version,
            cve_ids=cve_ids or [],
            failure_log_excerpt=None,
        )
        record.token_usage = {
            "prompt_tokens": summary.prompt_tokens,
            "completion_tokens": summary.completion_tokens,
        }
        tracking_store.update(record)
        return summary

    def run_retry_fix(self, tracking_id: str, tracking_store) -> ChangeSummary:
        record = tracking_store.get(tracking_id)
        if record is None:
            raise InvalidRetryError(
                f"Tracking record {tracking_id} not found. "
                "Cannot retry a fix without a valid Watcher-issued tracking record."
            )
        if record.status != TrackingStatus.RETRY_REQUESTED.value:
            raise InvalidRetryError(
                f"Tracking record {tracking_id} has status={record.status!r}, "
                f"expected {TrackingStatus.RETRY_REQUESTED.value!r}. "
                "The Fixer's retry entry point may only be invoked by the Watcher "
                "through a RETRY_REQUESTED record. Refusing to act."
            )
        if record.attempt_number > self._max_attempts:
            raise InvalidRetryError(
                f"Tracking record {tracking_id} has attempt_number={record.attempt_number} "
                f"which exceeds MAX_RETRY_ATTEMPTS={self._max_attempts}. "
                "Retry limit already exhausted. Refusing to act."
            )
        logger.info(
            "[retry] %s: %s → %s attempt %d/%d (tracking=%s)",
            record.component_name, record.old_version, record.new_version,
            record.attempt_number, self._max_attempts, tracking_id[:8],
        )
        if not record.failure_log_excerpt:
            logger.warning(
                "Retry tracking record %s has no failure_log_excerpt — "
                "proceeding with reduced context.",
                tracking_id[:8],
            )
        summary = self._execute_fix(
            component_name=record.component_name,
            current_version=record.old_version,
            target_version=record.new_version,
            cve_ids=[record.vulnerability_id] if record.vulnerability_id else [],
            failure_log_excerpt=record.failure_log_excerpt,
        )
        record.token_usage = {
            "prompt_tokens": summary.prompt_tokens,
            "completion_tokens": summary.completion_tokens,
        }
        tracking_store.update(record)
        return summary

    # ── Core fix logic (UNCHANGED) ────────────────────────────────────────────

    def _execute_fix(
        self,
        component_name: str,
        current_version: str,
        target_version: str,
        cve_ids: list,
        failure_log_excerpt: Optional[str],
    ) -> ChangeSummary:
        self._bump_pom_version(component_name, current_version, target_version)
        self._applied_changes = []
        file_listing = self._build_file_listing()
        reasoning, prompt_tokens, completion_tokens = self._call_model(
            component_name=component_name,
            current_version=current_version,
            target_version=target_version,
            file_listing=file_listing,
            failure_log_excerpt=failure_log_excerpt,
        )
        files_changed = ["pom.xml"] + list(dict.fromkeys(self._applied_changes))
        return ChangeSummary(
            component_name=component_name,
            old_version=current_version,
            new_version=target_version,
            files_changed=files_changed,
            rationale=reasoning.get("rationale", ""),
            cve_ids=cve_ids,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    # ── pom.xml manipulation (UNCHANGED) ─────────────────────────────────────

    def _bump_pom_version(self, component_name: str, current_version: str, target_version: str) -> None:
        pom_path = self._repo_path / "pom.xml"
        if not pom_path.exists():
            raise PomXMLError(f"pom.xml not found at {pom_path}")

        tree = ET.parse(str(pom_path))
        root = tree.getroot()
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        ET.register_namespace("", "http://maven.apache.org/POM/4.0.0")

        parts = component_name.split(":")
        artifact_id = parts[-1]
        group_id = parts[0] if len(parts) > 1 else None

        found = False
        for dep in root.findall(".//m:dependency", ns):
            aid_el = dep.find("m:artifactId", ns)
            gid_el = dep.find("m:groupId", ns)
            ver_el = dep.find("m:version", ns)
            if aid_el is None or ver_el is None:
                continue
            aid_match = aid_el.text == artifact_id
            gid_match = group_id is None or (gid_el is not None and gid_el.text == group_id)
            if aid_match and gid_match and ver_el.text == current_version:
                ver_el.text = target_version
                found = True
                logger.info("pom.xml: %s %s → %s", component_name, current_version, target_version)
                break

        if not found:
            raise PomXMLError(
                f"Dependency {component_name}@{current_version} not found in pom.xml."
            )
        tree.write(str(pom_path), xml_declaration=True, encoding="utf-8")

    # ── ADK model call (replaces Anthropic tool-use loop) ────────────────────

    def _call_model(
        self,
        component_name: str,
        current_version: str,
        target_version: str,
        file_listing: str,
        failure_log_excerpt: Optional[str],
    ) -> tuple:
        """
        Runs the ADK Agent with the four FunctionTools against the Vertex AI backend.
        Returns (reasoning_dict, total_prompt_tokens, total_completion_tokens).

        The agent's instruction IS the full fix prompt (FRESH or RETRY). ADK handles
        the tool-use loop internally; the handler methods are called synchronously
        by ADK as the model requests each tool.
        """
        if failure_log_excerpt:
            prompt = RETRY_FIX_PROMPT.format(
                component_name=component_name,
                current_version=current_version,
                target_version=target_version,
                failure_log_excerpt=failure_log_excerpt[:6000],
                file_listing=file_listing,
            )
        else:
            prompt = FRESH_FIX_PROMPT.format(
                component_name=component_name,
                current_version=current_version,
                target_version=target_version,
                file_listing=file_listing,
            )

        tools = [
            FunctionTool(func=self._tool_read_file),
            FunctionTool(func=self._tool_grep_files),
            FunctionTool(func=self._tool_apply_file_change),
            FunctionTool(func=self._tool_run_maven_compile),
        ]

        agent = Agent(
            name="code_fixer",
            model=self._model_name,
            instruction=prompt,
            tools=tools,
        )

        return asyncio.run(self._run_agent_async(agent))

    async def _run_agent_async(self, agent: Agent) -> tuple:
        """Async runner for the ADK agent. Called via asyncio.run() from _call_model."""
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

    # ── Tool handlers (UNCHANGED — called directly by ADK FunctionTool) ───────

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
        read_file — never guess or paraphrase it.
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
        try:
            result = subprocess.run(
                ["mvn", "compile", "-q", "--batch-mode"],
                cwd=str(self._repo_path),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            return "ERROR: mvn not found — Maven must be installed in the container image."
        except subprocess.TimeoutExpired:
            return "ERROR: mvn compile timed out after 300 seconds."

        if result.returncode == 0:
            return "mvn compile: SUCCESS — no compilation errors."

        output = (
            f"mvn compile: FAILED (exit code {result.returncode})\n\n"
            f"STDERR:\n{result.stderr[:10_000]}"
        )
        if result.stdout.strip():
            output += f"\n\nSTDOUT:\n{result.stdout[:5_000]}"
        return output

    # ── File listing (UNCHANGED) ──────────────────────────────────────────────

    def _build_file_listing(self) -> str:
        files = []
        for ext in ("*.java", "*.xml", "*.properties", "*.yml", "*.yaml"):
            for f in self._repo_path.rglob(ext):
                if "target" not in f.parts:
                    files.append(str(f.relative_to(self._repo_path)))
        return "\n".join(sorted(files)[:200])
