"""
Fixer Agent — code fixer with pluggable LLM backend (FixEngine) and package
ecosystem (PackageEcosystem).

Migrated from nexus-remediation-agent/agents/fixer/code_fixer.py, then
refactored twice:
  1. Model-calling logic (originally ADK + Vertex AI) moved behind
     engines.base.FixEngine so it can be swapped via FIX_ENGINE (engines/).
  2. Manifest handling (originally pom.xml-only methods on this class) moved
     behind ecosystems.base.PackageEcosystem (ecosystems/) so a Python/Node
     ecosystem can be added later without touching CodeFixer. Maven is the
     only implementation today -- see ecosystems/maven.py.

Neither refactor changed pom.xml handling, tracking-store, or retry-gate
logic; they only moved where that logic lives.

What is UNCHANGED (verbatim from nexus-remediation-agent):
  - ChangeSummary dataclass
  - FRESH_FIX_PROMPT and RETRY_FIX_PROMPT strings
  - pom.xml editing semantics (now in ecosystems/maven.py, not this class)
  - run_fresh_fix() and run_retry_fix() public entry points
  - _execute_fix() structure
  - InvalidRetryError

CodeFixerError (ADK's model-response parsing) lives in engines.adk_vertex.
PomXMLError (pom.xml editing) lives in ecosystems.maven. Import them from
there if you need to catch them specifically.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from common.tracking_store import TrackingStatus
from ecosystems.factory import get_ecosystem
from engines.factory import get_engine

logger = logging.getLogger(__name__)


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
    # None (not 0) when no LLM call was made (e.g. a transitive fix resolved
    # purely by a deterministic dependencyManagement override) or an engine
    # can't reliably report usage -- see engines.base.FixResult for the same
    # reasoning. 0 would misrepresent "no LLM used" as "confirmed zero cost".
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None


# ── Prompt templates (UNCHANGED from nexus-remediation-agent) ─────────────────

FRESH_FIX_PROMPT = """\
You are a Java/Maven dependency upgrade specialist. Apply the MINIMAL set of code
changes required to upgrade a specific dependency from one version to another.

## Dependency being upgraded
- Component: {component_name}
- Current version: {current_version}
- Target version: {target_version}
{kb_context}
## Repository file tree (paths only)
{file_listing}

## Available tools
- `grep_files(pattern, extensions?)` — regex search across file contents.
- `read_file(relative_path)` — read a file's full content.
- `apply_file_change(relative_path, find, replace, change_description?)` — write a find→replace edit to disk immediately.
- `run_maven_compile()` — run 'mvn compile -q'. No tests. Returns compiler error output on failure.
{test_tool_line}
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
{test_workflow_step}7. When compilation succeeds (or if no source changes are needed), return end_turn with JSON.

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
{test_tool_line}
## Your workflow
1. Analyse the CI failure log to identify the ROOT CAUSE.
2. Use grep_files and read_file to inspect the files mentioned in the failure log.
3. Call apply_file_change for the specific, minimal change that fixes the CI failure.
   Do NOT repeat the same change from the previous attempt unless the log shows it was incomplete.
4. Call run_maven_compile to verify the fix compiles cleanly.
5. If compilation fails: read the error, inspect affected files, apply corrections, compile again.
{test_workflow_step}6. When compilation succeeds, return end_turn with JSON.

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

def _render_kb_context(kb_entry) -> str:
    """
    Renders a KB entry into the prompt section injected into FRESH_FIX_PROMPT.
    Returns an empty string when no entry is available (bucket 2 with no KB).
    """
    if kb_entry is None:
        return ""

    lines = ["\n## Migration knowledge (from Knowledge Base)"]
    lines.append(f"Source: {kb_entry.source} | Confidence: {kb_entry.confidence}")

    if kb_entry.breaking_changes:
        lines.append("\n**Known breaking changes:**")
        for c in kb_entry.breaking_changes:
            lines.append(f"- {c}")

    if kb_entry.migration_steps:
        lines.append("\n**Migration steps:**")
        for i, step in enumerate(kb_entry.migration_steps, 1):
            lines.append(f"{i}. {step}")

    if kb_entry.patterns:
        lines.append("\n**Verified find→replace patterns (apply these first):**")
        for p in kb_entry.patterns:
            lines.append(
                f"- find: `{p.get('find', '')}` → replace: `{p.get('replace', '')}` "
                f"({p.get('description', '')})"
            )

    lines.append("")  # trailing newline before the next section
    return "\n".join(lines)


def _render_test_tool_line(run_tests_enabled: bool) -> str:
    """Empty when tests are disabled/unsupported -- same shape as
    _render_kb_context. Trailing newline so it fits cleanly between the
    tool list and the blank line already preceding "## Your workflow".
    """
    if not run_tests_enabled:
        return ""
    return "- `run_maven_test()` — run 'mvn test -q'. Runs the full test suite. Returns failure output on failure.\n"


def _render_test_workflow_step(step_label: str, run_tests_enabled: bool) -> str:
    """Empty when tests are disabled/unsupported. step_label lets
    FRESH_FIX_PROMPT ("6a") and RETRY_FIX_PROMPT ("5a") each insert this
    right after their own compile-and-fix-until-clean step, without
    renumbering the statically-numbered final step that follows it.
    """
    if not run_tests_enabled:
        return ""
    return (
        f"{step_label}. Once compilation succeeds, call run_maven_test to run the full test suite. "
        "If tests fail, read the failure output, inspect the affected code, and apply corrections -- "
        "write or update a test if the failure reveals a genuine behavioral gap the upgrade introduced, "
        "not merely to force a red test green artificially. Repeat compile+test until both pass.\n"
    )


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

    LLM backend: pluggable via FixEngine (engines/), selected by the
    FIX_ENGINE env var (default "adk" -- Google ADK Agent on Vertex AI /
    Gemini; "gemini_cli" -- Gemini CLI subprocess, see engines/gemini_cli.py
    for its security caveats before using it in production).

    Package ecosystem: pluggable via PackageEcosystem (ecosystems/),
    auto-detected from repo contents (Maven/pom.xml only in this POC --
    see ecosystems/factory.py). Manifest handling and prompt construction
    are engine- and ecosystem-agnostic.
    """

    def __init__(self, repo_path: str, model_deployment_name: Optional[str] = None):
        self._repo_path = Path(repo_path)
        self._max_attempts = int(os.environ.get("MAX_RETRY_ATTEMPTS", "3"))
        self._engine = get_engine(model_deployment_name=model_deployment_name)
        self._ecosystem = get_ecosystem(self._repo_path)
        # Opt-in (RUN_TESTS) AND the active engine has to actually support it
        # (engines.base.FixEngine.supports_tests) -- e.g. gemini_cli never
        # does, by its own documented security posture. Computed once here,
        # not re-checked per prompt build, so it can't disagree with itself
        # mid-run.
        self._run_tests_enabled = (
            os.environ.get("RUN_TESTS", "0") == "1" and getattr(self._engine, "supports_tests", False)
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
        kb_entry=None,
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
            kb_entry=kb_entry,
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

    def run_transitive_fix(
        self,
        component_name: str,
        current_version: str,
        target_version: str,
        introduced_by: str,
        tracking_id: str,
        tracking_store,
        cve_ids: Optional[list] = None,
    ) -> ChangeSummary:
        """Entry point for a transitive-dependency finding (see
        dependency_tree.py / classifier.py) -- component_name here is the
        transitive artifact itself, not the direct dependency that pulls it
        in. See _execute_transitive_fix for the deterministic fix logic.
        """
        logger.info(
            "[transitive] %s (via %s): %s → %s (tracking=%s)",
            component_name, introduced_by, current_version, target_version, tracking_id[:8],
        )
        record = tracking_store.get(tracking_id)
        if record is None:
            raise ValueError(f"Tracking record {tracking_id} not found.")

        summary = self._execute_transitive_fix(
            component_name=component_name,
            current_version=current_version,
            target_version=target_version,
            introduced_by=introduced_by,
            cve_ids=cve_ids or [],
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
        kb_entry=None,
    ) -> ChangeSummary:
        self._ecosystem.bump_direct_dependency(
            self._repo_path, component_name, current_version, target_version
        )
        file_listing = self._build_file_listing()
        prompt = self._build_prompt(
            component_name=component_name,
            current_version=current_version,
            target_version=target_version,
            file_listing=file_listing,
            failure_log_excerpt=failure_log_excerpt,
            kb_entry=kb_entry,
        )
        result = self._engine.run_fix(self._repo_path, prompt)
        files_changed = ["pom.xml"] + list(dict.fromkeys(result.files_changed))
        return ChangeSummary(
            component_name=component_name,
            old_version=current_version,
            new_version=target_version,
            files_changed=files_changed,
            rationale=result.rationale,
            cve_ids=cve_ids,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
        )

    def _execute_transitive_fix(
        self,
        component_name: str,
        current_version: str,
        target_version: str,
        introduced_by: str,
        cve_ids: list,
    ) -> ChangeSummary:
        """Deterministic path for a transitive-dependency finding: pins the
        resolved version via a <dependencyManagement> override (see
        _add_dependency_management_override) -- no LLM call, no source
        changes, no prompt_tokens/completion_tokens (None, not 0 -- see
        engines.base.FixResult on why 0 would misrepresent "no LLM used" as
        "confirmed zero cost").

        Verified by compiling. If the version bump itself breaks the build --
        version-mediation fallout, not something a pom.xml-only edit can fix
        further -- falls back to the FixEngine with the compile failure as
        context, reusing the exact same RETRY_FIX_PROMPT path a CI-failure
        retry would use (_build_prompt selects it whenever failure_log_excerpt
        is set, regardless of why).
        """
        self._ecosystem.add_transitive_override(self._repo_path, component_name, target_version)

        compiled, message = self._ecosystem.verify_build(self._repo_path)
        if compiled:
            return ChangeSummary(
                component_name=component_name,
                old_version=current_version,
                new_version=target_version,
                files_changed=["pom.xml"],
                rationale=(
                    f"Transitive dependency (introduced by {introduced_by}) pinned to "
                    f"{target_version} via a dependencyManagement override. No source "
                    "changes required."
                ),
                cve_ids=cve_ids,
            )

        logger.warning(
            "%s: dependencyManagement override to %s did not compile cleanly -- "
            "falling back to FixEngine with the compile failure as context. %s",
            component_name, target_version, message[:200],
        )
        file_listing = self._build_file_listing()
        prompt = self._build_prompt(
            component_name=component_name,
            current_version=current_version,
            target_version=target_version,
            file_listing=file_listing,
            failure_log_excerpt=message,
        )
        result = self._engine.run_fix(self._repo_path, prompt)
        files_changed = ["pom.xml"] + list(dict.fromkeys(result.files_changed))
        return ChangeSummary(
            component_name=component_name,
            old_version=current_version,
            new_version=target_version,
            files_changed=files_changed,
            rationale=(
                f"Transitive dependency (introduced by {introduced_by}) pinned to "
                f"{target_version} via a dependencyManagement override; that broke "
                f"compilation, so the FixEngine applied a corrective source fix. "
                f"{result.rationale}"
            ),
            cve_ids=cve_ids,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
        )

    # ── Prompt construction (engine-agnostic) ─────────────────────────────────

    def _build_prompt(
        self,
        component_name: str,
        current_version: str,
        target_version: str,
        file_listing: str,
        failure_log_excerpt: Optional[str],
        kb_entry=None,
    ) -> str:
        """Selects and formats FRESH_FIX_PROMPT or RETRY_FIX_PROMPT. The result is
        handed to whichever FixEngine is configured -- prompt content doesn't
        change based on which engine will run it, only on self._run_tests_enabled
        (a capability the engine itself already reported, not an engine-name
        branch here -- see __init__).
        """
        if failure_log_excerpt:
            return RETRY_FIX_PROMPT.format(
                component_name=component_name,
                current_version=current_version,
                target_version=target_version,
                failure_log_excerpt=failure_log_excerpt[:6000],
                file_listing=file_listing,
                test_tool_line=_render_test_tool_line(self._run_tests_enabled),
                test_workflow_step=_render_test_workflow_step("5a", self._run_tests_enabled),
            )
        return FRESH_FIX_PROMPT.format(
            component_name=component_name,
            current_version=current_version,
            target_version=target_version,
            file_listing=file_listing,
            kb_context=_render_kb_context(kb_entry),
            test_tool_line=_render_test_tool_line(self._run_tests_enabled),
            test_workflow_step=_render_test_workflow_step("6a", self._run_tests_enabled),
        )

    # ── File listing (UNCHANGED) ──────────────────────────────────────────────

    def _build_file_listing(self) -> str:
        files = []
        for ext in ("*.java", "*.xml", "*.properties", "*.yml", "*.yaml"):
            for f in self._repo_path.rglob(ext):
                if "target" not in f.parts:
                    files.append(str(f.relative_to(self._repo_path)))
        return "\n".join(sorted(files)[:200])
