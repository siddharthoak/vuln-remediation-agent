"""FixEngine backed by Google's Gemini CLI (`gemini`).

Requires the `gemini` binary on PATH (npm install -g @google/gemini-cli,
Node 18+) and GEMINI_API_KEY. Runs a single non-interactive turn against the
cloned repo, relying on the CLI's own Read/Glob/Grep/Edit tools instead of
the hand-rolled FunctionTools AdkVertexEngine wires up.

Safety posture for an unattended CVE-remediation pipeline:
  - Shell execution is meant to be disabled via a per-run .gemini/settings.json
    tool exclusion (_write_settings below), rather than trusting --yolo alone.
    `mvn compile` verification stays out of this engine entirely -- CodeFixer/
    the CI-driven Watcher retry loop is the compile gate, not a model-invoked
    shell command.
  - ** UNVERIFIED -- DO NOT TREAT AS A PROVEN SECURITY BOUNDARY YET **
    The {"tools": {"exclude": [...]}} settings.json mechanism and exact key
    name have not been confirmed against the installed gemini-cli version's
    actual behavior. Before routing real remediation traffic through this
    engine, run the validation spike from the architecture review: confirm
    the exclusion actually blocks run_shell_command (e.g. ask the model to
    run `whoami` and verify it can't), not just that the flag is accepted.
  - files_changed is computed from `git diff --name-only` after the run, not
    from the model's self-reported output -- deterministic, not dependent on
    the model accurately narrating what it touched.
  - stdin is DEVNULL (see _subprocess_utils.run_cli) so an unexpected
    interactive prompt fails fast instead of hanging the container.

--skip-trust is required: Gemini CLI refuses to run tools in a directory it
hasn't been told to trust, even with --yolo, and a freshly-cloned repo is
never pre-trusted.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from engines._subprocess_utils import EngineTimeoutError, run_cli, turns_to_timeout_seconds
from engines.base import EngineExecutionError, FixResult

logger = logging.getLogger(__name__)

CLI_BINARY = "gemini"
DEFAULT_MAX_TURNS = int(os.environ.get("GEMINI_CLI_MAX_TURNS", "10"))


def _write_settings(repo_path: Path) -> None:
    """Writes a per-run .gemini/settings.json excluding the shell tool.

    UNVERIFIED -- see module docstring. This is a best-effort attempt at a
    tool restriction, not a confirmed one.
    """
    settings_dir = repo_path / ".gemini"
    settings_dir.mkdir(exist_ok=True)
    (settings_dir / "settings.json").write_text(
        json.dumps({"tools": {"exclude": ["run_shell_command"]}}, indent=2),
        encoding="utf-8",
    )


def _git_diff_files(repo_path: Path) -> list:
    """Deterministic list of tracked files the working tree diff shows
    changed. Excludes pom.xml -- CodeFixer._execute_fix prepends that
    itself, since the version bump happens before the engine ever runs.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("git diff --name-only failed: %s", exc)
        return []
    if result.returncode != 0:
        logger.warning("git diff --name-only exited %d: %s", result.returncode, result.stderr)
        return []
    return [f for f in result.stdout.splitlines() if f and f != "pom.xml"]


def _parse_rationale(stdout: str) -> str:
    """Gemini's --output-format json prints a single JSON object with a
    "response" field holding the model's final text. That text still
    contains the ```json {"rationale": ...}``` block the shared fix prompts
    (FRESH_FIX_PROMPT/RETRY_FIX_PROMPT in code_fixer.py) ask for -- try to
    extract it the same way AdkVertexEngine does, but fall back to the raw
    response text on any parse failure instead of raising. Rationale is
    PR-description copy, not something worth hard-failing a fix attempt over.
    """
    try:
        response = json.loads(stdout).get("response", "")
    except json.JSONDecodeError:
        response = stdout.strip()

    if not isinstance(response, str) or not response:
        return stdout.strip() or "(gemini produced no output)"

    match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(1))
            return parsed.get("rationale") or response.strip()
        except json.JSONDecodeError:
            pass
    return response.strip()


class GeminiCliEngine:
    def __init__(self, max_turns: int = DEFAULT_MAX_TURNS) -> None:
        self._max_turns = max_turns
        self._api_key = os.environ.get("GEMINI_API_KEY", "")

    def run_fix(self, repo_path: Path, prompt: str) -> FixResult:
        if shutil.which(CLI_BINARY) is None:
            raise EngineExecutionError(
                f"'{CLI_BINARY}' (Gemini CLI) not found on PATH. "
                "Install: npm install -g @google/gemini-cli"
            )

        _write_settings(repo_path)

        args = [CLI_BINARY, "-p", prompt, "--yolo", "--skip-trust", "--output-format", "json"]
        timeout = turns_to_timeout_seconds(self._max_turns)
        extra_env = {"GEMINI_API_KEY": self._api_key} if self._api_key else None

        try:
            returncode, stdout, stderr = asyncio.run(
                run_cli(args, cwd=repo_path, timeout_seconds=timeout, extra_env=extra_env)
            )
        except EngineTimeoutError as exc:
            raise EngineExecutionError(str(exc)) from exc

        if returncode != 0 and not stdout.strip():
            raise EngineExecutionError(
                f"gemini exited {returncode} with no output.\n\nstderr:\n{stderr[:4000]}"
            )

        return FixResult(
            rationale=_parse_rationale(stdout),
            files_changed=_git_diff_files(repo_path),
        )
