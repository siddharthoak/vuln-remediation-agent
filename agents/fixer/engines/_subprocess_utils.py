"""Shared subprocess execution for CLI-based FixEngines."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Optional


class EngineTimeoutError(RuntimeError):
    pass


async def run_cli(
    args: list, cwd: Path, timeout_seconds: float, extra_env: Optional[dict] = None
) -> tuple:
    """Runs a CLI to completion, returns (returncode, stdout, stderr).

    extra_env is merged on top of the current process environment (e.g. to
    pass a provider API key under the exact env var name its CLI expects).

    stdin is DEVNULL so an unexpected interactive prompt (trust confirmation,
    tool-approval, auth) fails fast instead of hanging the container forever.
    """
    env = {**os.environ, **extra_env} if extra_env else None
    process = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd),
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise EngineTimeoutError(f"{args[0]} did not finish within {timeout_seconds}s") from exc

    return (
        process.returncode or 0,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


def turns_to_timeout_seconds(max_turns: int, seconds_per_turn: float = 60.0) -> float:
    """CLIs that don't expose a native turn-limit concept get a wall-clock budget instead."""
    return max(max_turns, 1) * seconds_per_turn
