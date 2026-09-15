"""Timezone-aware scheduling helpers for daemonized agents."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)


def seconds_until_next_run(
    run_time: str = "00:00",
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
) -> float:
    """Return seconds until the next occurrence of run_time in timezone_name."""
    try:
        timezone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(
            f"Unknown NIGHTLY_RUN_TIMEZONE={timezone_name!r}. "
            "Use an IANA timezone such as Asia/Kolkata or UTC."
        ) from exc

    try:
        hour, minute = (int(part) for part in run_time.split(":", 1))
    except (AttributeError, ValueError) as exc:
        raise ValueError(
            f"Invalid NIGHTLY_RUN_TIME={run_time!r}; expected HH:MM."
        ) from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"Invalid NIGHTLY_RUN_TIME={run_time!r}; expected HH:MM.")

    now = datetime.now(timezone)
    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    next_run += timedelta(minutes=offset_minutes)
    if next_run <= now:
        next_run += timedelta(days=1)
    return max((next_run - now).total_seconds(), 0.0)


from typing import Optional, Callable


def sleep_until_next_run(
    run_time: str = "00:00",
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
    check_cancel_fn: Optional[Callable[[], bool]] = None,
) -> bool:
    """
    Sleeps until the next occurrence of run_time in timezone_name.
    Periodically checks check_cancel_fn() (e.g. every 5s) to allow early wake-up
    if Night Mode is toggled off at runtime.
    Returns True if full sleep completed, False if cancelled early.
    """
    delay = seconds_until_next_run(run_time, timezone_name, offset_minutes)
    logger.info(
        "Nightly scheduler sleeping %.1f hours until %s %s.",
        delay / 3600,
        timezone_name,
        run_time,
    )
    end_time = time.time() + delay
    while time.time() < end_time:
        if check_cancel_fn and check_cancel_fn():
            logger.info("Nightly sleep cancelled early (Night Mode disabled).")
            return False
        remaining = end_time - time.time()
        time.sleep(min(5.0, max(0.0, remaining)))
    return True

