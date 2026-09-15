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


def sleep_until_next_run(
    run_time: str = "00:00",
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
) -> None:
    delay = seconds_until_next_run(run_time, timezone_name, offset_minutes)
    logger.info(
        "Nightly scheduler sleeping %.1f hours until %s %s.",
        delay / 3600,
        timezone_name,
        run_time,
    )
    time.sleep(delay)
