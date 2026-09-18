"""Timezone-aware scheduling helpers for daemonized agents."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)


def get_active_window_status(
    run_time: str = "00:00",
    duration_seconds: int = 7200,
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
) -> tuple[bool, float, float]:
    """
    Evaluates whether current time falls inside the daily scheduled active window:
    [window_start, window_start + duration_seconds).

    Returns:
        (is_active, remaining_active_seconds, seconds_until_next_start)
    """
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
    duration = timedelta(seconds=max(0, duration_seconds))

    # Check today's scheduled window
    today_start = now.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(minutes=offset_minutes)
    today_end = today_start + duration

    # Check yesterday's window (relevant if duration extends past midnight)
    yesterday_start = today_start - timedelta(days=1)
    yesterday_end = yesterday_start + duration

    if today_start <= now < today_end:
        is_active = True
        remaining_active = (today_end - now).total_seconds()
        seconds_until_next = 0.0
    elif yesterday_start <= now < yesterday_end:
        is_active = True
        remaining_active = (yesterday_end - now).total_seconds()
        seconds_until_next = 0.0
    else:
        is_active = False
        remaining_active = 0.0
        if now < today_start:
            seconds_until_next = (today_start - now).total_seconds()
        else:
            tomorrow_start = today_start + timedelta(days=1)
            seconds_until_next = (tomorrow_start - now).total_seconds()

    return is_active, max(0.0, remaining_active), max(0.0, seconds_until_next)


def seconds_until_next_run(
    run_time: str = "00:00",
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
) -> float:
    """Return seconds until the next occurrence of run_time in timezone_name."""
    _, _, seconds_until_next = get_active_window_status(
        run_time=run_time,
        duration_seconds=0,
        timezone_name=timezone_name,
        offset_minutes=offset_minutes,
    )
    return seconds_until_next


from typing import Optional, Callable
from common.config import (
    get_nightly_run_time,
    get_nightly_scan_max_wait_seconds,
    is_nightly_run_enabled,
)


def sleep_until_active_window(
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
    check_cancel_fn: Optional[Callable[[], bool]] = None,
    poll_interval: float = 5.0,
) -> bool:
    """
    Sleeps until the daily scheduled active window begins.
    Periodically checks every `poll_interval` seconds to allow:
    - Early cancellation (e.g. Night Mode disabled) -> returns False
    - Dynamic reschedule or current time entering active window -> returns True immediately

    Returns True if we are in the active window, False if cancelled.
    """
    last_logged_hour = None
    while True:
        if check_cancel_fn and check_cancel_fn():
            logger.info("Nightly sleep cancelled early (Night Mode disabled).")
            return False

        run_time = get_nightly_run_time()
        duration_seconds = get_nightly_scan_max_wait_seconds()
        is_active, _, seconds_until_next = get_active_window_status(
            run_time=run_time,
            duration_seconds=duration_seconds,
            timezone_name=timezone_name,
            offset_minutes=offset_minutes,
        )

        if is_active:
            logger.info(
                "Entered active window (%s %s for %d hours). Waking up!",
                timezone_name,
                run_time,
                duration_seconds // 3600,
            )
            return True

        current_hour_int = int(seconds_until_next // 3600)
        if last_logged_hour != current_hour_int:
            logger.info(
                "Nightly scheduler sleeping %.1f hours until %s %s (window duration %dh).",
                seconds_until_next / 3600.0,
                timezone_name,
                run_time,
                duration_seconds // 3600,
            )
            last_logged_hour = current_hour_int

        sleep_duration = min(poll_interval, max(1.0, seconds_until_next))
        time.sleep(sleep_duration)


def sleep_until_next_run(
    run_time: str = "00:00",
    timezone_name: str = "Asia/Kolkata",
    offset_minutes: int = 0,
    check_cancel_fn: Optional[Callable[[], bool]] = None,
) -> bool:
    """
    Sleeps until the next occurrence of run_time or active window in timezone_name.
    Maintained for backward compatibility.
    """
    return sleep_until_active_window(
        timezone_name=timezone_name,
        offset_minutes=offset_minutes,
        check_cancel_fn=check_cancel_fn,
    )


