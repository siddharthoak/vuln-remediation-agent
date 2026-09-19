import unittest
from datetime import datetime, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "agents"))

from common.nightly_scheduler import get_active_window_status, sleep_until_active_window


class TestNightlyScheduler(unittest.TestCase):
    def test_inside_window_same_day(self):
        tz = ZoneInfo("Asia/Kolkata")
        fake_now = datetime(2026, 9, 18, 16, 0, 0, tzinfo=tz)  # 16:00
        with patch("common.nightly_scheduler.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
            is_active, rem, until_next = get_active_window_status(
                run_time="15:39", duration_seconds=7200, timezone_name="Asia/Kolkata"
            )
            self.assertTrue(is_active)
            self.assertEqual(rem, 5940.0)  # 17:39 - 16:00 = 1h39m = 5940s
            self.assertEqual(until_next, 0.0)

    def test_after_window_same_day(self):
        tz = ZoneInfo("Asia/Kolkata")
        fake_now = datetime(2026, 9, 18, 18, 0, 0, tzinfo=tz)  # 18:00
        with patch("common.nightly_scheduler.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
            is_active, rem, until_next = get_active_window_status(
                run_time="15:39", duration_seconds=7200, timezone_name="Asia/Kolkata"
            )
            self.assertFalse(is_active)
            self.assertEqual(rem, 0.0)
            self.assertEqual(until_next, 21 * 3600 + 39 * 60)  # Until tomorrow 15:39

    def test_before_window_same_day(self):
        tz = ZoneInfo("Asia/Kolkata")
        fake_now = datetime(2026, 9, 18, 14, 0, 0, tzinfo=tz)  # 14:00
        with patch("common.nightly_scheduler.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
            is_active, rem, until_next = get_active_window_status(
                run_time="15:39", duration_seconds=7200, timezone_name="Asia/Kolkata"
            )
            self.assertFalse(is_active)
            self.assertEqual(rem, 0.0)
            self.assertEqual(until_next, 1 * 3600 + 39 * 60)  # Until today 15:39

    def test_midnight_spanning_window(self):
        tz = ZoneInfo("Asia/Kolkata")
        # 01:30 AM after a 23:00 run start with 4 hour duration (ends at 03:00)
        fake_now = datetime(2026, 9, 19, 1, 30, 0, tzinfo=tz)
        with patch("common.nightly_scheduler.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
    def test_format_duration(self):
        from common.nightly_scheduler import format_duration
        self.assertEqual(format_duration(60), "1m")
        self.assertEqual(format_duration(300), "5m")
        self.assertEqual(format_duration(3600), "1h")
        self.assertEqual(format_duration(5400), "1h 30m")
        self.assertEqual(format_duration(7200), "2h")

    def test_minutes_window(self):
        tz = ZoneInfo("Asia/Kolkata")
        fake_now = datetime(2026, 9, 18, 15, 45, 0, tzinfo=tz)  # 15:45
        with patch("common.nightly_scheduler.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
            # 15:39 with 15 minutes window (ends at 15:54)
            is_active, rem, until_next = get_active_window_status(
                run_time="15:39", duration_seconds=15 * 60, timezone_name="Asia/Kolkata"
            )
            self.assertTrue(is_active)
            self.assertEqual(rem, 9 * 60.0)  # 15:54 - 15:45 = 9m = 540s
            self.assertEqual(until_next, 0.0)


if __name__ == "__main__":
    unittest.main()
