"""Unit tests for Cisco timestamp normalization."""

from datetime import datetime
from app.core.timestamps import parse_cisco_timestamp


def test_parse_cisco_month_day_timestamp():
    raw = "*Sep 19 10:15:22.632:"
    dt, clean_str = parse_cisco_timestamp(raw, reference_year=2026)
    assert dt is not None
    assert dt == datetime(2026, 9, 19, 10, 15, 22, 632000)
    assert clean_str == "*Sep 19 10:15:22.632"


def test_parse_cisco_month_day_without_asterisk():
    raw = "Sep 19 10:15:22.632"
    dt, clean_str = parse_cisco_timestamp(raw, reference_year=2026)
    assert dt is not None
    assert dt.month == 9
    assert dt.day == 19
    assert dt.hour == 10


def test_parse_iso_timestamp():
    raw = "2026-09-19 14:22:01.123"
    dt, clean_str = parse_cisco_timestamp(raw)
    assert dt is not None
    assert dt == datetime(2026, 9, 19, 14, 22, 1, 123000)


def test_time_only_does_not_invent_date():
    raw = "10:15:22.632"
    dt, clean_str = parse_cisco_timestamp(raw)
    # Requirement: Do not invent the date if it is unavailable
    assert dt is None
    assert clean_str == "10:15:22.632"


def test_empty_timestamp():
    dt, clean_str = parse_cisco_timestamp(None)
    assert dt is None
    assert clean_str is None

    dt, clean_str = parse_cisco_timestamp("")
    assert dt is None
    assert clean_str is None
