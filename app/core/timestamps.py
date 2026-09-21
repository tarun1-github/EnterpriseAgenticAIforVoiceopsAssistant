"""Core timestamp normalization utilities for Cisco voice traces."""

import re
from datetime import date, datetime, timezone
from typing import Optional, Tuple
from zoneinfo import ZoneInfo

IST_TZ = ZoneInfo("Asia/Kolkata")

# Regex patterns for Cisco timestamps
# Pattern 1: ISO or full date (e.g. 2026-09-19 14:22:01.123 or 2026-09-19T14:22:01)
ISO_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<year>\d{4})[-/](?P<month>\d{2})[-/](?P<day>\d{2})[T\s](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<msec>\d+))?"
)

# Pattern 2: Cisco Month Day Time (e.g. *Sep 19 10:15:22.632 or Sep 19 14:22:01.123 UTC:)
CISCO_MD_TIMESTAMP_PATTERN = re.compile(
    r"^\*?(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<msec>\d+))?(?:\s+[A-Z]{3,4})?:?$"
)

# Pattern 3: Cisco Time-only (e.g. 10:15:22.632 or 10:15:22)
TIME_ONLY_PATTERN = re.compile(
    r"^(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<msec>\d+))?:?$"
)

MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12
}


def parse_date_from_file_head(content_or_line: str) -> Optional[date]:
    """Extract explicit date declared in CUCM trace FileHead header.

    Example line:
    00602802.000 |08:52:24.482 |FileHead |UTC:+00:00,Date: 2026/09/20, AppName: CCM...
    """
    if not content_or_line:
        return None
    m = re.search(r"Date:\s*(?P<year>\d{4})[-/](?P<month>\d{2})[-/](?P<day>\d{2})", content_or_line, re.IGNORECASE)
    if m:
        return date(int(m.group("year")), int(m.group("month")), int(m.group("day")))
    return None


def parse_cisco_timestamp(
    raw_ts: Optional[str],
    reference_year: int = 2026,
    reference_date: Optional[date] = None,
) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse Cisco trace timestamp into a normalized datetime and clean raw string.

    Args:
        raw_ts: Raw timestamp string from trace header.
        reference_year: Reference year to apply when trace provides month and day only.
        reference_date: Optional explicit date when trace lines contain time-only format.

    Returns:
        Tuple of (normalized_datetime_or_None, cleaned_raw_string).
        If only time is provided without date and reference_date is None, datetime is None.
    """
    if not raw_ts or not raw_ts.strip():
        return None, None

    clean_raw = raw_ts.strip().strip(": ")

    # Check ISO format
    m_iso = ISO_TIMESTAMP_PATTERN.match(clean_raw)
    if m_iso:
        year = int(m_iso.group("year"))
        month = int(m_iso.group("month"))
        day = int(m_iso.group("day"))
        hour = int(m_iso.group("hour"))
        minute = int(m_iso.group("minute"))
        second = int(m_iso.group("second"))
        msec_str = m_iso.group("msec") or "0"
        microsecond = int(msec_str.ljust(6, "0")[:6])
        dt = datetime(year, month, day, hour, minute, second, microsecond)
        return dt, clean_raw

    # Check Cisco Month-Day format (e.g. *Sep 19 10:15:22.632:)
    m_md = CISCO_MD_TIMESTAMP_PATTERN.match(clean_raw)
    if m_md:
        mon_str = m_md.group("month").lower()
        month = MONTH_MAP.get(mon_str, 1)
        day = int(m_md.group("day"))
        hour = int(m_md.group("hour"))
        minute = int(m_md.group("minute"))
        second = int(m_md.group("second"))
        msec_str = m_md.group("msec") or "0"
        microsecond = int(msec_str.ljust(6, "0")[:6])
        year = reference_date.year if reference_date else reference_year
        dt = datetime(year, month, day, hour, minute, second, microsecond)
        return dt, clean_raw

    # Check Time-only format (e.g. 10:15:22.632)
    m_time = TIME_ONLY_PATTERN.match(clean_raw)
    if m_time:
        if reference_date:
            hour = int(m_time.group("hour"))
            minute = int(m_time.group("minute"))
            second = int(m_time.group("second"))
            msec_str = m_time.group("msec") or "0"
            microsecond = int(msec_str.ljust(6, "0")[:6])
            dt = datetime(reference_date.year, reference_date.month, reference_date.day, hour, minute, second, microsecond)
            return dt, clean_raw
        return None, clean_raw

    return None, clean_raw


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Convert any datetime to a canonical timezone-aware UTC datetime."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_ist_display(dt: Optional[datetime], fallback: str = "N/A") -> str:
    """Convert canonical datetime to IST display string (e.g. '20-Sep-2026 15:42:31 IST').

    Uses Asia/Kolkata timezone with proper offset calculations without manual string math.
    """
    if dt is None:
        return fallback
    if dt.tzinfo is None:
        # Trace timestamps are recorded in UTC as defined in Cisco trace headers (UTC:+00:00)
        dt_utc = dt.replace(tzinfo=timezone.utc)
    else:
        dt_utc = dt.astimezone(timezone.utc)
    dt_ist = dt_utc.astimezone(IST_TZ)
    return dt_ist.strftime("%d-%b-%Y %H:%M:%S IST")


def format_time_range_ist(start_dt: Optional[datetime], end_dt: Optional[datetime], fallback: str = "N/A") -> str:
    """Format start and end datetimes into an IST range display."""
    if not start_dt and not end_dt:
        return fallback
    start_str = to_ist_display(start_dt, fallback="N/A")
    end_str = to_ist_display(end_dt, fallback="N/A")
    return f"{start_str} → {end_str}"
