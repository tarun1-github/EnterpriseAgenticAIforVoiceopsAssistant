"""Core timestamp normalization utilities for Cisco voice traces."""

import re
from datetime import datetime
from typing import Optional, Tuple

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


def parse_cisco_timestamp(
    raw_ts: Optional[str],
    reference_year: int = 2026,
) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse Cisco trace timestamp into a normalized datetime and clean raw string.

    Args:
        raw_ts: Raw timestamp string from trace header.
        reference_year: Reference year to apply when trace provides month and day only.

    Returns:
        Tuple of (normalized_datetime_or_None, cleaned_raw_string).
        If only time is provided without date, datetime is None ("do not invent date").
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
        dt = datetime(reference_year, month, day, hour, minute, second, microsecond)
        return dt, clean_raw

    # Check Time-only format (e.g. 10:15:22.632)
    # Requirement: Do not invent the date if it is unavailable.
    m_time = TIME_ONLY_PATTERN.match(clean_raw)
    if m_time:
        return None, clean_raw

    return None, clean_raw
