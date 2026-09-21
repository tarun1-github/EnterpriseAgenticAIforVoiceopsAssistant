"""Normalizer utilities for CUCM SDL trace events and timestamps."""

import re
from datetime import date, datetime, timezone, timedelta
from typing import Optional, Tuple
from zoneinfo import ZoneInfo

IST_TZ = ZoneInfo("Asia/Kolkata")

SIP_SIGNALS = {
    "sippingreq", "sippingres", "siphandler", "sipd", "sipstationinit",
    "sipstationd", "sipcc", "invite", "bye", "ack", "cancel", "options",
    "200 ok", "180 ringing", "100 trying", "486 busy", "404 not found",
    "500 server internal error", "503 service unavailable", "sipmessage"
}

Q931_SIGNALS = {
    "ccsetupreq", "ccsetupind", "ccalertind", "ccalertreq", "ccconnectind",
    "ccconnectreq", "ccdisconnectind", "ccdisconnectreq", "ccreleaseind",
    "ccreleasereq", "ccreleasecomplete", "q931", "pridchannel", "layer3nl",
    "setup", "call proceeding", "alerting", "connect", "disconnect", "release"
}

MGCP_SIGNALS = {
    "mgcpnotify", "mgcpnotifyres", "mgcphandler", "mgcpinit", "mgcpmanager",
    "mgcpoctimer", "ntfy", "crcx", "mdcx", "dlcx", "rqnt", "auep", "aucx",
    "mgcp"
}

SCCP_SIGNALS = {
    "stationinit", "stationregister", "stationregisterreq", "stationregisterres",
    "stationoffhook", "stationonhook", "stationkeypad", "stationcallstate",
    "skinny", "stationd"
}


def parse_tz_offset(offset_str: str) -> timezone:
    """Parse a timezone offset string like 'UTC:+00:00', '+05:30', or '-04:00'."""
    if not offset_str:
        return timezone.utc

    clean = offset_str.strip().upper()
    if "UTC:" in clean:
        clean = clean.split("UTC:", 1)[1].strip()
    elif "UTC" in clean:
        clean = clean.replace("UTC", "").strip()

    m = re.match(r"^(?P<sign>[+-])(?P<hours>\d{1,2}):(?P<minutes>\d{2})$", clean)
    if m:
        hours = int(m.group("hours"))
        minutes = int(m.group("minutes"))
        sign = -1 if m.group("sign") == "-" else 1
        return timezone(sign * timedelta(hours=hours, minutes=minutes))

    return timezone.utc


def parse_filehead_metadata(header_line: str) -> Tuple[Optional[date], timezone, Optional[str]]:
    """Parse FileHead line to extract date, timezone offset, and CUCM host node.

    Example:
    00644027.000 |13:35:15.018 |FileHead |UTC:+00:00,Date: 2026/09/20, AppName: CCM, ..., HostName: UCM15-HQ-PUB...
    """
    ref_date = None
    tz = timezone.utc
    node = None

    if not header_line or "FileHead" not in header_line:
        return ref_date, tz, node

    # Extract UTC offset
    m_utc = re.search(r"UTC:\s*([+-]\d{2}:\d{2})", header_line, re.IGNORECASE)
    if m_utc:
        tz = parse_tz_offset(m_utc.group(1))

    # Extract Date
    m_date = re.search(r"Date:\s*(\d{4}[-/]\d{2}[-/]\d{2})", header_line, re.IGNORECASE)
    if m_date:
        d_str = m_date.group(1).replace("/", "-")
        parts = [int(p) for p in d_str.split("-")]
        ref_date = date(parts[0], parts[1], parts[2])

    # Extract HostName / Node
    m_host = re.search(r"HostName:\s*([^\s,]+)", header_line, re.IGNORECASE)
    if m_host:
        node = m_host.group(1).strip()

    return ref_date, tz, node


def normalize_cucm_timestamp(
    time_str: str,
    base_date: Optional[date] = None,
    tz: timezone = timezone.utc,
) -> datetime:
    """Convert CUCM time string (HH:MM:SS.mmm or full ISO) to timezone-aware datetime.

    Never creates a naive datetime. Defaults to base_date or current date if none provided.
    """
    clean = time_str.strip()
    target_date = base_date or date(2026, 9, 20)

    # Check full datetime format (YYYY-MM-DD HH:MM:SS.mmm)
    m_full = re.match(r"^(\d{4})[-/](\d{2})[-/](\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", clean)
    if m_full:
        year, month, day = int(m_full.group(1)), int(m_full.group(2)), int(m_full.group(3))
        h, mi, s = int(m_full.group(4)), int(m_full.group(5)), int(m_full.group(6))
        msec_str = m_full.group(7) or "0"
        us = int(msec_str.ljust(6, "0")[:6])
        return datetime(year, month, day, h, mi, s, us, tzinfo=tz)

    # Check time-only format (HH:MM:SS.mmm)
    m_time = re.match(r"^(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", clean)
    if m_time:
        h, mi, s = int(m_time.group(1)), int(m_time.group(2)), int(m_time.group(3))
        msec_str = m_time.group(4) or "0"
        us = int(msec_str.ljust(6, "0")[:6])
        return datetime(target_date.year, target_date.month, target_date.day, h, mi, s, us, tzinfo=tz)

    # Fallback to base date at 00:00:00
    return datetime(target_date.year, target_date.month, target_date.day, 0, 0, 0, tzinfo=tz)


def to_ist(dt: datetime) -> datetime:
    """Convert any timezone-aware or naive datetime to Asia/Kolkata (IST)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST_TZ)


def infer_protocol(signal: Optional[str], process: Optional[str], raw_text: str) -> str:
    """Infer protocol based on signal name, process name, and raw content."""
    sig_low = (signal or "").lower()
    proc_low = (process or "").lower()
    text_low = raw_text.lower()

    if any(s in sig_low or s in proc_low for s in SIP_SIGNALS) or "sip/2.0" in text_low:
        return "SIP"
    if any(s in sig_low or s in proc_low for s in Q931_SIGNALS) or "q931" in text_low:
        return "Q931"
    if any(s in sig_low or s in proc_low for s in MGCP_SIGNALS) or "mgcp 0.1" in text_low or "mgcp 1.0" in text_low:
        return "MGCP"
    if any(s in sig_low or s in proc_low for s in SCCP_SIGNALS) or "skinny" in text_low:
        return "SCCP"

    return "CUCM"


def infer_direction(raw_header: str, raw_text: str) -> str:
    """Determine signaling direction from trace tags and text."""
    if "[R:" in raw_header or "received msg from" in raw_text.lower():
        return "INBOUND"
    if "[T:" in raw_header or "send msg" in raw_text.lower() or "sending msg" in raw_text.lower():
        return "OUTBOUND"
    return "INTERNAL"
