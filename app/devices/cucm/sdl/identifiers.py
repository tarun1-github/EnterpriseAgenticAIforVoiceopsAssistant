"""Deterministic extractors for CUCM SDL correlation identifiers."""

import re
from typing import Any, Dict, Optional

# Regular expressions for CUCM SDL identifiers
CI_PATTERN = re.compile(r"\b(?:CI|ci)[=\s:]+([0-9]{3,12})\b")
CDCC_PATTERN = re.compile(r"\b(?:cdcc|CDCC)[=\s:]+([0-9]{3,12})\b")
CDCC_PROC_PATTERN = re.compile(r"Cdcc\((?P<proc>\d+,\d+,\d+,\d+)\)")
SIP_CALLID_PATTERN = re.compile(r"\b(?:Call-ID|call-id|callId|CallId)[=\s:]+([^\s,;]+)", re.IGNORECASE)
CCBID_PATTERN = re.compile(r"\bccbID[=\s:]+([0-9]+)\b", re.IGNORECASE)
APPCORR_PATTERN = re.compile(r"\bAppCorr[=\s:]+([0-9]+)\b", re.IGNORECASE)
TCP_HANDLE_PATTERN = re.compile(r"\b(?:tcpHandle|tcphandle)[=\s:]+([0-9]+)\b", re.IGNORECASE)

CALLING_PATTERNS = [
    re.compile(r"(?:callingPartyNumber|callingNumber|callingParty|calling)[=\s:]+['\"]?(\+?[0-9*#]{3,20})['\"]?", re.IGNORECASE),
    re.compile(r"\bparty1[=\s:]+['\"]?(\+?[0-9*#]{3,20})['\"]?", re.IGNORECASE),
    re.compile(r"From:\s*(?:\"[^\"]*\"|[^\r\n<]*?)?<\s*sip:(\+?[0-9*#]{3,20})@", re.IGNORECASE),
]

CALLED_PATTERNS = [
    re.compile(r"(?:calledPartyNumber|calledNumber|calledParty|called|finalCalledPartyNumber)[=\s:]+['\"]?(\+?[0-9*#]{3,20})['\"]?", re.IGNORECASE),
    re.compile(r"\bparty2[=\s:]+['\"]?(\+?[0-9*#]{3,20})['\"]?", re.IGNORECASE),
    re.compile(r"To:\s*(?:\"[^\"]*\"|[^\r\n<]*?)?<\s*sip:(\+?[0-9*#]{3,20})@", re.IGNORECASE),
    re.compile(r"\bINVITE\s+sip:(\+?[0-9*#]{3,20})@", re.IGNORECASE),
    re.compile(r"\bpattern[=\s:]+['\"]?(\+?[0-9*#]{3,20})['\"]?", re.IGNORECASE),
]

DEVICE_PATTERN = re.compile(
    r"\b(SEP[0-9A-Fa-f]{12}|vg224\S*|CSF[A-Za-z0-9_.-]+|BOT[A-Za-z0-9_.-]+|TAB[A-Za-z0-9_.-]+|\*?@?[A-Za-z0-9_.-]+\.cisco\.com)\b"
)
IP_PATTERN = re.compile(r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")


def extract_ci(text: str) -> Optional[str]:
    """Extract CUCM Call Identification (CI)."""
    m = CI_PATTERN.search(text)
    return m.group(1) if m else None


def extract_cdcc(text: str) -> Optional[str]:
    """Extract CDCC identifier or process handle."""
    m = CDCC_PATTERN.search(text)
    if m:
        return m.group(1)
    m2 = CDCC_PROC_PATTERN.search(text)
    if m2:
        return m2.group("proc")
    return None


def extract_call_id(text: str) -> Optional[str]:
    """Extract SIP or protocol Call-ID."""
    m = SIP_CALLID_PATTERN.search(text)
    return m.group(1) if m else None


def extract_calling_number(text: str) -> Optional[str]:
    """Extract calling phone number (ANI)."""
    for pat in CALLING_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1).strip()
    return None


def extract_called_number(text: str) -> Optional[str]:
    """Extract called phone number (DNIS)."""
    for pat in CALLED_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1).strip()
    return None


def extract_device(text: str) -> Optional[str]:
    """Extract endpoint or trunk device name."""
    m = DEVICE_PATTERN.search(text)
    return m.group(1) if m else None


def extract_ip_address(text: str) -> Optional[str]:
    """Extract IPv4 address."""
    m = IP_PATTERN.search(text)
    return m.group(0) if m else None


def extract_all_identifiers(text: str) -> Dict[str, Any]:
    """Extract all recognizable identifiers from trace text."""
    result: Dict[str, Any] = {}

    ci = extract_ci(text)
    if ci:
        result["ci"] = ci

    cdcc = extract_cdcc(text)
    if cdcc:
        result["cdcc"] = cdcc

    cid = extract_call_id(text)
    if cid:
        result["call_id"] = cid

    calling = extract_calling_number(text)
    if calling:
        result["calling_number"] = calling

    called = extract_called_number(text)
    if called:
        result["called_number"] = called

    dev = extract_device(text)
    if dev:
        result["device"] = dev

    ip = extract_ip_address(text)
    if ip:
        result["ip_address"] = ip

    m_ccb = CCBID_PATTERN.search(text)
    if m_ccb:
        result["ccb_id"] = m_ccb.group(1)

    m_appcorr = APPCORR_PATTERN.search(text)
    if m_appcorr:
        result["app_corr"] = m_appcorr.group(1)

    m_tcp = TCP_HANDLE_PATTERN.search(text)
    if m_tcp:
        result["tcp_handle"] = m_tcp.group(1)

    return result
