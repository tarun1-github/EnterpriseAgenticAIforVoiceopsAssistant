"""Heuristic protocol detection engine for Cisco voice trace files and segments."""

import re
from typing import List
from app.models.event import ProtocolEnum

# Pattern weighting heuristics
ISDN_PATTERNS = [
    re.compile(r"Q931:", re.IGNORECASE),
    re.compile(r"ISDN\s+\S+\s+Q931", re.IGNORECASE),
    re.compile(r"callref\s*=\s*0x[0-9a-fA-F]+", re.IGNORECASE),
    re.compile(r"Bearer Capability\s+i\s*=", re.IGNORECASE),
    re.compile(r"Calling Party Number\s+i\s*=", re.IGNORECASE),
    re.compile(r"Called Party Number\s+i\s*=", re.IGNORECASE),
    re.compile(r"Cause\s+i\s*=\s*0x[0-9a-fA-F]+", re.IGNORECASE),
]

SIP_PATTERNS = [
    re.compile(r"SIP/2\.0", re.IGNORECASE),
    re.compile(r"ccsipDisplayMsg", re.IGNORECASE),
    re.compile(r"debug\s+ccsip", re.IGNORECASE),
    re.compile(r"Call-ID:\s*\S+", re.IGNORECASE),
    re.compile(r"CSeq:\s*\d+\s+[A-Z]+", re.IGNORECASE),
    re.compile(r"INVITE\s+sip:", re.IGNORECASE),
    re.compile(r"v=0\s+o=.*IN\s+IP4", re.IGNORECASE),
]

MGCP_PATTERNS = [
    re.compile(r"MGCP\s+Packet", re.IGNORECASE),
    re.compile(r"debug\s+mgcp", re.IGNORECASE),
    re.compile(r"(?:CRCX|MDCX|DLCX|RQNT|AUEP|AUCX|RSIP)\s+\d+\s+\S+@\S+\s+MGCP", re.IGNORECASE),
    re.compile(r"MGCP\s+(?:0\.1|1\.0)", re.IGNORECASE),
    re.compile(r"^[1-5]\d{2}\s+\d+\s+(?:OK|Transaction)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*C:\s*[a-zA-Z0-9]+", re.MULTILINE),
    re.compile(r"^\s*I:\s*[a-zA-Z0-9]+", re.MULTILINE),
]

CUCM_PATTERNS = [
    re.compile(r"\|StationInit:", re.IGNORECASE),
    re.compile(r"\|CC\|", re.IGNORECASE),
    re.compile(r"Layer3NL::msgData", re.IGNORECASE),
    re.compile(r"Digit Analysis:", re.IGNORECASE),
    re.compile(r"StationD:", re.IGNORECASE),
    re.compile(r"SDL_Process", re.IGNORECASE),
]


def detect_protocol(content: str) -> ProtocolEnum:
    """Analyze raw trace content and detect the primary protocol using heuristic scoring.

    Args:
        content: Raw text content from trace file.

    Returns:
        Detected ProtocolEnum (ISDN, SIP, MGCP, CUCM, or UNKNOWN).
    """
    if not content or not content.strip():
        return ProtocolEnum.UNKNOWN

    sample = content[:100000]

    scores = {
        ProtocolEnum.ISDN: sum(1 for p in ISDN_PATTERNS if p.search(sample)),
        ProtocolEnum.SIP: sum(1 for p in SIP_PATTERNS if p.search(sample)),
        ProtocolEnum.MGCP: sum(1 for p in MGCP_PATTERNS if p.search(sample)),
        ProtocolEnum.CUCM: sum(1 for p in CUCM_PATTERNS if p.search(sample)),
    }

    best_protocol, highest_score = max(scores.items(), key=lambda item: item[1])

    if highest_score >= 1:
        return best_protocol

    return ProtocolEnum.UNKNOWN


def detect_segment_protocol(block: str) -> ProtocolEnum:
    """Detect the protocol of a discrete message block or log segment.

    Args:
        block: Raw message block text or line.

    Returns:
        Detected ProtocolEnum for this segment.
    """
    if not block or not block.strip():
        return ProtocolEnum.UNKNOWN

    # Check ISDN markers
    if re.search(r"Q931:|ISDN\s+\S+\s+Q931|callref\s*=\s*0x", block, re.IGNORECASE):
        return ProtocolEnum.ISDN

    # Check MGCP markers
    if re.search(
        r"MGCP\s+Packet|(?:CRCX|MDCX|DLCX|RQNT|AUEP|AUCX|RSIP)\s+\d+|[1-5]\d{2}\s+\d+\s+OK|MGCP\s+[0-9\.]+",
        block,
        re.IGNORECASE,
    ):
        return ProtocolEnum.MGCP

    # Check SIP markers
    if re.search(r"SIP/2\.0|ccsipDisplayMsg|Call-ID:|CSeq:|INVITE\s+sip:", block, re.IGNORECASE):
        return ProtocolEnum.SIP

    # Check CUCM markers
    if re.search(r"\|StationInit:|\|CC\||Layer3NL::|Digit Analysis:", block, re.IGNORECASE):
        return ProtocolEnum.CUCM

    return ProtocolEnum.UNKNOWN


def detect_multiple_protocols(content: str) -> List[ProtocolEnum]:
    """Detect all signaling protocols present in a mixed trace file."""
    sample = content[:200000]
    present = []
    if any(p.search(sample) for p in ISDN_PATTERNS):
        present.append(ProtocolEnum.ISDN)
    if any(p.search(sample) for p in SIP_PATTERNS):
        present.append(ProtocolEnum.SIP)
    if any(p.search(sample) for p in MGCP_PATTERNS):
        present.append(ProtocolEnum.MGCP)
    if any(p.search(sample) for p in CUCM_PATTERNS):
        present.append(ProtocolEnum.CUCM)
    return present
