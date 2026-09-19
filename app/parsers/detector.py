"""Heuristic protocol detection engine for Cisco voice trace files."""

import re
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
    re.compile(r"^C:\s*[a-zA-Z0-9]+", re.MULTILINE),
    re.compile(r"^I:\s*[a-zA-Z0-9]+", re.MULTILINE),
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

    # Sample the first 100,000 characters for fast heuristic evaluation
    sample = content[:100000]

    scores = {
        ProtocolEnum.ISDN: sum(1 for p in ISDN_PATTERNS if p.search(sample)),
        ProtocolEnum.SIP: sum(1 for p in SIP_PATTERNS if p.search(sample)),
        ProtocolEnum.MGCP: sum(1 for p in MGCP_PATTERNS if p.search(sample)),
        ProtocolEnum.CUCM: sum(1 for p in CUCM_PATTERNS if p.search(sample)),
    }

    # Find highest score
    best_protocol, highest_score = max(scores.items(), key=lambda item: item[1])

    if highest_score >= 1:
        return best_protocol

    return ProtocolEnum.UNKNOWN
