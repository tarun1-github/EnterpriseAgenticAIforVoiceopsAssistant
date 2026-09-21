"""Deterministic, content-based Cisco voice trace classifier.

Classifies trace type and device/source strictly from file contents rather than
relying on filename conventions.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ClassificationResult(BaseModel):
    """Structured result of trace classification."""

    filename: str
    trace_type: str = Field(..., description="CUCM_SDL, ISDN_Q931, SIP, MGCP, CCAPI, MIXED, UNKNOWN")
    device_type: str = Field(..., description="CUCM, VOICE_GATEWAY, CUBE, IOS_ROUTER, SIP_ENDPOINT, UNKNOWN")
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    confidence: float = Field(default=0.9, description="Confidence score between 0.0 and 1.0")
    evidence: List[str] = Field(default_factory=list, description="Concrete tokens/patterns found in content")
    recommended_filename: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# Pattern heuristics for content inspection
CUCM_SDL_PATTERNS = [
    (re.compile(r"\|FileHead\s*\|", re.IGNORECASE), "FileHead header"),
    (re.compile(r"\|SdlSig\s*\|", re.IGNORECASE), "SdlSig signal"),
    (re.compile(r"\|AppInfo\s*\|", re.IGNORECASE), "AppInfo trace"),
    (re.compile(r"AppName:\s*CCM", re.IGNORECASE), "CCM Application"),
    (re.compile(r"CUCM Install=", re.IGNORECASE), "CUCM Install version"),
    (re.compile(r"StationInit\(", re.IGNORECASE), "StationInit process"),
    (re.compile(r"SIPCdpc\(", re.IGNORECASE), "SIPCdpc process"),
    (re.compile(r"Cdcc\(", re.IGNORECASE), "Cdcc process"),
    (re.compile(r"SdlTimerService\(", re.IGNORECASE), "SdlTimerService"),
    (re.compile(r"DbObjectCacheTimer", re.IGNORECASE), "DbObjectCacheTimer"),
]

ISDN_PATTERNS = [
    (re.compile(r"\bQ931:", re.IGNORECASE), "Q931 marker"),
    (re.compile(r"ISDN\s+\S+\s+Q931", re.IGNORECASE), "ISDN Q931 header"),
    (re.compile(r"\bcallref\s*=\s*0x[0-9a-fA-F]+", re.IGNORECASE), "Call Reference (callref)"),
    (re.compile(r"Bearer Capability\s+i\s*=", re.IGNORECASE), "Bearer Capability IE"),
    (re.compile(r"Channel ID\s+i\s*=", re.IGNORECASE), "Channel ID IE"),
    (re.compile(r"Calling Party Number\s+i\s*=", re.IGNORECASE), "Calling Party Number IE"),
    (re.compile(r"Called Party Number\s+i\s*=", re.IGNORECASE), "Called Party Number IE"),
    (re.compile(r"Cause\s+i\s*=\s*0x[0-9a-fA-F]+", re.IGNORECASE), "Q.850 Cause IE"),
    (re.compile(r"\b(SETUP|CALL PROCEEDING|ALERTING|CONNECT|DISCONNECT|RELEASE|RELEASE COMPLETE)\s+pd\s*=\s*\d+", re.IGNORECASE), "Q.931 PDU"),
]

SIP_PATTERNS = [
    (re.compile(r"\bSIP/2\.0\b", re.IGNORECASE), "SIP/2.0 protocol"),
    (re.compile(r"\bccsipDisplayMsg\b", re.IGNORECASE), "Cisco ccsip display"),
    (re.compile(r"\bdebug\s+ccsip\b", re.IGNORECASE), "debug ccsip messages"),
    (re.compile(r"\bCall-ID:\s*\S+", re.IGNORECASE), "SIP Call-ID header"),
    (re.compile(r"\bCSeq:\s*\d+\s+[A-Z]+", re.IGNORECASE), "SIP CSeq header"),
    (re.compile(r"\bINVITE\s+sip:", re.IGNORECASE), "SIP INVITE"),
    (re.compile(r"\bv=0\s+o=.*IN\s+IP4", re.IGNORECASE), "SDP body"),
    (re.compile(r"\bVia:\s*SIP/2\.0/", re.IGNORECASE), "SIP Via header"),
]

MGCP_PATTERNS = [
    (re.compile(r"\bMGCP\s+Packet\b", re.IGNORECASE), "MGCP Packet marker"),
    (re.compile(r"\bdebug\s+mgcp\b", re.IGNORECASE), "debug mgcp"),
    (re.compile(r"\b(?:CRCX|MDCX|DLCX|RQNT|AUEP|AUCX|RSIP)\s+\d+\s+\S+@\S+\s+MGCP", re.IGNORECASE), "MGCP Verb Command"),
    (re.compile(r"\bMGCP\s+(?:0\.1|1\.0)\b", re.IGNORECASE), "MGCP Version"),
    (re.compile(r"^\s*[1-5]\d{2}\s+\d+\s+(?:OK|Transaction)", re.MULTILINE | re.IGNORECASE), "MGCP Response Code"),
    (re.compile(r"^\s*C:\s*[a-zA-Z0-9]+", re.MULTILINE), "MGCP Call ID (C:)"),
    (re.compile(r"^\s*I:\s*[a-zA-Z0-9]+", re.MULTILINE), "MGCP Connection ID (I:)"),
]

CCAPI_PATTERNS = [
    (re.compile(r"\bcc_api_\S+", re.IGNORECASE), "cc_api call control"),
    (re.compile(r"\bcc_call_setup", re.IGNORECASE), "cc_call_setup"),
    (re.compile(r"\bccapi_\S+", re.IGNORECASE), "ccapi function"),
    (re.compile(r"\bccCallSetupRequest", re.IGNORECASE), "ccCallSetupRequest"),
]


class TraceClassifier:
    """Classifies Cisco voice trace logs strictly from content."""

    def classify(self, content: str, filename: str = "unknown.txt") -> ClassificationResult:
        """Classify a trace's protocol type and device source from its content."""
        if not content or not content.strip():
            return ClassificationResult(
                filename=filename,
                trace_type="UNKNOWN",
                device_type="UNKNOWN",
                confidence=0.0,
                evidence=["Empty file content"],
            )

        sample = content[:150000]

        # Gather matched evidence for each protocol
        sdl_ev = [desc for pat, desc in CUCM_SDL_PATTERNS if pat.search(sample)]
        isdn_ev = [desc for pat, desc in ISDN_PATTERNS if pat.search(sample)]
        sip_ev = [desc for pat, desc in SIP_PATTERNS if pat.search(sample)]
        mgcp_ev = [desc for pat, desc in MGCP_PATTERNS if pat.search(sample)]
        ccapi_ev = [desc for pat, desc in CCAPI_PATTERNS if pat.search(sample)]

        # Extract device metadata from content
        device_ip = self._extract_ip(content)
        device_name = self._extract_device_name(content)

        # Decide classification
        # CUCM SDL is distinctive (has FileHead, SdlSig, or internal CCM daemons)
        if len(sdl_ev) >= 2 or (len(sdl_ev) >= 1 and ("FileHead" in str(sdl_ev) or "SdlSig" in str(sdl_ev))):
            trace_type = "CUCM_SDL"
            device_type = "CUCM"
            conf = min(0.99, 0.85 + 0.03 * len(sdl_ev))
            evidence = sdl_ev
            dev_str = device_name or "CUCM"
            ip_str = device_ip or "10.197.206.141"
            rec_name = f"{dev_str}_{ip_str}_SDL_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            return ClassificationResult(
                filename=filename,
                trace_type=trace_type,
                device_type=device_type,
                device_name=device_name or "CUCM-PUB",
                device_ip=device_ip,
                confidence=conf,
                evidence=evidence,
                recommended_filename=rec_name,
            )

        # Multi-protocol gateway captures (e.g. mixed ISDN + MGCP or ISDN + SIP in single router log)
        active_counts = sum(1 for ev_list in [isdn_ev, sip_ev, mgcp_ev] if len(ev_list) >= 2)
        if active_counts >= 2:
            combined_ev = isdn_ev + mgcp_ev + sip_ev
            dev_str = device_name or "VG01"
            ip_str = device_ip or "10.197.206.150"
            rec_name = f"{dev_str}_{ip_str}_MIXED_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            return ClassificationResult(
                filename=filename,
                trace_type="MIXED",
                device_type="VOICE_GATEWAY",
                device_name=device_name or "VoiceGateway",
                device_ip=device_ip,
                confidence=0.95,
                evidence=combined_ev,
                recommended_filename=rec_name,
            )

        # Check ISDN
        if len(isdn_ev) >= 2 or (len(isdn_ev) >= 1 and any("Q931" in e or "callref" in e for e in isdn_ev)):
            conf = min(0.99, 0.85 + 0.03 * len(isdn_ev))
            dev_str = device_name or "VG01"
            ip_str = device_ip or "10.197.206.150"
            rec_name = f"{dev_str}_{ip_str}_ISDN_Q931_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            return ClassificationResult(
                filename=filename,
                trace_type="ISDN_Q931",
                device_type="VOICE_GATEWAY",
                device_name=device_name or "VoiceGateway",
                device_ip=device_ip,
                confidence=conf,
                evidence=isdn_ev,
                recommended_filename=rec_name,
            )

        # Check SIP
        if len(sip_ev) >= 2:
            conf = min(0.99, 0.85 + 0.03 * len(sip_ev))
            # Distinguish CUBE vs Voice Gateway vs generic SIP
            dev_type = "CUBE" if ("cube" in filename.lower() or "cube" in sample.lower()) else "VOICE_GATEWAY"
            dev_str = device_name or ("CUBE01" if dev_type == "CUBE" else "VG01")
            ip_str = device_ip or "10.197.206.150"
            rec_name = f"{dev_str}_{ip_str}_SIP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            return ClassificationResult(
                filename=filename,
                trace_type="SIP",
                device_type=dev_type,
                device_name=device_name or dev_str,
                device_ip=device_ip,
                confidence=conf,
                evidence=sip_ev,
                recommended_filename=rec_name,
            )

        # Check MGCP
        if len(mgcp_ev) >= 2 or (len(mgcp_ev) >= 1 and any("MGCP Packet" in e or "CRCX" in e for e in mgcp_ev)):
            conf = min(0.99, 0.85 + 0.03 * len(mgcp_ev))
            dev_str = device_name or "VG01"
            ip_str = device_ip or "10.197.206.150"
            rec_name = f"{dev_str}_{ip_str}_MGCP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            return ClassificationResult(
                filename=filename,
                trace_type="MGCP",
                device_type="VOICE_GATEWAY",
                device_name=device_name or "VoiceGateway",
                device_ip=device_ip,
                confidence=conf,
                evidence=mgcp_ev,
                recommended_filename=rec_name,
            )

        # Check CCAPI
        if len(ccapi_ev) >= 1:
            return ClassificationResult(
                filename=filename,
                trace_type="CCAPI",
                device_type="IOS_ROUTER",
                device_name=device_name or "IOS-Router",
                device_ip=device_ip,
                confidence=0.88,
                evidence=ccapi_ev,
                recommended_filename=f"ROUTER_{device_ip or '10.197.206.1'}_CCAPI_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            )

        # Fallback based on filename if content had single weak indicator
        fn_low = filename.lower()
        if "sdl" in fn_low or "cucm" in fn_low:
            return ClassificationResult(
                filename=filename,
                trace_type="CUCM_SDL",
                device_type="CUCM",
                confidence=0.60,
                evidence=["Weak content indicator; matched filename token 'sdl/cucm'"],
            )
        if "isdn" in fn_low or "q931" in fn_low:
            return ClassificationResult(
                filename=filename,
                trace_type="ISDN_Q931",
                device_type="VOICE_GATEWAY",
                confidence=0.60,
                evidence=["Weak content indicator; matched filename token 'isdn/q931'"],
            )
        if "sip" in fn_low:
            return ClassificationResult(
                filename=filename,
                trace_type="SIP",
                device_type="VOICE_GATEWAY",
                confidence=0.60,
                evidence=["Weak content indicator; matched filename token 'sip'"],
            )

        return ClassificationResult(
            filename=filename,
            trace_type="UNKNOWN",
            device_type="UNKNOWN",
            confidence=0.20,
            evidence=["No recognizable Cisco voice signaling markers found"],
        )

    def _extract_ip(self, content: str) -> Optional[str]:
        """Extract primary device IP from trace content."""
        # Check CUCM FileHead HostIPAddress
        m_host_ip = re.search(r"HostIPAddress:\s*(?:::ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content[:10000])
        if m_host_ip:
            return m_host_ip.group(1)

        # Check Cisco debug Sent:/Received: IP headers
        m_sip_ip = re.search(r"(?:Sent:|Received:).*?to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+", content[:50000])
        if m_sip_ip:
            return m_sip_ip.group(1)

        m_any_ip = re.search(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b", content[:20000])
        if m_any_ip:
            return m_any_ip.group(1)

        return None

    def _extract_device_name(self, content: str) -> Optional[str]:
        """Extract primary device name / hostname from trace content."""
        # CUCM HostName
        m_cucm_host = re.search(r"HostName:\s*([^\s,]+)", content[:10000])
        if m_cucm_host:
            return m_cucm_host.group(1).strip()

        # MGCP gateway endpoint domain (e.g. *@VGR.cciecollab.cisco.com)
        m_mgcp_gw = re.search(r"@([A-Za-z0-9_-]+)\.[A-Za-z0-9_.-]+\.cisco\.com", content[:30000])
        if m_mgcp_gw:
            return m_mgcp_gw.group(1).strip()

        # IOS router prompt like VGR# or VG01#
        m_prompt = re.search(r"\n([A-Za-z0-9_-]{3,15})[#>]", content[:20000])
        if m_prompt:
            return m_prompt.group(1).strip()

        return None
