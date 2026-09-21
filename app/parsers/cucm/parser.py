"""Deterministic parser for CUCM SDL/SDI trace lines."""

import re
from datetime import date
from typing import Any, Dict, List, Optional
from app.core.logging import get_logger
from app.core.timestamps import parse_cisco_timestamp, parse_date_from_file_head
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.base import BaseParser

logger = get_logger("parsers.cucm")

# CUCM line pattern: supports both standard Cisco logs and sequence-prefixed SDL logs
# Example 1: 2026-09-19 14:22:01.123 |Process:StationInit(1,100,14,5)|...
# Example 2: 00602803.000 |08:52:24.482 |SdlSig |DbObjectCacheTimer |...
CUCM_TIMESTAMP_PATTERN = re.compile(
    r"^(?:(?P<seq>\d+\.\d+)\s*\|)?\s*(?P<timestamp>(?:\d{4}[-/]\d{2}[-/]\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*\|(?P<type>[^|]+)\s*\|(?P<rest>.*)$"
)

# Common signal extractors in CUCM logs
PROCESS_PATTERN = re.compile(r"\|(?P<process>[A-Za-z0-9_]+(?:::msgData|:[A-Za-z0-9_]+)?)")
DEVICE_PATTERN = re.compile(r"\b(?P<device>SEP[0-9A-Fa-f]{12}|vg224\S*|CSF\S*|BOT\S*)\b")
CALLING_PATTERN = re.compile(r"(?:calling|callingPartyNumber|party1|callingNumber)[=\s:]+['\"]?(?P<num>\d+)['\"]?", re.IGNORECASE)
CALLED_PATTERN = re.compile(r"(?:called|calledPartyNumber|party2|calledNumber|pattern)[=\s:]+['\"]?(?P<num>\d+)['\"]?", re.IGNORECASE)
SIP_CALLID_PATTERN = re.compile(r"Call-ID:[=\s]+(?P<cid>\S+)", re.IGNORECASE)
CI_PATTERN = re.compile(r"\bCI=(?P<ci>\d+)\b")
APP_CORR_PATTERN = re.compile(r"\bAppCorr:\s*(?P<tag>\d+)\b")
CCBID_PATTERN = re.compile(r"\bccbID=\s*(?P<id>\d+)\b")


class CUCMParser(BaseParser):
    """Parser for CUCM CallManager SDL/SDI trace events."""

    def parse(self, content: str, source: str = "unknown") -> List[VoiceEvent]:
        """Parse CUCM trace content into normalized VoiceEvent objects."""
        if not content:
            return []

        # Detect base date declared in FileHead or file header
        ref_date = parse_date_from_file_head(content)
        if ref_date:
            logger.info("Found base date %s from header in source '%s'", ref_date, source)

        events: List[VoiceEvent] = []
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            event = self._parse_line(line_str, source, ref_date)
            if event:
                events.append(event)

        logger.info("Parsed %d CUCM events from source '%s'", len(events), source)
        return events

    def _parse_line(self, line: str, source: str, ref_date: Optional[date] = None) -> Optional[VoiceEvent]:
        """Extract recognizable identifiers and event types from a single CUCM trace line."""
        m_ts = CUCM_TIMESTAMP_PATTERN.match(line)
        raw_ts = m_ts.group("timestamp") if m_ts else None
        line_type = m_ts.group("type").strip() if m_ts else None
        rest = m_ts.group("rest") if m_ts else line

        dt = None
        clean_raw = raw_ts
        if raw_ts:
            dt, clean_raw = parse_cisco_timestamp(raw_ts, reference_date=ref_date)

        # Extract process or message type
        metadata: Dict[str, Any] = {"source_file": source}
        if m_ts and m_ts.group("seq"):
            metadata["sequence_num"] = m_ts.group("seq")

        msg_type = "CUCM_LOG"
        protocol = ProtocolEnum.CUCM

        if line_type:
            metadata["trace_type"] = line_type
            if line_type.startswith("SdlSig"):
                # Parse SdlSig pipe fields: signal_name | state | receiving | sending | ids | params
                parts = [p.strip() for p in rest.split("|")]
                if parts:
                    signal_name = parts[0]
                    msg_type = signal_name
                    metadata["signal"] = signal_name
                if len(parts) > 1:
                    metadata["state"] = parts[1]
                if len(parts) > 2:
                    metadata["receiving_process"] = parts[2]
                if len(parts) > 3:
                    metadata["sending_process"] = parts[3]

                # Check if signal is an embedded ISDN/Q.931 event
                sig_lower = (msg_type or "").lower()
                if any(x in sig_lower for x in ["ccsetup", "q931", "pridchannel", "layer3nl", "isdn"]):
                    protocol = ProtocolEnum.ISDN
            elif line_type.startswith("AppInfo"):
                # Extract first word / token from rest as message type
                parts = rest.split(None, 2)
                msg_type = parts[0] if parts else "AppInfo"
                metadata["app_info"] = rest
            else:
                msg_type = line_type

        m_proc = PROCESS_PATTERN.search(line)
        if m_proc:
            metadata["cucm_process"] = m_proc.group("process")
            if msg_type == "CUCM_LOG":
                msg_type = m_proc.group("process")

        # Calling / Called party
        calling_num = None
        m_calling = CALLING_PATTERN.search(line)
        if m_calling:
            calling_num = m_calling.group("num")

        called_num = None
        m_called = CALLED_PATTERN.search(line)
        if m_called:
            called_num = m_called.group("num")

        # Device
        device = None
        m_dev = DEVICE_PATTERN.search(line)
        if m_dev:
            device = m_dev.group("device")

        # Call-ID
        call_id = None
        m_cid = SIP_CALLID_PATTERN.search(line)
        if m_cid:
            call_id = m_cid.group("cid").strip(";")

        # Connection / Call Identifier
        call_ref = None
        m_ci = CI_PATTERN.search(line)
        if m_ci:
            call_ref = f"CI_{m_ci.group('ci')}"
            metadata["call_id_ci"] = m_ci.group("ci")

        m_tag = APP_CORR_PATTERN.search(line)
        if m_tag:
            metadata["correlation_tag"] = m_tag.group("tag")

        m_ccb = CCBID_PATTERN.search(line)
        if m_ccb:
            metadata["ccb_id"] = m_ccb.group("id")

        return VoiceEvent(
            timestamp=dt,
            timestamp_raw=clean_raw,
            protocol=protocol,
            direction=DirectionEnum.INTERNAL,
            source=source,
            message_type=msg_type,
            call_reference=call_ref,
            call_id=call_id,
            calling_number=calling_num,
            called_number=called_num,
            device=device,
            raw=line,
            metadata=metadata,
        )
