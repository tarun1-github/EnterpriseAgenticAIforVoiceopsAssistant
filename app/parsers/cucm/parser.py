"""Initial deterministic parser for CUCM SDL/SDI trace lines."""

import re
from typing import Any, Dict, List, Optional
from app.core.logging import get_logger
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.base import BaseParser

logger = get_logger("parsers.cucm")

# CUCM line pattern:
# Example: 2026-09-19 14:22:01.123 |Process:StationInit(1,100,14,5)|...
CUCM_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*\|(?P<rest>.*)$"
)

# Common signal extractors in CUCM logs
PROCESS_PATTERN = re.compile(r"\|(?P<process>[A-Za-z0-9_]+(?:::msgData|:[A-Za-z0-9_]+)?)")
DEVICE_PATTERN = re.compile(r"\b(?P<device>SEP[0-9A-Fa-f]{12}|vg224\S*|CSF\S*|BOT\S*)\b")
CALLING_PATTERN = re.compile(r"(?:calling|callingPartyNumber|party1|callingNumber)[=\s:]+['\"]?(?P<num>\d+)['\"]?", re.IGNORECASE)
CALLED_PATTERN = re.compile(r"(?:called|calledPartyNumber|party2|calledNumber|pattern)[=\s:]+['\"]?(?P<num>\d+)['\"]?", re.IGNORECASE)
SIP_CALLID_PATTERN = re.compile(r"Call-ID:[=\s]+(?P<cid>\S+)", re.IGNORECASE)
CI_PATTERN = re.compile(r"\bCI=(?P<ci>\d+)\b")


class CUCMParser(BaseParser):
    """Initial parser for CUCM CallManager SDL/SDI trace events."""

    def parse(self, content: str, source: str = "unknown") -> List[VoiceEvent]:
        """Parse CUCM trace content into normalized VoiceEvent objects."""
        if not content:
            return []

        events: List[VoiceEvent] = []
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            event = self._parse_line(line_str, source)
            if event:
                events.append(event)

        logger.info("Parsed %d CUCM events from source '%s'", len(events), source)
        return events

    def _parse_line(self, line: str, source: str) -> Optional[VoiceEvent]:
        """Extract recognizable identifiers and event types from a single CUCM trace line."""
        m_ts = CUCM_TIMESTAMP_PATTERN.match(line)
        timestamp = m_ts.group("timestamp") if m_ts else None

        # Extract process or message type
        m_proc = PROCESS_PATTERN.search(line)
        msg_type = m_proc.group("process") if m_proc else "CUCM_LOG"

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

        metadata: Dict[str, Any] = {}
        if m_proc:
            metadata["cucm_process"] = m_proc.group("process")

        return VoiceEvent(
            timestamp=timestamp,
            timestamp_raw=timestamp,
            protocol=ProtocolEnum.CUCM,
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
