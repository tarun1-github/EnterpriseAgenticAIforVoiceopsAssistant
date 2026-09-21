"""Deterministic parser for Cisco ISDN / Q.931 debug traces."""

import re
from typing import Any, Dict, List, Optional
from app.core.logging import get_logger
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.base import BaseParser

logger = get_logger("parsers.isdn")

# Normalized mapping for Cisco debug message names to standard Q.931 terms
Q931_NORMALIZATION = {
    "CALL_PROC": "CALL PROCEEDING",
    "CONNECT_ACK": "CONNECT ACKNOWLEDGE",
    "RELEASE_COMP": "RELEASE COMPLETE",
    "STATUS_ENQ": "STATUS ENQUIRY",
    "RESTART_ACK": "RESTART ACKNOWLEDGE",
}

# Regex to detect start of an ISDN Q.931 message block
# Example: *Sep 19 14:22:01.123: ISDN Se0/2/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0082
ISDN_HEADER_PATTERN = re.compile(
    r"^(?:(?P<seq>\d+):\s+)?"
    r"(?:\*(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:(?:\s+[A-Z]{3,4})|(?::))?)\s+)?"
    r"(?:ISDN\s+)?(?P<interface>\S+)\s+Q931:\s+"
    r"(?P<direction>RX\s*<-|TX\s*->|RX|TX)\s+"
    r"(?P<msg_type>[A-Za-z0-9_]+)"
    r"(?:\s+pd\s*=\s*(?P<pd>\d+))?"
    r"(?:\s+callref\s*=\s*(?P<callref>0x[0-9a-fA-F]+|\d+))?",
    re.IGNORECASE,
)

ISDN_FLEXIBLE_PATTERN = re.compile(
    r"(?:ISDN\s+(?:Q\.?931\s+)?|Q931:\s+)"
    r"(?:(?P<direction>RX\s*<-|TX\s*->|RX|TX|INBOUND|OUTBOUND)[\s<>-]*)?"
    r"(?P<msg_type>SETUP|CALL_PROC(?:EEDING)?|ALERTING|CONNECT(?:_ACK)?|DISCONNECT|RELEASE(?:_COMP(?:LETE)?)?|STATUS(?:_ENQ(?:UIRY)?)?|NOTIFY|PROGRESS|FACILITY)"
    r"(?:.*?(?:cr|callref)\s*=\s*(?P<callref>0x[0-9a-fA-F]+|\d+))?",
    re.IGNORECASE,
)

# IE extraction patterns
CALLING_NUM_PATTERN = re.compile(
    r"Calling\s+Party\s+Number(?:\s+i\s*=[^,\n\r]+)?,\s*'([^']+)'",
    re.IGNORECASE,
)
CALLED_NUM_PATTERN = re.compile(
    r"Called\s+Party\s+Number(?:\s+i\s*=[^,\n\r]+)?,\s*'([^']+)'",
    re.IGNORECASE,
)
CAUSE_PATTERN = re.compile(
    r"Cause\s+i\s*=\s*(0x[0-9a-fA-F]+(?:\s*-\s*[^\r\n]+)?)",
    re.IGNORECASE,
)
CHANNEL_PATTERN = re.compile(
    r"Channel\s+ID\s+i\s*=\s*(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
CHANNEL_NUM_PATTERN = re.compile(
    r"(?:Exclusive,\s*)?(?:Channel|B-channel)\s+(\d+)",
    re.IGNORECASE,
)
BEARER_CAP_PATTERN = re.compile(
    r"Bearer\s+Capability\s+i\s*=\s*(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)


class ISDNParser(BaseParser):
    """Deterministic parser for Cisco Q.931 PRI/BRI signaling traces."""

    def parse(self, content: str, source: str = "unknown") -> List[VoiceEvent]:
        """Parse raw trace content into normalized VoiceEvent objects."""
        if not content:
            return []

        events: List[VoiceEvent] = []
        lines = content.splitlines()

        current_header_match = None
        current_block_lines: List[str] = []

        for line in lines:
            line_s = line.strip()
            header_match = ISDN_HEADER_PATTERN.search(line_s) or ISDN_FLEXIBLE_PATTERN.search(line_s)
            if header_match:
                # If we were already collecting a message block, process it now
                if current_header_match:
                    event = self._build_event(current_header_match, current_block_lines, source)
                    if event:
                        events.append(event)

                current_header_match = header_match
                current_block_lines = [line]
            else:
                if current_header_match:
                    current_block_lines.append(line)

        # Process the final block
        if current_header_match:
            event = self._build_event(current_header_match, current_block_lines, source)
            if event:
                events.append(event)

        logger.info("Parsed %d ISDN events from source '%s'", len(events), source)
        return events

    def _build_event(
        self,
        header_match: re.Match,
        block_lines: List[str],
        source: str,
    ) -> Optional[VoiceEvent]:
        """Extract structured fields from header and message block lines."""
        raw_block = "\n".join(block_lines)
        gdict = header_match.groupdict()

        raw_timestamp = gdict.get("timestamp")
        timestamp_clean = raw_timestamp.strip(": ") if raw_timestamp else None

        interface = gdict.get("interface")
        raw_dir = (gdict.get("direction") or "").upper()
        raw_msg_type = (gdict.get("msg_type") or "Q931_EVENT").upper()
        callref = gdict.get("callref")
        pd = gdict.get("pd")

        # Normalize direction
        direction = DirectionEnum.UNKNOWN
        if "RX" in raw_dir or "<-" in raw_dir or "INBOUND" in raw_dir:
            direction = DirectionEnum.INBOUND
        elif "TX" in raw_dir or "->" in raw_dir or "OUTBOUND" in raw_dir:
            direction = DirectionEnum.OUTBOUND

        # Normalize message type
        msg_type = Q931_NORMALIZATION.get(raw_msg_type, raw_msg_type)

        # Extract Information Elements from body lines
        calling_number = None
        called_number = None
        cause_code = None
        channel_id = None
        channel_num = None
        bearer_cap = None

        m_calling = CALLING_NUM_PATTERN.search(raw_block)
        if m_calling:
            calling_number = m_calling.group(1).strip()

        m_called = CALLED_NUM_PATTERN.search(raw_block)
        if m_called:
            called_number = m_called.group(1).strip()

        m_cause = CAUSE_PATTERN.search(raw_block)
        if m_cause:
            cause_code = m_cause.group(1).strip()

        m_chan = CHANNEL_PATTERN.search(raw_block)
        if m_chan:
            channel_id = m_chan.group(1).strip()

        m_chan_num = CHANNEL_NUM_PATTERN.search(raw_block)
        if m_chan_num:
            channel_num = m_chan_num.group(1).strip()

        m_bearer = BEARER_CAP_PATTERN.search(raw_block)
        if m_bearer:
            bearer_cap = m_bearer.group(1).strip()

        metadata: Dict[str, Any] = {
            "protocol_discriminator": pd,
            "raw_message_type": raw_msg_type,
        }
        if channel_id:
            metadata["channel_id"] = channel_id
        if channel_num:
            metadata["b_channel"] = channel_num
        if bearer_cap:
            metadata["bearer_capability"] = bearer_cap

        return VoiceEvent(
            timestamp=timestamp_clean,
            timestamp_raw=raw_timestamp,
            protocol=ProtocolEnum.ISDN,
            direction=direction,
            source=source,
            interface=interface,
            message_type=msg_type,
            call_reference=callref,
            calling_number=calling_number,
            called_number=called_number,
            cause_code=cause_code,
            raw=raw_block,
            metadata=metadata,
        )
