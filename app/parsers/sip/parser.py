"""Deterministic parser for Cisco SIP debug traces and SIP message exchanges."""

import re
from typing import Any, Dict, List, Optional
from app.core.logging import get_logger
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.base import BaseParser

logger = get_logger("parsers.sip")

# Cisco debug banner line
# Example: *Sep 19 14:22:01.180: //123/A1B2C3D4E5F6/SIP/Msg/ccsipDisplayMsg:
CISCO_SIP_BANNER = re.compile(
    r"(?:\*(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?):\s+)?.*ccsipDisplayMsg:",
    re.IGNORECASE,
)

# Standard SIP start line patterns
# Request: INVITE sip:5001@10.1.1.10:5060 SIP/2.0
SIP_REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+SIP/2\.0", re.IGNORECASE)
# Response: SIP/2.0 200 OK or SIP/2.0 180 Ringing
SIP_RESPONSE_LINE = re.compile(r"^SIP/2\.0\s+(?P<code>\d{3})\s*(?P<reason>[^\r\n]*)", re.IGNORECASE)

# Header patterns (allowing leading whitespace and case-insensitivity)
CALL_ID_PATTERN = re.compile(r"^\s*(?:Call-ID|i):\s*(?P<val>\S+)", re.IGNORECASE | re.MULTILINE)
CSEQ_PATTERN = re.compile(r"^\s*CSeq:\s*(?P<seq>\d+)\s+(?P<method>[A-Z]+)", re.IGNORECASE | re.MULTILINE)
FROM_PATTERN = re.compile(r"^\s*(?:From|f):\s*(?P<val>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
TO_PATTERN = re.compile(r"^\s*(?:To|t):\s*(?P<val>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
CONTACT_PATTERN = re.compile(r"^\s*(?:Contact|m):\s*(?P<val>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
VIA_PATTERN = re.compile(r"^\s*(?:Via|v):\s*SIP/2\.0/(?P<transport>[A-Z]+)\s+(?P<host>[^;:\s]+)(?::(?P<port>\d+))?", re.IGNORECASE | re.MULTILINE)

# Number extraction from SIP URI: <sip:2001@10.1.1.20> or "Alice" <sip:2001@...
URI_USER_PATTERN = re.compile(r"sip:(?:(?P<user>[^@;>:]+)@)?(?P<host>[^;>:]+)", re.IGNORECASE)

# SDP patterns
SDP_CONNECTION = re.compile(r"^\s*c=IN\s+IP4\s+(?P<ip>\S+)", re.IGNORECASE | re.MULTILINE)
SDP_MEDIA = re.compile(r"^\s*m=audio\s+(?P<port>\d+)\s+(?P<proto>\S+)\s+(?P<codecs>[^\r\n]+)", re.IGNORECASE | re.MULTILINE)
SDP_RTPMAP = re.compile(r"^\s*a=rtpmap:(?P<payload>\d+)\s+(?P<encoding>[^/\s]+)/(?P<clock>\d+)", re.IGNORECASE | re.MULTILINE)


class SIPParser(BaseParser):
    """Deterministic parser for Cisco SIP signaling messages and SDP media descriptions."""

    def parse(self, content: str, source: str = "unknown") -> List[VoiceEvent]:
        """Parse raw trace content into normalized VoiceEvent objects."""
        if not content:
            return []

        events: List[VoiceEvent] = []
        chunks = self._split_into_messages(content)

        for raw_block, prefix_info in chunks:
            event = self._build_event(raw_block, prefix_info, source)
            if event:
                events.append(event)

        logger.info("Parsed %d SIP events from source '%s'", len(events), source)
        return events

    def _split_into_messages(self, content: str) -> List[tuple[str, Dict[str, Any]]]:
        """Split raw text into discrete SIP message blocks with timestamp/direction prefixes."""
        lines = content.splitlines()
        chunks: List[tuple[str, Dict[str, Any]]] = []

        current_block: List[str] = []
        current_meta: Dict[str, Any] = {}
        in_sip_body = False

        pending_timestamp: Optional[str] = None
        pending_dir = DirectionEnum.UNKNOWN

        for line in lines:
            stripped = line.strip()

            # Check for Cisco timestamp or banner
            banner_match = CISCO_SIP_BANNER.search(line)
            if banner_match:
                ts = banner_match.group("timestamp")
                if ts:
                    pending_timestamp = ts

            # Check for direction markers
            if stripped.startswith("Received:") or "RX" in stripped:
                pending_dir = DirectionEnum.INBOUND
            elif stripped.startswith("Sent:") or "TX" in stripped:
                pending_dir = DirectionEnum.OUTBOUND

            # Check if line begins a new SIP message
            is_req = bool(SIP_REQUEST_LINE.match(stripped))
            is_resp = bool(SIP_RESPONSE_LINE.match(stripped))

            if is_req or is_resp:
                if current_block:
                    chunks.append(("\n".join(current_block), current_meta))
                    current_block = []

                current_meta = {
                    "timestamp": pending_timestamp,
                    "direction": pending_dir,
                }
                in_sip_body = True
                current_block.append(line)
                continue

            if in_sip_body:
                # Delimiter line indicating end of SIP packet in some Cisco logs
                if stripped.startswith("<---") or stripped.startswith("---"):
                    current_block.append(line)
                    chunks.append(("\n".join(current_block), current_meta))
                    current_block = []
                    in_sip_body = False
                    pending_dir = DirectionEnum.UNKNOWN
                else:
                    current_block.append(line)

        if current_block:
            chunks.append(("\n".join(current_block), current_meta))

        return chunks

    def _build_event(
        self,
        raw_block: str,
        prefix_info: Dict[str, Any],
        source: str,
    ) -> Optional[VoiceEvent]:
        """Build VoiceEvent from a raw SIP message block."""
        lines = raw_block.strip().splitlines()
        if not lines:
            return None

        # Find first SIP line (might not be line 0 if comments or blank lines preceded)
        start_line = ""
        for line in lines:
            s = line.strip()
            if SIP_REQUEST_LINE.match(s) or SIP_RESPONSE_LINE.match(s):
                start_line = s
                break

        if not start_line:
            return None

        # Determine method / message_type
        req_match = SIP_REQUEST_LINE.match(start_line)
        resp_match = SIP_RESPONSE_LINE.match(start_line)

        cause_code = None
        sip_method = None
        sip_response_code = None

        if req_match:
            msg_type = req_match.group("method").upper()
            sip_method = msg_type
        elif resp_match:
            code = resp_match.group("code")
            reason = resp_match.group("reason").strip()
            msg_type = f"{code} {reason}".strip()
            cause_code = f"SIP {code} {reason}".strip()
            sip_response_code = int(code)
        else:
            return None

        # Extract Headers
        call_id = None
        m_cid = CALL_ID_PATTERN.search(raw_block)
        if m_cid:
            call_id = m_cid.group("val").strip()

        transaction_id = None
        cseq_num = None
        cseq_method = None
        m_cseq = CSEQ_PATTERN.search(raw_block)
        if m_cseq:
            cseq_num = int(m_cseq.group("seq"))
            cseq_method = m_cseq.group("method").upper()
            transaction_id = f"{cseq_num} {cseq_method}"
            if not sip_method:
                sip_method = cseq_method

        calling_number = None
        m_from = FROM_PATTERN.search(raw_block)
        if m_from:
            uri_match = URI_USER_PATTERN.search(m_from.group("val"))
            if uri_match and uri_match.group("user"):
                calling_number = uri_match.group("user")

        called_number = None
        m_to = TO_PATTERN.search(raw_block)
        if m_to:
            uri_match = URI_USER_PATTERN.search(m_to.group("val"))
            if uri_match and uri_match.group("user"):
                called_number = uri_match.group("user")

        source_ip = None
        source_port = None
        m_via = VIA_PATTERN.search(raw_block)
        if m_via:
            source_ip = m_via.group("host")
            if m_via.group("port"):
                source_port = int(m_via.group("port"))

        # Extract SDP metadata
        metadata: Dict[str, Any] = {}
        if sip_method:
            metadata["sip_method"] = sip_method
        if sip_response_code is not None:
            metadata["sip_response_code"] = sip_response_code
        if cseq_num is not None:
            metadata["cseq_number"] = cseq_num

        m_conn = SDP_CONNECTION.search(raw_block)
        if m_conn:
            metadata["rtp_ip"] = m_conn.group("ip")

        m_media = SDP_MEDIA.search(raw_block)
        if m_media:
            metadata["rtp_port"] = int(m_media.group("port"))
            metadata["rtp_proto"] = m_media.group("proto")

        codecs = SDP_RTPMAP.findall(raw_block)
        if codecs:
            metadata["codecs"] = [f"{enc}/{clock} ({p})" for p, enc, clock in codecs]

        raw_ts = prefix_info.get("timestamp")

        return VoiceEvent(
            timestamp=raw_ts,
            timestamp_raw=raw_ts,
            protocol=ProtocolEnum.SIP,
            direction=prefix_info.get("direction", DirectionEnum.UNKNOWN),
            source=source,
            message_type=msg_type,
            call_id=call_id,
            transaction_id=transaction_id,
            calling_number=calling_number,
            called_number=called_number,
            source_ip=source_ip,
            source_port=source_port,
            cause_code=cause_code,
            raw=raw_block,
            metadata=metadata,
        )
