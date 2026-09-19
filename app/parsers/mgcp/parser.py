"""Deterministic parser for Cisco MGCP debug traces (debug mgcp packets)."""

import re
from typing import Any, Dict, List, Optional
from app.core.logging import get_logger
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.base import BaseParser

logger = get_logger("parsers.mgcp")

# Banner pattern:
# *Sep 19 14:22:01.160: MGCP Packet received from 10.1.1.10:2427--->
# *Sep 19 14:22:01.170: MGCP Packet sent to 10.1.1.10:2427--->
MGCP_BANNER_PATTERN = re.compile(
    r"(?:(?P<seq>\d+):\s+)?"
    r"(?:\*(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?):\s+)?"
    r"MGCP Packet (?P<dir_text>received from|sent to)\s+(?P<ip>[0-9a-zA-Z\.\-]+):(?P<port>\d+)\s*--->?",
    re.IGNORECASE,
)

# Command line: CRCX 1001 S0/SU0/DS1-0/1@vg224.cisco.com MGCP 0.1
MGCP_CMD_PATTERN = re.compile(
    r"^(?P<verb>CRCX|MDCX|DLCX|RQNT|NTFY|AUEP|AUCX|RSIP)\s+(?P<trans_id>\d+)\s+(?P<endpoint>\S+)\s+(?P<version>MGCP\s+[0-9\.]+)",
    re.IGNORECASE,
)

# Response line: 200 1001 OK or 250 1003 OK
MGCP_RESP_PATTERN = re.compile(
    r"^(?P<code>[1-5]\d{2})\s+(?P<trans_id>\d+)\s*(?P<comment>[^\r\n]*)",
    re.IGNORECASE,
)

# Headers (allowing leading whitespace)
CALL_ID_PATTERN = re.compile(r"^\s*C:\s*(?P<val>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)
CONN_ID_PATTERN = re.compile(r"^\s*I:\s*(?P<val>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)
MODE_PATTERN = re.compile(r"^\s*M:\s*(?P<val>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)
LOCAL_OPTS_PATTERN = re.compile(r"^\s*L:\s*(?P<val>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)
REQ_ID_PATTERN = re.compile(r"^\s*X:\s*(?P<val>[^\r\n]+)", re.MULTILINE | re.IGNORECASE)

# SDP (allowing leading whitespace)
SDP_CONN_PATTERN = re.compile(r"^\s*c=IN\s+IP4\s+(?P<ip>\S+)", re.MULTILINE | re.IGNORECASE)
SDP_MEDIA_PATTERN = re.compile(r"^\s*m=audio\s+(?P<port>\d+)", re.MULTILINE | re.IGNORECASE)


class MGCPParser(BaseParser):
    """Deterministic parser for Cisco MGCP command and response packets."""

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

        logger.info("Parsed %d MGCP events from source '%s'", len(events), source)
        return events

    def _split_into_messages(self, content: str) -> List[tuple[str, Dict[str, Any]]]:
        """Split raw MGCP text into individual packet blocks."""
        lines = content.splitlines()
        chunks: List[tuple[str, Dict[str, Any]]] = []

        current_block: List[str] = []
        current_meta: Dict[str, Any] = {}
        in_packet = False

        for line in lines:
            banner_match = MGCP_BANNER_PATTERN.search(line)
            if banner_match:
                if current_block:
                    chunks.append(("\n".join(current_block), current_meta))
                    current_block = []

                dir_text = banner_match.group("dir_text").lower()
                direction = DirectionEnum.INBOUND if "received" in dir_text else DirectionEnum.OUTBOUND
                ip = banner_match.group("ip")
                port = int(banner_match.group("port"))

                current_meta = {
                    "timestamp": banner_match.group("timestamp"),
                    "direction": direction,
                    "peer_ip": ip,
                    "peer_port": port,
                    "banner": line,
                }
                in_packet = True
                current_block.append(line)
                continue

            if in_packet:
                current_block.append(line)
                # End of MGCP packet delimiter in Cisco debug
                if line.strip().startswith("<---") or line.strip() == "":
                    if line.strip().startswith("<---"):
                        chunks.append(("\n".join(current_block), current_meta))
                        current_block = []
                        in_packet = False
            else:
                # Standalone MGCP line without banner
                stripped = line.strip()
                if MGCP_CMD_PATTERN.match(stripped) or MGCP_RESP_PATTERN.match(stripped):
                    if current_block:
                        chunks.append(("\n".join(current_block), current_meta))
                        current_block = []
                    current_meta = {
                        "timestamp": None,
                        "direction": DirectionEnum.UNKNOWN,
                    }
                    current_block.append(line)
                    in_packet = True

        if current_block:
            chunks.append(("\n".join(current_block), current_meta))

        return chunks

    def _build_event(
        self,
        raw_block: str,
        prefix_info: Dict[str, Any],
        source: str,
    ) -> Optional[VoiceEvent]:
        """Build VoiceEvent from an MGCP packet block."""
        lines = [line.strip() for line in raw_block.splitlines() if line.strip()]
        if not lines:
            return None

        # Locate either command or response line
        cmd_match = None
        resp_match = None

        for line in lines:
            cmd_match = MGCP_CMD_PATTERN.match(line)
            if cmd_match:
                break
            resp_match = MGCP_RESP_PATTERN.match(line)
            if resp_match:
                break

        if not cmd_match and not resp_match:
            return None

        endpoint = None
        cause_code = None
        metadata: Dict[str, Any] = {}

        if cmd_match:
            verb = cmd_match.group("verb").upper()
            trans_id = cmd_match.group("trans_id")
            endpoint = cmd_match.group("endpoint")
            msg_type = verb
            metadata["mgcp_version"] = cmd_match.group("version")
        else:
            code = resp_match.group("code")
            trans_id = resp_match.group("trans_id")
            comment = resp_match.group("comment").strip()
            msg_type = f"{code} {comment}".strip()
            cause_code = f"MGCP {code} {comment}".strip()

        # Extract headers
        call_id = None
        m_cid = CALL_ID_PATTERN.search(raw_block)
        if m_cid:
            call_id = m_cid.group("val").strip()

        conn_id = None
        m_conn = CONN_ID_PATTERN.search(raw_block)
        if m_conn:
            conn_id = m_conn.group("val").strip()
            metadata["connection_id"] = conn_id

        m_mode = MODE_PATTERN.search(raw_block)
        if m_mode:
            metadata["mode"] = m_mode.group("val").strip()

        m_opts = LOCAL_OPTS_PATTERN.search(raw_block)
        if m_opts:
            metadata["local_options"] = m_opts.group("val").strip()

        m_xid = REQ_ID_PATTERN.search(raw_block)
        if m_xid:
            metadata["request_identifier"] = m_xid.group("val").strip()

        # SDP checks
        m_sdp_conn = SDP_CONN_PATTERN.search(raw_block)
        if m_sdp_conn:
            metadata["rtp_ip"] = m_sdp_conn.group("ip")

        m_sdp_media = SDP_MEDIA_PATTERN.search(raw_block)
        if m_sdp_media:
            metadata["rtp_port"] = int(m_sdp_media.group("port"))

        direction = prefix_info.get("direction", DirectionEnum.UNKNOWN)
        peer_ip = prefix_info.get("peer_ip")
        peer_port = prefix_info.get("peer_port")

        source_ip = peer_ip if direction == DirectionEnum.INBOUND else None
        destination_ip = peer_ip if direction == DirectionEnum.OUTBOUND else None
        source_port = peer_port if direction == DirectionEnum.INBOUND else None
        destination_port = peer_port if direction == DirectionEnum.OUTBOUND else None

        return VoiceEvent(
            timestamp=prefix_info.get("timestamp"),
            timestamp_raw=prefix_info.get("timestamp"),
            protocol=ProtocolEnum.MGCP,
            direction=direction,
            source=source,
            message_type=msg_type,
            transaction_id=trans_id,
            call_id=call_id,
            endpoint=endpoint,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            cause_code=cause_code,
            raw=raw_block,
            metadata=metadata,
        )
