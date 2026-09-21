"""Deterministic streaming parser for CUCM SDL trace files."""

import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union

from app.core.logging import get_logger
from app.devices.cucm.sdl.identifiers import extract_all_identifiers
from app.devices.cucm.sdl.models import SDLEvent
from app.devices.cucm.sdl.normalizer import (
    infer_direction,
    infer_protocol,
    normalize_cucm_timestamp,
    parse_filehead_metadata,
)

logger = get_logger("devices.cucm.sdl.parser")

# Standard CUCM trace line patterns
# Pattern 1: Sequence number + Time + TraceType + Rest
# Example: 00644028.000 |13:35:15.018 |SdlSig   |DbObjectCacheTimer |...
SDL_HEADER_PATTERN_SEQ = re.compile(
    r"^(?P<seq>\d+\.\d+)\s*\|\s*(?P<time>(?:\d{4}[-/]\d{2}[-/]\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*\|\s*(?P<type>[^|]+)\s*\|(?P<rest>.*)$"
)

# Pattern 2: Time + TraceType + Rest (without sequence number)
# Example: 13:35:15.018 |SdlSig   |DbObjectCacheTimer |...
SDL_HEADER_PATTERN_NO_SEQ = re.compile(
    r"^(?P<time>(?:\d{4}[-/]\d{2}[-/]\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*\|\s*(?P<type>[^|]+)\s*\|(?P<rest>.*)$"
)


class SDLParser:
    """Deterministic parser converting raw CUCM SDL trace records into structured SDLEvent objects."""

    def __init__(self, default_node: Optional[str] = None):
        self.default_node = default_node
        self.malformed_records: List[Dict[str, Any]] = []
        self.parse_warnings: List[str] = []

    def parse_file(self, file_path: Union[str, Path], default_node: Optional[str] = None) -> List[SDLEvent]:
        """Parse an entire SDL file into a list of SDLEvent objects."""
        return list(self.parse_file_iter(file_path, default_node=default_node))

    def parse_file_iter(
        self, file_path: Union[str, Path], default_node: Optional[str] = None
    ) -> Iterator[SDLEvent]:
        """Stream SDLEvent objects from an SDL trace file on disk without loading entire file into memory."""
        path = Path(file_path)
        source_name = path.name
        node = default_node or self.default_node

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                yield from self.parse_stream(f, source_file=source_name, default_node=node)
        except Exception as exc:
            logger.error("Failed to open or read SDL trace file %s: %s", path, exc)
            self.parse_warnings.append(f"File read error on {source_name}: {exc}")

    def parse_stream(
        self,
        lines: Iterable[str],
        source_file: str = "unknown",
        default_node: Optional[str] = None,
        default_date: Optional[date] = None,
        default_tz: Optional[timezone] = None,
    ) -> Iterator[SDLEvent]:
        """Stream parser yielding SDLEvent objects for each record in the input line generator."""
        current_date: Optional[date] = default_date
        current_tz: timezone = default_tz or timezone.utc
        current_node: Optional[str] = default_node or self.default_node

        current_header: Optional[Dict[str, Any]] = None
        current_lines: List[str] = []
        current_start_line: int = 1

        line_num = 0
        for line_raw in lines:
            line_num += 1
            line = line_raw.rstrip("\r\n")

            # Check if this line is an event header
            m = SDL_HEADER_PATTERN_SEQ.match(line)
            seq = None
            if m:
                seq = m.group("seq")
                time_str = m.group("time")
                trace_type = m.group("type").strip()
                rest = m.group("rest")
            else:
                m_no_seq = SDL_HEADER_PATTERN_NO_SEQ.match(line)
                if m_no_seq:
                    time_str = m_no_seq.group("time")
                    trace_type = m_no_seq.group("type").strip()
                    rest = m_no_seq.group("rest")
                else:
                    m_no_seq = None

            if m or m_no_seq:
                # Yield previous accumulated event if one exists
                if current_header:
                    event = self._build_event(
                        header=current_header,
                        raw_lines=current_lines,
                        source_file=source_file,
                        start_line=current_start_line,
                        base_date=current_date,
                        tz=current_tz,
                        node=current_node,
                    )
                    if event:
                        yield event

                # Check if this line is a FileHead header
                if trace_type == "FileHead":
                    f_date, f_tz, f_node = parse_filehead_metadata(line)
                    if f_date:
                        current_date = f_date
                    if f_tz:
                        current_tz = f_tz
                    if f_node:
                        current_node = f_node

                # Start new record
                current_header = {
                    "seq": seq,
                    "time_str": time_str,
                    "type": trace_type,
                    "rest": rest,
                    "header_line": line,
                }
                current_lines = [line]
                current_start_line = line_num
            else:
                # Continuation line (multiline SIP/MGCP message, parameters, stack)
                if current_header:
                    current_lines.append(line)
                elif line.strip():
                    # Unparsed preamble line before first header
                    self.malformed_records.append({
                        "source_file": source_file,
                        "line_num": line_num,
                        "text": line,
                        "reason": "Line before first trace header",
                    })

        # Yield last event at end of stream
        if current_header:
            event = self._build_event(
                header=current_header,
                raw_lines=current_lines,
                source_file=source_file,
                start_line=current_start_line,
                base_date=current_date,
                tz=current_tz,
                node=current_node,
            )
            if event:
                yield event

    def _build_event(
        self,
        header: Dict[str, Any],
        raw_lines: List[str],
        source_file: str,
        start_line: int,
        base_date: Optional[date],
        tz: timezone,
        node: Optional[str],
    ) -> Optional[SDLEvent]:
        """Construct structured SDLEvent safely without crashing on malformed input."""
        full_text = "\n".join(raw_lines)
        trace_type = header["type"]
        time_str = header["time_str"]
        rest = header["rest"]
        seq = header.get("seq")

        try:
            timestamp = normalize_cucm_timestamp(time_str, base_date=base_date, tz=tz)
        except Exception as exc:
            self.malformed_records.append({
                "source_file": source_file,
                "line_num": start_line,
                "text": full_text[:200],
                "reason": f"Timestamp parsing failed: {exc}",
            })
            timestamp = datetime(2026, 9, 20, 0, 0, 0, tzinfo=tz)

        # Parse type-specific fields
        signal: Optional[str] = None
        process: Optional[str] = None
        state: Optional[str] = None
        receiving_proc: Optional[str] = None
        sending_proc: Optional[str] = None
        proc_ids: Optional[str] = None

        attributes: Dict[str, Any] = {"trace_type": trace_type}
        if seq:
            attributes["sequence_num"] = seq

        if trace_type.startswith("SdlSig"):
            # Format: signal | state | receiving_process | sending_process | proc_ids | params
            parts = [p.strip() for p in rest.split("|")]
            if parts and parts[0]:
                signal = parts[0]
            if len(parts) > 1 and parts[1]:
                state = parts[1]
                attributes["state"] = state
            if len(parts) > 2 and parts[2]:
                receiving_proc = parts[2]
                attributes["receiving_process"] = receiving_proc
                # Set process name without internal instance ID
                process = receiving_proc.split("(")[0] if "(" in receiving_proc else receiving_proc
            if len(parts) > 3 and parts[3]:
                sending_proc = parts[3]
                attributes["sending_process"] = sending_proc
            if len(parts) > 4 and parts[4]:
                proc_ids = parts[4]
                attributes["process_ids"] = proc_ids
            if len(parts) > 5 and parts[5]:
                attributes["params"] = parts[5]

        elif trace_type.startswith("AppInfo"):
            parts = rest.split(None, 1)
            process = parts[0] if parts else "AppInfo"
            signal = process

            # Detect embedded protocol verb from message body
            m_sip_req = re.search(r"^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|INFO|PRACK|UPDATE)\s+sip:", full_text, re.MULTILINE | re.IGNORECASE)
            if m_sip_req:
                signal = m_sip_req.group(1).upper()
            else:
                m_sip_resp = re.search(r"^SIP/2\.0\s+(\d{3}\s+[^\r\n]+)", full_text, re.MULTILINE | re.IGNORECASE)
                if m_sip_resp:
                    signal = m_sip_resp.group(1).strip()
                else:
                    m_mgcp = re.search(r"^(NTFY|CRCX|MDCX|DLCX|RQNT|AUEP|AUCX|EPCF|RSIP)\s+(\d+)", full_text, re.MULTILINE | re.IGNORECASE)
                    if m_mgcp:
                        signal = m_mgcp.group(1).upper()

        elif trace_type == "FileHead":
            signal = "FileHead"
            process = "TraceService"

        elif trace_type.startswith("SdlStat"):
            signal = "SdlStat"
            process = "TraceService"

        else:
            signal = trace_type
            process = trace_type

        # Extract correlation identifiers
        identifiers = extract_all_identifiers(full_text)
        attributes.update({k: v for k, v in identifiers.items() if k not in ("ci", "cdcc", "call_id", "calling_number", "called_number", "device", "ip_address")})

        protocol = infer_protocol(signal, process, full_text)
        direction = infer_direction(header["header_line"], full_text)

        event = SDLEvent(
            timestamp=timestamp,
            node=node,
            process=process,
            signal=signal,
            direction=direction,
            call_id=identifiers.get("call_id"),
            ci=identifiers.get("ci"),
            cdcc=identifiers.get("cdcc"),
            calling_number=identifiers.get("calling_number"),
            called_number=identifiers.get("called_number"),
            device=identifiers.get("device"),
            ip_address=identifiers.get("ip_address"),
            protocol=protocol,
            raw_text=full_text,
            source_file=source_file,
            source_line=start_line,
            attributes=attributes,
        )
        return event
