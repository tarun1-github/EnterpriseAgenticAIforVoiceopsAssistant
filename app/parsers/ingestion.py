"""Trace ingestion orchestrator with automated protocol detection and dispatch."""

from pathlib import Path
from typing import Dict, List, Optional, Union
from app.core.logging import get_logger
from app.models.event import ProtocolEnum, VoiceEvent
from app.parsers.base import BaseParser
from app.parsers.cucm.parser import CUCMParser
from app.parsers.detector import detect_multiple_protocols, detect_protocol, detect_segment_protocol
from app.parsers.isdn.parser import ISDNParser
from app.parsers.mgcp.parser import MGCPParser
from app.parsers.sip.parser import SIPParser

logger = get_logger("parsers.ingestion")


class TraceIngestionEngine:
    """Enterprise trace ingestion layer supporting multiple Cisco voice signaling formats."""

    def __init__(self) -> None:
        """Initialize parser registry."""
        self._parsers: Dict[ProtocolEnum, BaseParser] = {
            ProtocolEnum.ISDN: ISDNParser(),
            ProtocolEnum.SIP: SIPParser(),
            ProtocolEnum.MGCP: MGCPParser(),
            ProtocolEnum.CUCM: CUCMParser(),
        }

    def ingest_content(
        self,
        content: str,
        source: str = "memory_buffer",
        protocol: Optional[ProtocolEnum] = None,
    ) -> List[VoiceEvent]:
        """Ingest raw trace text, auto-detect protocol if needed, and parse into VoiceEvents.

        Supports single-protocol files as well as mixed-protocol gateway captures.

        Args:
            content: Raw trace string.
            source: Source identifier (e.g. filename).
            protocol: Optional explicit protocol override.

        Returns:
            List of parsed VoiceEvent instances.
        """
        if not content or not content.strip():
            logger.warning("Empty content provided for source '%s'", source)
            return []

        # If protocol is explicitly provided, use it directly
        if protocol is not None:
            parser = self._parsers.get(protocol)
            if parser:
                return parser.parse(content, source=source)

        # Check if multiple protocols are present in this trace file
        detected_protocols = detect_multiple_protocols(content)
        if len(detected_protocols) > 1:
            logger.info(
                "Source '%s' contains multiple protocols %s. Executing mixed ingestion.",
                source,
                [p.value for p in detected_protocols],
            )
            return self.ingest_mixed_content(content, source=source, protocols=detected_protocols)

        # Single primary protocol detected
        target_protocol = detect_protocol(content)
        logger.info("Ingesting source '%s' with detected protocol: %s", source, target_protocol.value)

        parser = self._parsers.get(target_protocol)
        if not parser:
            logger.warning("No parser registered for protocol %s (source: %s)", target_protocol, source)
            return [
                VoiceEvent(
                    protocol=ProtocolEnum.UNKNOWN,
                    source=source,
                    message_type="RAW_TRACE",
                    raw=content,
                )
            ]

        return parser.parse(content, source=source)

    def ingest_mixed_content(
        self,
        content: str,
        source: str = "mixed_trace",
        protocols: Optional[List[ProtocolEnum]] = None,
    ) -> List[VoiceEvent]:
        """Ingest trace content that contains interleaved protocols (e.g. ISDN + MGCP + SIP).

        Args:
            content: Raw multi-protocol trace content.
            source: Source identifier.
            protocols: Optional pre-detected list of protocols.

        Returns:
            Aggregated list of VoiceEvents ordered by their appearance in the trace.
        """
        target_protocols = protocols or detect_multiple_protocols(content)
        all_events: List[VoiceEvent] = []

        for proto in target_protocols:
            parser = self._parsers.get(proto)
            if parser:
                proto_events = parser.parse(content, source=source)
                all_events.extend(proto_events)

        # Sort events by their earliest line position in the raw content
        def get_event_position(ev: VoiceEvent) -> int:
            first_line = ev.raw.strip().splitlines()[0] if ev.raw else ""
            pos = content.find(first_line)
            return pos if pos != -1 else 0

        all_events.sort(key=get_event_position)
        logger.info("Extracted %d total events from mixed source '%s'", len(all_events), source)
        return all_events

    def ingest_file(
        self,
        file_path: Union[str, Path],
        protocol: Optional[ProtocolEnum] = None,
    ) -> List[VoiceEvent]:
        """Safely read and ingest a single trace file from disk.

        Args:
            file_path: Path to the .txt trace file.
            protocol: Optional explicit protocol override.

        Returns:
            List of parsed VoiceEvent instances.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Trace file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.error("Failed to read trace file '%s': %s", path, exc)
            raise

        return self.ingest_content(content, source=path.name, protocol=protocol)

    def ingest_multiple_files(
        self,
        file_paths: List[Union[str, Path]],
    ) -> List[VoiceEvent]:
        """Ingest and aggregate events from multiple trace files.

        Args:
            file_paths: List of file paths to process.

        Returns:
            Combined list of parsed VoiceEvent instances.
        """
        all_events: List[VoiceEvent] = []
        for fp in file_paths:
            try:
                events = self.ingest_file(fp)
                all_events.extend(events)
            except Exception as exc:
                logger.error("Skipping file '%s' due to error: %s", fp, exc)

        return all_events
