"""Trace ingestion orchestrator with automated protocol detection, content classification, and dispatch."""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.core.logging import get_logger
from app.core.timestamps import ensure_utc
from app.devices.cucm.sdl.models import SDLEvent
from app.devices.cucm.sdl.parser import SDLParser
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.models.trace_artifact import TraceArtifact
from app.parsers.base import BaseParser
from app.parsers.classifier import ClassificationResult, TraceClassifier
from app.parsers.cucm.parser import CUCMParser
from app.parsers.detector import detect_multiple_protocols, detect_protocol
from app.parsers.isdn.parser import ISDNParser
from app.parsers.mgcp.parser import MGCPParser
from app.parsers.sip.parser import SIPParser

logger = get_logger("parsers.ingestion")

PROTO_MAP = {
    "SIP": ProtocolEnum.SIP,
    "Q931": ProtocolEnum.ISDN,
    "ISDN": ProtocolEnum.ISDN,
    "MGCP": ProtocolEnum.MGCP,
    "SCCP": ProtocolEnum.CUCM,
    "CUCM": ProtocolEnum.CUCM,
}

DIR_MAP = {
    "INBOUND": DirectionEnum.INBOUND,
    "OUTBOUND": DirectionEnum.OUTBOUND,
    "INTERNAL": DirectionEnum.INTERNAL,
    "UNKNOWN": DirectionEnum.UNKNOWN,
}


class TraceIngestionEngine:
    """Enterprise trace ingestion layer supporting multiple Cisco voice signaling formats."""

    def __init__(self) -> None:
        """Initialize parser registry and content classifier."""
        self.classifier = TraceClassifier()
        self.sdl_parser = SDLParser()
        self.trace_artifacts: List[TraceArtifact] = []
        self._parsers: Dict[ProtocolEnum, BaseParser] = {
            ProtocolEnum.ISDN: ISDNParser(),
            ProtocolEnum.SIP: SIPParser(),
            ProtocolEnum.MGCP: MGCPParser(),
            ProtocolEnum.CUCM: CUCMParser(),
        }

    def clear(self) -> None:
        """Clear cached trace artifacts."""
        self.trace_artifacts.clear()

    def get_trace_inventory(self) -> List[Dict[str, Any]]:
        """Return structured inventory summary for all ingested trace artifacts."""
        return [a.to_inventory_dict() for a in self.trace_artifacts]

    def ingest_content(
        self,
        content: str,
        source: str = "memory_buffer",
        protocol: Optional[ProtocolEnum] = None,
        metadata_override: Optional[Dict[str, Any]] = None,
    ) -> List[VoiceEvent]:
        """Ingest raw trace text, classify content, and parse into VoiceEvents.

        Args:
            content: Raw trace string.
            source: Source identifier (e.g. filename).
            protocol: Optional explicit protocol override.
            metadata_override: Optional user metadata overrides (device_type, trace_type, IP, timezone).

        Returns:
            List of parsed VoiceEvent instances.
        """
        if not content or not content.strip():
            logger.warning("Empty content provided for source '%s'", source)
            return []

        # 1. Content-based classification
        classification: ClassificationResult = self.classifier.classify(content, filename=source)

        # Apply user overrides if specified
        if metadata_override:
            tt_override = metadata_override.get("trace_type")
            if tt_override and tt_override != "Auto Detect":
                classification.trace_type = tt_override.upper().replace("/", "_").replace(" ", "_")
            dt_override = metadata_override.get("device_type")
            if dt_override and dt_override != "Auto Detect":
                classification.device_type = dt_override.upper().replace(" ", "_")
            if metadata_override.get("device_ip"):
                classification.device_ip = metadata_override["device_ip"].strip()
            if metadata_override.get("device_name"):
                classification.device_name = metadata_override["device_name"].strip()

        # 2. Parse based on classified trace type
        events: List[VoiceEvent] = []

        if classification.trace_type == "CUCM_SDL":
            # Use dedicated streaming SDLParser
            sdl_events = list(self.sdl_parser.parse_stream(content.splitlines(), source_file=source))
            events = [self._convert_sdl_event_to_voice_event(e, classification, source) for e in sdl_events]

        elif classification.trace_type == "MIXED":
            detected_protocols = detect_multiple_protocols(content)
            events = self.ingest_mixed_content(content, source=source, protocols=detected_protocols)

        else:
            # Map trace_type to protocol
            target_proto = protocol
            if target_proto is None:
                if classification.trace_type == "ISDN_Q931":
                    target_proto = ProtocolEnum.ISDN
                elif classification.trace_type == "SIP":
                    target_proto = ProtocolEnum.SIP
                elif classification.trace_type == "MGCP":
                    target_proto = ProtocolEnum.MGCP
                else:
                    target_proto = detect_protocol(content)

            parser = self._parsers.get(target_proto)
            if parser:
                events = parser.parse(content, source=source)
            if not events:
                events = [
                    VoiceEvent(
                        protocol=target_proto or ProtocolEnum.UNKNOWN,
                        source=source,
                        message_type="RAW_TRACE",
                        raw=content,
                    )
                ]

        # 3. Stamp metadata and provenance onto every event
        for ev in events:
            if ev.timestamp:
                ev.timestamp = ensure_utc(ev.timestamp)
            if not ev.trace_type:
                ev.trace_type = classification.trace_type
            if not ev.device_type:
                ev.device_type = classification.device_type
            if not ev.device_name and classification.device_name:
                ev.device_name = classification.device_name
            if not ev.device_ip and classification.device_ip:
                ev.device_ip = classification.device_ip
            if not ev.source:
                ev.source = source

        # 4. Create TraceArtifact manifest record
        earliest_ts = min([ensure_utc(e.timestamp) for e in events if e.timestamp], default=None)
        latest_ts = max([ensure_utc(e.timestamp) for e in events if e.timestamp], default=None)
        sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        artifact = TraceArtifact(
            filename=source,
            original_filename=source,
            trace_type=classification.trace_type,
            device_type=classification.device_type,
            device_name=classification.device_name,
            device_ip=classification.device_ip,
            protocol=events[0].protocol.value if events else "UNKNOWN",
            timezone=metadata_override.get("timezone", "Asia/Kolkata") if metadata_override else "Asia/Kolkata",
            earliest_timestamp=earliest_ts,
            latest_timestamp=latest_ts,
            file_size=len(content.encode("utf-8")),
            sha256=sha256_hash,
            classification_confidence=classification.confidence,
            classification_evidence=classification.evidence,
            source="upload",
        )
        self.trace_artifacts.append(artifact)

        logger.info(
            "Ingested %d events from '%s' [Classified: %s, Device: %s, Confidence: %.2f]",
            len(events),
            source,
            classification.trace_type,
            classification.device_type,
            classification.confidence,
        )
        return events

    def _convert_sdl_event_to_voice_event(
        self,
        ev: SDLEvent,
        classification: ClassificationResult,
        source: str,
    ) -> VoiceEvent:
        """Bridge an SDLEvent from the dedicated CUCM SDL parser into a common VoiceEvent."""
        proto = PROTO_MAP.get(ev.protocol or "CUCM", ProtocolEnum.CUCM)
        direction = DIR_MAP.get(ev.direction or "INTERNAL", DirectionEnum.INTERNAL)

        correl_ids: Dict[str, Any] = {}
        if ev.ci:
            correl_ids["ci"] = ev.ci
        if ev.cdcc:
            correl_ids["cdcc"] = ev.cdcc
        if ev.call_id:
            correl_ids["call_id"] = ev.call_id
        if ev.attributes.get("ccb_id"):
            correl_ids["ccb_id"] = ev.attributes["ccb_id"]
        if ev.attributes.get("tcp_handle"):
            correl_ids["tcp_handle"] = ev.attributes["tcp_handle"]
        if ev.attributes.get("app_corr"):
            correl_ids["app_corr"] = ev.attributes["app_corr"]

        return VoiceEvent(
            timestamp=ensure_utc(ev.timestamp) if ev.timestamp else None,
            timestamp_raw=ev.timestamp.isoformat() if ev.timestamp else "",
            protocol=proto,
            direction=direction,
            source=source,
            message_type=ev.signal or ev.process or "CUCM_EVENT",
            call_id=ev.call_id,
            calling_number=ev.calling_number,
            called_number=ev.called_number,
            device=ev.device or ev.node or classification.device_name,
            source_ip=ev.ip_address or classification.device_ip,
            raw=ev.raw_text,
            metadata=ev.attributes,
            trace_type="CUCM_SDL",
            device_type="CUCM",
            device_name=ev.node or classification.device_name,
            device_ip=ev.ip_address or classification.device_ip,
            correlation_ids=correl_ids,
        )

    def ingest_mixed_content(
        self,
        content: str,
        source: str = "mixed_trace",
        protocols: Optional[List[ProtocolEnum]] = None,
    ) -> List[VoiceEvent]:
        """Ingest trace content that contains interleaved protocols (e.g. ISDN + MGCP + SIP)."""
        target_protocols = protocols or detect_multiple_protocols(content)
        all_events: List[VoiceEvent] = []

        for proto in target_protocols:
            parser = self._parsers.get(proto)
            if parser:
                proto_events = parser.parse(content, source=source)
                all_events.extend(proto_events)

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
        metadata_override: Optional[Dict[str, Any]] = None,
    ) -> List[VoiceEvent]:
        """Safely read and ingest a single trace file from disk."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Trace file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.error("Failed to read trace file '%s': %s", path, exc)
            raise

        return self.ingest_content(
            content,
            source=path.name,
            protocol=protocol,
            metadata_override=metadata_override,
        )

    def ingest_multiple_files(
        self,
        file_paths: List[Union[str, Path]],
        metadata_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[VoiceEvent]:
        """Ingest and aggregate events from multiple trace files."""
        all_events: List[VoiceEvent] = []
        for fp in file_paths:
            path = Path(fp)
            override = metadata_overrides.get(path.name) if metadata_overrides else None
            try:
                events = self.ingest_file(fp, metadata_override=override)
                all_events.extend(events)
            except Exception as exc:
                logger.error("Skipping file '%s' due to error: %s", fp, exc)

        return all_events
