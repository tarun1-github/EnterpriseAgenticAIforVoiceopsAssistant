"""AnalysisWorkspace model and pipeline service for unified cross-protocol troubleshooting."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import uuid4
from pydantic import BaseModel, Field

from app.models.event import VoiceEvent, ProtocolEnum
from app.models.call_session import CallSession, CallArchitecture
from app.models.anomaly import CallAnomaly
from app.analysis.anomaly_detector import AnomalyDetector
from app.analysis.evidence_builder import build_evidence_pack
from app.analysis.architecture import detect_call_architecture, ArchitectureEvidence
from app.correlation.engine import CorrelationEngine
from app.parsers.ingestion import TraceIngestionEngine
from app.artifacts.models import TraceManifest
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("analysis.workspace")


class AnalysisWorkspace(BaseModel):
    """Unified analysis workspace shared across all VoiceOps UI tabs."""

    workspace_id: str = Field(default_factory=lambda: f"ws_{uuid4().hex[:8]}")
    trace_ids: List[str] = Field(default_factory=list, description="IDs of ingested trace manifests or collections")
    source_files: List[str] = Field(default_factory=list, description="Source filenames analyzed")
    events: List[VoiceEvent] = Field(default_factory=list, description="All parsed VoiceEvents")
    call_sessions: List[CallSession] = Field(default_factory=list, description="Correlated call sessions")
    anomalies: List[CallAnomaly] = Field(default_factory=list, description="All signaling anomalies detected")
    evidence: List[str] = Field(default_factory=list, description="All evidence statements extracted")
    architecture: str = Field(default="UNKNOWN", description="Inferred overall or primary call architecture")
    architecture_evidence: Optional[ArchitectureEvidence] = Field(default=None, description="Detailed architecture evidence and topology flow")
    timestamps: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Temporal bounds of analyzed traces (start_time, end_time)",
    )
    protocol_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Event breakdown count by protocol",
    )
    ingestion_status: str = Field(default="READY", description="Status of ingestion (READY, EMPTY, ERROR)")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def get_session(self, session_id: str) -> Optional[CallSession]:
        """Find a CallSession by session_id."""
        for s in self.call_sessions:
            if s.session_id == session_id:
                return s
        return None

    def get_event(self, event_id: str) -> Optional[VoiceEvent]:
        """Find a VoiceEvent by event_id."""
        for e in self.events:
            if e.id == event_id:
                return e
        return None


class AnalysisPipelineService:
    """Service to ingest raw/extracted trace texts into a persistent AnalysisWorkspace."""

    def __init__(self, storage_dir: Optional[Path] = None):
        if storage_dir is None:
            settings = get_settings()
            self._storage_dir = Path(settings.voiceops_trace_storage)
        else:
            self._storage_dir = Path(storage_dir)

        self._manifest_path = self._storage_dir / "analysis_manifest.json"
        self._ingestion_engine = TraceIngestionEngine()
        self._detector = AnomalyDetector()
        self._correlation_engine = CorrelationEngine(anomaly_detector=self._detector)

    @property
    def manifest_path(self) -> Path:
        return self._manifest_path

    def ingest_trace_contents(
        self,
        contents: List[tuple[str, str]],
        trace_ids: Optional[List[str]] = None,
    ) -> AnalysisWorkspace:
        """Parse contents, correlate sessions, detect anomalies, and generate AnalysisWorkspace.

        Args:
            contents: List of (filename, text_content) tuples.
            trace_ids: Optional list of trace/request identifiers.

        Returns:
            Populated AnalysisWorkspace instance.
        """
        all_events: List[VoiceEvent] = []
        source_files: List[str] = []

        for filename, text in contents:
            source_files.append(filename)
            events = self._ingestion_engine.ingest_content(text, source=filename)
            all_events.extend(events)

        logger.info(
            "Parsed %d events across %d file(s)", len(all_events), len(source_files)
        )

        # Correlate sessions
        call_sessions = self._correlation_engine.correlate(all_events)
        logger.info("Correlated %d call session(s)", len(call_sessions))

        # Collect anomalies and evidence
        all_anomalies: List[CallAnomaly] = []
        all_evidence: List[str] = []
        architectures: List[str] = []

        for session in call_sessions:
            all_anomalies.extend(session.anomalies)
            if session.correlation_evidence:
                all_evidence.extend(session.correlation_evidence)
            if session.architecture and session.architecture != CallArchitecture.UNKNOWN:
                architectures.append(session.architecture.value)

        # Protocol counts
        protocol_counts: Dict[str, int] = {}
        for ev in all_events:
            proto_key = ev.protocol.value
            protocol_counts[proto_key] = protocol_counts.get(proto_key, 0) + 1

        # Timestamps
        earliest_ts: Optional[str] = None
        latest_ts: Optional[str] = None
        valid_ts = [e.timestamp for e in all_events if e.timestamp]
        if valid_ts:
            earliest_ts = min(valid_ts).isoformat()
            latest_ts = max(valid_ts).isoformat()

        # Derive evidence-driven call architecture
        arch_evidence = detect_call_architecture(all_events, sessions=call_sessions)
        primary_arch = arch_evidence.architecture_name

        workspace = AnalysisWorkspace(
            trace_ids=trace_ids or [],
            source_files=source_files,
            events=all_events,
            call_sessions=call_sessions,
            anomalies=all_anomalies,
            evidence=list(dict.fromkeys(all_evidence)),  # deduplicate
            architecture=primary_arch,
            architecture_evidence=arch_evidence,
            timestamps={"start_time": earliest_ts, "end_time": latest_ts},
            protocol_counts=protocol_counts,
            ingestion_status="READY" if all_events else "EMPTY",
        )

        # Persist analysis manifest to disk
        self.save_workspace(workspace)
        return workspace

    def ingest_manifests(self, manifests: List[TraceManifest]) -> AnalysisWorkspace:
        """Ingest selected TraceManifests from the persistent repository.

        Args:
            manifests: List of TraceManifest instances.

        Returns:
            Populated AnalysisWorkspace.
        """
        contents: List[tuple[str, str]] = []
        trace_ids: List[str] = []

        for m in manifests:
            trace_ids.append(m.request_id)
            ext_path = Path(m.extracted_path)
            if ext_path.exists():
                text = ext_path.read_text(encoding="utf-8", errors="replace")
                contents.append((m.normalized_filename or m.original_filename, text))
            else:
                logger.warning("Extracted path not found for manifest %s: %s", m.request_id, ext_path)

        return self.ingest_trace_contents(contents, trace_ids=trace_ids)

    def ingest_files(self, paths: List[Path]) -> AnalysisWorkspace:
        """Ingest trace files from disk paths."""
        contents: List[tuple[str, str]] = []
        for p in paths:
            if p.exists() and p.is_file():
                text = p.read_text(encoding="utf-8", errors="replace")
                contents.append((p.name, text))
        return self.ingest_trace_contents(contents)

    def save_workspace(self, workspace: AnalysisWorkspace) -> Path:
        """Persist AnalysisWorkspace to storage directory as JSON."""
        self._manifest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._manifest_path.with_suffix(".tmp")
        data = workspace.model_dump(mode="json")
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp_path.replace(self._manifest_path)
        logger.info("Saved analysis workspace manifest to %s", self._manifest_path)
        return self._manifest_path

    def load_saved_workspace(self) -> Optional[AnalysisWorkspace]:
        """Load persisted AnalysisWorkspace if available."""
        if not self._manifest_path.exists() or not self._manifest_path.is_file():
            return None
        try:
            content = self._manifest_path.read_text(encoding="utf-8")
            data = json.loads(content)
            return AnalysisWorkspace.model_validate(data)
        except Exception as e:
            logger.error("Failed to load analysis manifest %s: %s", self._manifest_path, e)
            return None

    def has_saved_workspace(self) -> bool:
        """Check if an analysis manifest exists on disk."""
        return self._manifest_path.exists() and self._manifest_path.is_file()

    def clear_saved_workspace(self) -> bool:
        """Remove persisted analysis manifest."""
        if self._manifest_path.exists():
            try:
                self._manifest_path.unlink()
                logger.info("Cleared analysis workspace manifest")
                return True
            except Exception as e:
                logger.warning("Failed to remove analysis manifest: %s", e)
        return False
