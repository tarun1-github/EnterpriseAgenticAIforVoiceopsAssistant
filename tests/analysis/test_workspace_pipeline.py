"""Tests for AnalysisWorkspace, ingestion pipeline, and state persistence."""

import pytest
from pathlib import Path
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.artifacts.models import TraceManifest
from app.models.event import ProtocolEnum, DirectionEnum

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def service(tmp_path):
    """Provide an AnalysisPipelineService pointing to tmp_path."""
    return AnalysisPipelineService(storage_dir=tmp_path / "voiceops_traces")


@pytest.fixture
def sample_traces():
    """Load bundled sample traces."""
    sample_dir = ROOT_DIR / "sample_data"
    isdn_text = (sample_dir / "isdn" / "sample_isdn_call.txt").read_text(encoding="utf-8")
    sip_text = (sample_dir / "sip" / "sample_sip_call.txt").read_text(encoding="utf-8")
    mgcp_text = (sample_dir / "mgcp" / "sample_mgcp_call.txt").read_text(encoding="utf-8")
    return [
        ("sample_isdn_call.txt", isdn_text),
        ("sample_sip_call.txt", sip_text),
        ("sample_mgcp_call.txt", mgcp_text),
    ]


class TestAnalysisWorkspacePipeline:
    """Test ingestion pipeline execution and AnalysisWorkspace population."""

    def test_ingest_traces_creates_workspace(self, service, sample_traces):
        """Verify that ingesting traces populates an AnalysisWorkspace with sessions, events, and metrics."""
        workspace = service.ingest_trace_contents(sample_traces, trace_ids=["req_001", "req_002"])

        assert workspace.workspace_id.startswith("ws_")
        assert workspace.trace_ids == ["req_001", "req_002"]
        assert len(workspace.source_files) == 3
        assert workspace.ingestion_status == "READY"
        assert len(workspace.events) > 0
        assert len(workspace.call_sessions) > 0

        # Protocol counts
        assert ProtocolEnum.ISDN.value in workspace.protocol_counts
        assert workspace.protocol_counts[ProtocolEnum.ISDN.value] > 0

    def test_call_sessions_populated_and_queryable(self, service, sample_traces):
        """Verify correlated call sessions are correctly structured in the workspace."""
        workspace = service.ingest_trace_contents(sample_traces)

        first_session = workspace.call_sessions[0]
        assert first_session.session_id is not None
        assert len(first_session.events) > 0

        # Query method
        found = workspace.get_session(first_session.session_id)
        assert found is not None
        assert found.session_id == first_session.session_id

        # Non-existent query
        assert workspace.get_session("non_existent_id") is None

    def test_events_queryable_in_workspace(self, service, sample_traces):
        """Verify individual VoiceEvents can be inspected by ID."""
        workspace = service.ingest_trace_contents(sample_traces)

        first_event = workspace.events[0]
        found_ev = workspace.get_event(first_event.id)
        assert found_ev is not None
        assert found_ev.id == first_event.id

        assert workspace.get_event("invalid_event_id") is None

    def test_timeline_ordering_and_timestamps(self, service, sample_traces):
        """Verify timeline timestamps are extracted."""
        workspace = service.ingest_trace_contents(sample_traces)

        assert "start_time" in workspace.timestamps
        assert "end_time" in workspace.timestamps
        assert workspace.timestamps["start_time"] is not None

    def test_architecture_detection_from_real_evidence(self, service):
        """Verify architecture detection is derived from evidence, not hardcoded."""
        mixed_path = ROOT_DIR / "sample_data" / "mixed" / "sample_mixed_gateway.txt"
        if mixed_path.exists():
            text = mixed_path.read_text(encoding="utf-8")
            workspace = service.ingest_trace_contents([("sample_mixed_gateway.txt", text)])

            # Architecture should be detected (ISDN_MGCP or ISDN_SIP)
            assert workspace.architecture != "UNKNOWN"
            assert "ISDN" in workspace.architecture

    def test_persistence_and_rehydration(self, service, sample_traces, tmp_path):
        """Verify analysis manifest saves to disk and survives service re-instantiation."""
        workspace = service.ingest_trace_contents(sample_traces, trace_ids=["req_persist"])
        ws_id = workspace.workspace_id
        event_count = len(workspace.events)
        session_count = len(workspace.call_sessions)

        assert service.has_saved_workspace() is True

        # Simulate browser refresh / fresh service instance
        rehydrated_service = AnalysisPipelineService(storage_dir=tmp_path / "voiceops_traces")
        rehydrated = rehydrated_service.load_saved_workspace()

        assert rehydrated is not None
        assert rehydrated.workspace_id == ws_id
        assert len(rehydrated.events) == event_count
        assert len(rehydrated.call_sessions) == session_count
        assert rehydrated.trace_ids == ["req_persist"]

    def test_clear_saved_workspace(self, service, sample_traces):
        """Verify clearing saved analysis removes manifest."""
        service.ingest_trace_contents(sample_traces)
        assert service.has_saved_workspace() is True

        assert service.clear_saved_workspace() is True
        assert service.has_saved_workspace() is False
        assert service.load_saved_workspace() is None

    def test_ingest_manifests(self, service, tmp_path):
        """Verify ingesting TraceManifest objects."""
        # Create a sample extracted .txt file
        ext_file = tmp_path / "extracted" / "10_197_206_141" / "req_m1" / "sample.txt"
        ext_file.parent.mkdir(parents=True, exist_ok=True)
        ext_file.write_text(
            "09/20/2026 12:00:00.100 | ISDN cc_setup_req: calling=1001 called=2001\n",
            encoding="utf-8",
        )

        manifest = TraceManifest(
            request_id="req_m1",
            node="10_197_206_141",
            original_filename="sample.txt.gzo",
            normalized_filename="sample.txt",
            extracted_path=str(ext_file.resolve()),
        )

        workspace = service.ingest_manifests([manifest])
        assert workspace.trace_ids == ["req_m1"]
        assert len(workspace.source_files) == 1
        assert len(workspace.events) > 0
