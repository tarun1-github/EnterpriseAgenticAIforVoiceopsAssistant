"""Comprehensive end-to-end integration tests for all 20 required enterprise features."""

import gzip
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.artifacts.models import TraceManifest
from app.artifacts.repository import TraceArtifactRepository
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.commands.models import CommandRequest, DeviceTypeEnum
from app.commands.safety import validate_command_safety, mask_secrets
from app.commands.history import CommandHistoryManager
from app.commands.service import DeviceCommandService
from app.devices.cucm.collector import CUCMTraceCollector, CollectionResult
from app.devices.cucm.client import CUCMClient
from app.devices.ios.transport import IOSVoiceGatewayTransport
from app.models.event import ProtocolEnum, DirectionEnum

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestEnterpriseTraceAndAnalysisIntegration:
    """Verifies Requirements 1 to 14: Persistent Storage, Library, Extraction, and Workspace."""

    def test_req_1_persistent_trace_manifest_creation(self, tmp_path):
        """Req 1: Persistent trace manifest contains all required metadata fields."""
        storage = tmp_path / "voiceops_traces"
        repo = TraceArtifactRepository(storage_dir=storage)

        manifest = repo.process_and_store_artifact(
            request_id="req_test_01",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"sample cucm sdl trace data line 1\n",
            cucm_timestamp="2026-09-20T12:00:00",
            trace_type="SDL_TRACE",
            transfer_method="sftp_file_get",
        )

        assert manifest.request_id == "req_test_01"
        assert manifest.node == "10_197_206_141"
        assert manifest.original_filename == "SDL001_100_000087.txt.gzo"
        assert manifest.normalized_filename == "SDL001_100_000087.txt"
        assert manifest.cucm_timestamp == "2026-09-20T12:00:00"
        assert manifest.trace_type == "SDL_TRACE"
        assert manifest.original_extension == ".gzo"
        assert Path(manifest.raw_path).exists()
        assert Path(manifest.extracted_path).exists()
        assert manifest.raw_size > 0
        assert manifest.extracted_size > 0
        assert manifest.raw_sha256 is not None
        assert manifest.extracted_sha256 is not None
        assert manifest.collection_timestamp is not None
        assert manifest.transfer_method == "sftp_file_get"
        assert manifest.extraction_method == "plain_copy_no_gunzip"
        assert manifest.validation_status == "Validated"

    def test_req_2_and_14_trace_library_discovery_and_rehydration(self, tmp_path):
        """Req 2 & 14: Trace inventory is reconstructed by scanning manifests after application reload."""
        storage = tmp_path / "voiceops_traces"
        repo1 = TraceArtifactRepository(storage_dir=storage)

        repo1.process_and_store_artifact(
            request_id="trace_a",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"Trace A content\n",
        )
        repo1.process_and_store_artifact(
            request_id="trace_b",
            node="10_197_206_141",
            filename="SDL001_100_000086.txt.gzo",
            raw_bytes=b"Trace B content\n",
        )

        # Fresh repository instance (simulating app restart / reload)
        repo2 = TraceArtifactRepository(storage_dir=storage)
        inventory = repo2.list_manifests()

        assert len(inventory) == 2
        file_names = {m.normalized_filename for m in inventory}
        assert "SDL001_100_000087.txt" in file_names
        assert "SDL001_100_000086.txt" in file_names

    def test_req_3_gzo_normalization_without_gunzip(self, tmp_path):
        """Req 3: .gzo trace is preserved raw and copied to .txt without gunzip decompression."""
        storage = tmp_path / "voiceops_traces"
        repo = TraceArtifactRepository(storage_dir=storage)
        raw_text = b"ASCII SDL text inside .gzo\n"

        manifest = repo.process_and_store_artifact(
            request_id="req_gzo",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=raw_text,
        )

        assert manifest.normalized_filename == "SDL001_100_000087.txt"
        assert manifest.extraction_method == "plain_copy_no_gunzip"
        assert Path(manifest.extracted_path).read_bytes() == raw_text

    def test_req_4_gz_decompression_to_txt(self, tmp_path):
        """Req 4: .gz trace is preserved raw and decompressed using gzip into .txt."""
        storage = tmp_path / "voiceops_traces"
        repo = TraceArtifactRepository(storage_dir=storage)
        plain = b"Original uncompressed trace text\n"
        compressed = gzip.compress(plain)

        manifest = repo.process_and_store_artifact(
            request_id="req_gz",
            node="10_197_206_141",
            filename="SDL001_100_000050.txt.gz",
            raw_bytes=compressed,
        )

        assert manifest.normalized_filename == "SDL001_100_000050.txt"
        assert manifest.extraction_method == "gzip_decompress"
        assert Path(manifest.extracted_path).read_bytes() == plain

    def test_req_5_txt_preservation(self, tmp_path):
        """Req 5: Plain .txt trace is preserved raw and copied directly to normalized .txt."""
        storage = tmp_path / "voiceops_traces"
        repo = TraceArtifactRepository(storage_dir=storage)
        plain = b"Plain uncompressed SDL text\n"

        manifest = repo.process_and_store_artifact(
            request_id="req_txt",
            node="10_197_206_141",
            filename="SDL001_100_000010.txt",
            raw_bytes=plain,
        )

        assert manifest.normalized_filename == "SDL001_100_000010.txt"
        assert manifest.extraction_method == "plain_copy"
        assert Path(manifest.extracted_path).read_bytes() == plain

    def test_req_6_download_button_reads_extracted_txt(self, tmp_path):
        """Req 6: Artifact download reads the extracted normalized .txt file rather than temp paths."""
        storage = tmp_path / "voiceops_traces"
        repo = TraceArtifactRepository(storage_dir=storage)

        manifest = repo.process_and_store_artifact(
            request_id="req_dl",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"Normalized text for UI download\n",
        )

        # Verify that reading from repo extracted text matches
        extracted_text = repo.get_extracted_text(manifest)
        assert extracted_text == "Normalized text for UI download\n"
        assert Path(manifest.extracted_path).suffix == ".txt"

    def test_req_7_and_8_ingest_and_workspace_creation(self, tmp_path):
        """Req 7 & 8: Ingesting selected traces creates a populated AnalysisWorkspace."""
        storage = tmp_path / "voiceops_traces"
        pipeline = AnalysisPipelineService(storage_dir=storage)

        sample_isdn = (ROOT_DIR / "sample_data" / "isdn" / "sample_isdn_call.txt").read_text(encoding="utf-8")
        sample_sip = (ROOT_DIR / "sample_data" / "sip" / "sample_sip_call.txt").read_text(encoding="utf-8")

        ws = pipeline.ingest_trace_contents(
            [("isdn.txt", sample_isdn), ("sip.txt", sample_sip)],
            trace_ids=["trace_1", "trace_2"],
        )

        assert isinstance(ws, AnalysisWorkspace)
        assert ws.workspace_id.startswith("ws_")
        assert ws.trace_ids == ["trace_1", "trace_2"]
        assert ws.ingestion_status == "READY"
        assert len(ws.events) > 0
        assert len(ws.call_sessions) > 0

    def test_req_9_call_sessions_receives_correlated_sessions(self, tmp_path):
        """Req 9: Call Sessions contains correlated sessions with identifiers and signaling metadata."""
        storage = tmp_path / "voiceops_traces"
        pipeline = AnalysisPipelineService(storage_dir=storage)
        sample_isdn = (ROOT_DIR / "sample_data" / "isdn" / "sample_isdn_call.txt").read_text(encoding="utf-8")

        ws = pipeline.ingest_trace_contents([("isdn.txt", sample_isdn)])

        assert len(ws.call_sessions) > 0
        session = ws.call_sessions[0]
        assert session.session_id is not None
        assert session.calling_number is not None
        assert session.called_number is not None
        assert len(session.events) > 0

    def test_req_10_unified_timeline_receives_events(self, tmp_path):
        """Req 10: Unified Timeline receives events sorted with timestamp, protocol, direction."""
        storage = tmp_path / "voiceops_traces"
        pipeline = AnalysisPipelineService(storage_dir=storage)
        sample_sip = (ROOT_DIR / "sample_data" / "sip" / "sample_sip_call.txt").read_text(encoding="utf-8")

        ws = pipeline.ingest_trace_contents([("sip.txt", sample_sip)])

        assert len(ws.events) > 0
        for ev in ws.events:
            assert ev.message_type is not None
            assert ev.protocol is not None
            assert ev.direction is not None

    def test_req_11_protocol_view_receives_events(self, tmp_path):
        """Req 11: Protocol View receives protocol events and exposes parsed attributes."""
        storage = tmp_path / "voiceops_traces"
        pipeline = AnalysisPipelineService(storage_dir=storage)
        sample_sip = (ROOT_DIR / "sample_data" / "sip" / "sample_sip_call.txt").read_text(encoding="utf-8")

        ws = pipeline.ingest_trace_contents([("sip.txt", sample_sip)])
        sip_events = [e for e in ws.events if e.protocol == ProtocolEnum.SIP]

        assert len(sip_events) > 0
        first_sip = sip_events[0]
        assert first_sip.call_id is not None
        assert first_sip.message_type is not None

    def test_req_12_event_inspector_receives_selected_event(self, tmp_path):
        """Req 12: Event Inspector retrieves event details, metadata, and raw text."""
        storage = tmp_path / "voiceops_traces"
        pipeline = AnalysisPipelineService(storage_dir=storage)
        sample_isdn = (ROOT_DIR / "sample_data" / "isdn" / "sample_isdn_call.txt").read_text(encoding="utf-8")

        ws = pipeline.ingest_trace_contents([("isdn.txt", sample_isdn)])
        ev = ws.events[0]

        retrieved = ws.get_event(ev.id)
        assert retrieved is not None
        assert retrieved.id == ev.id
        assert retrieved.raw != ""

    def test_req_13_architecture_detection_receives_real_evidence(self, tmp_path):
        """Req 13: Architecture detection is derived dynamically from trace evidence, without H.323."""
        storage = tmp_path / "voiceops_traces"
        pipeline = AnalysisPipelineService(storage_dir=storage)
        mixed_file = ROOT_DIR / "sample_data" / "mixed" / "sample_mixed_gateway.txt"

        if mixed_file.exists():
            text = mixed_file.read_text(encoding="utf-8")
            ws = pipeline.ingest_trace_contents([("mixed.txt", text)])

            assert "H323" not in ws.architecture
            assert "H.323" not in ws.architecture
            assert ws.architecture != "UNKNOWN"


class TestEnterpriseDeviceCommandCenterIntegration:
    """Verifies Requirements 15 to 20: Command Center, Safety, and Transports."""

    def test_req_15_cucm_command_execution_uses_cli_credentials(self):
        """Req 15: CUCM command execution uses CUCM CLI SSH transport with admin: prompt."""
        mock_cucm = MagicMock(spec=CUCMClient)
        mock_cucm.is_connected.return_value = True
        mock_cucm.execute_read_only.return_value = "Cisco Unified Communications Manager 15.0"
        mock_cucm.get_prompt.return_value = "admin:"

        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history, cucm_client=mock_cucm)

        req = CommandRequest(
            device_type=DeviceTypeEnum.CUCM,
            host="10.197.206.141",
            command="show version active",
        )
        resp = service.execute(req)

        assert resp.success is True
        assert resp.prompt == "admin:"
        assert "15.0" in resp.output
        mock_cucm.execute_read_only.assert_called_once_with("show version active")

    def test_req_16_and_17_ios_command_execution_and_transport_separation(self):
        """Req 16 & 17: IOS command execution uses separate IOS Netmiko connection without CUCM transport."""
        mock_cucm = MagicMock(spec=CUCMClient)
        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history, cucm_client=mock_cucm)

        with patch("app.commands.service.IOSVoiceGatewayTransport") as mock_ios_cls:
            mock_transport = MagicMock()
            mock_transport.__enter__.return_value = mock_transport
            mock_transport.send_command.return_value = "Gateway#show isdn status\nISDN BRI or PRI Layer 1 Status: ACTIVE"
            mock_ios_cls.return_value = mock_transport

            req = CommandRequest(
                device_type=DeviceTypeEnum.IOS,
                host="10.10.10.1",
                command="show isdn status",
            )
            resp = service.execute(req)

            assert resp.success is True
            assert "ACTIVE" in resp.output
            assert resp.prompt == "Gateway#"
            # CUCM client should NOT have been called
            mock_cucm.execute_read_only.assert_not_called()
            mock_transport.send_command.assert_called_once_with("show isdn status", timeout=30)

    def test_req_18_secrets_never_appear_in_output(self):
        """Req 18: Sensitive credentials, passwords, and private keys are redacted from command output."""
        raw_output = (
            "username voiceadmin password 7 0822455D0A16\n"
            "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\n"
            "snmp-server community private RW\n"
            "crypto isakmp key mysecretkey123 address 10.0.0.1\n"
        )
        masked = mask_secrets(raw_output)

        assert "0822455D0A16" not in masked
        assert "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0" not in masked
        assert "private" not in masked
        assert "mysecretkey123" not in masked
        assert "********" in masked

    def test_req_19_read_only_command_protection(self):
        """Req 19: State-altering and configuration commands are blocked before hitting the network device."""
        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history)

        blocked_commands = [
            "conf t",
            "configure terminal",
            "write memory",
            "reload",
            "erase startup-config",
            "no shutdown",
            "utils system restart",
        ]

        for cmd in blocked_commands:
            req = CommandRequest(device_type=DeviceTypeEnum.CUCM, host="10.197.206.141", command=cmd)
            resp = service.execute(req)
            assert resp.success is False
            assert "blocked" in resp.error.lower()

    def test_req_20_command_history_recording(self):
        """Req 20: Command history records requests, responses, execution time, and statuses."""
        history = CommandHistoryManager()
        mock_cucm = MagicMock(spec=CUCMClient)
        mock_cucm.is_connected.return_value = True
        mock_cucm.execute_read_only.return_value = "System status: OK"
        mock_cucm.get_prompt.return_value = "admin:"

        service = DeviceCommandService(history_manager=history, cucm_client=mock_cucm)

        service.execute(CommandRequest(device_type=DeviceTypeEnum.CUCM, host="10.197.206.141", command="show status"))
        service.execute(CommandRequest(device_type=DeviceTypeEnum.CUCM, host="10.197.206.141", command="conf t"))

        entries = history.get_entries()
        assert len(entries) == 2
        # Most recent first
        assert entries[0].status == "BLOCKED"
        assert entries[0].command == "conf t"
        assert entries[1].status == "SUCCESS"
        assert entries[1].command == "show status"
        assert entries[1].execution_time_seconds >= 0.0
