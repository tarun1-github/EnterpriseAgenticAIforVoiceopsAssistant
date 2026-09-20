"""Explicit Acceptance Tests for Section 24 Requirements 1 through 20."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.artifacts.models import TraceManifest
from app.artifacts.repository import TraceArtifactRepository
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.analysis.architecture import detect_call_architecture, ArchitectureEvidence
from app.analysis.evidence import (
    extract_signaling_messages,
    extract_sdl_observations,
    calculate_timing_deltas,
    SDLObservation,
)
from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.agent.models import AgentAnalysisResult
from app.commands.models import CommandRequest, DeviceTypeEnum
from app.commands.safety import validate_command_safety, mask_secrets
from app.commands.history import CommandHistoryManager
from app.commands.service import DeviceCommandService
from app.commands.export import generate_command_filename, format_command_output_package, sanitize_command_for_filename
from app.devices.cucm.client import CUCMClient
from app.models.event import VoiceEvent, ProtocolEnum, DirectionEnum
from app.models.call_session import CallSession, CallArchitecture


@pytest.fixture
def temp_repo(tmp_path):
    storage = tmp_path / "voiceops_traces"
    return TraceArtifactRepository(storage_dir=storage)


class TestSection24AcceptanceRequirements:
    """Comprehensive test cases matching Section 24 requirements 1 to 20."""

    # 1. Quick command selection
    def test_01_quick_command_selection(self):
        cucm_suggestions = [
            "show version active",
            "show status",
            "utils service status",
            "show network eth0",
            "file list activelog /cm/trace/ccm/sdl detail",
        ]
        ios_suggestions = [
            "show version",
            "show isdn status",
            "show dial-peer voice summary",
            "show voice port summary",
            "show sip-ua status",
            "show call active voice",
            "show controllers t1",
        ]
        # Verify suggestions are valid read-only commands
        for cmd in cucm_suggestions + ios_suggestions:
            is_safe, reason = validate_command_safety(cmd)
            assert is_safe is True, f"Quick suggestion {cmd} failed safety check: {reason}"

    # 2. Editable ad-hoc command
    def test_02_editable_adhoc_command(self):
        # User modifies quick command or writes arbitrary read-only command
        adhoc_cmds = [
            "show risdb query",
            "show perf query class \"Cisco CallManager\"",
            "show interfaces",
            "show ip interface brief",
            "file list activelog /cm/trace/ccm/sdl detail",
        ]
        for cmd in adhoc_cmds:
            is_safe, reason = validate_command_safety(cmd)
            assert is_safe is True, f"Ad-hoc command {cmd} failed safety check: {reason}"

    # 3. CUCM command execution
    def test_03_cucm_command_execution(self):
        mock_cucm = MagicMock(spec=CUCMClient)
        mock_cucm.is_connected.return_value = True
        mock_cucm.execute_read_only.return_value = "Cisco Unified Communications Manager 15.0"
        mock_cucm.get_prompt.return_value = "admin:"

        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history, cucm_client=mock_cucm)

        req = CommandRequest(device_type=DeviceTypeEnum.CUCM, host="10.197.206.141", command="show version active")
        resp = service.execute(req)

        assert resp.success is True
        assert resp.prompt == "admin:"
        assert "15.0" in resp.output
        mock_cucm.execute_read_only.assert_called_once_with("show version active")

    # 4. IOS command execution
    def test_04_ios_command_execution(self):
        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history)

        with patch("app.commands.service.IOSVoiceGatewayTransport") as mock_ios_cls:
            mock_transport = MagicMock()
            mock_transport.__enter__.return_value = mock_transport
            mock_transport.send_command.return_value = "ISDN BRI or PRI Layer 1 Status: ACTIVE"
            mock_ios_cls.return_value = mock_transport

            req = CommandRequest(device_type=DeviceTypeEnum.IOS, host="10.10.10.1", command="show isdn status")
            resp = service.execute(req)

            assert resp.success is True
            assert "ACTIVE" in resp.output
            assert resp.prompt == "Gateway#"
            mock_transport.send_command.assert_called_once_with("show isdn status", timeout=30)

    # 5. Read-only command safety
    def test_05_readonly_command_safety(self):
        dangerous = [
            "configure terminal",
            "conf t",
            "write",
            "write memory",
            "copy running-config startup-config",
            "reload",
            "erase",
            "delete nvram:",
            "format flash:",
            "shutdown",
            "no shutdown",
            "no dial-peer voice 100",
            "utils system restart",
            "utils system reboot",
            "utils system shutdown",
            "file delete activelog test.txt",
        ]
        for cmd in dangerous:
            is_safe, reason = validate_command_safety(cmd)
            assert is_safe is False, f"Dangerous command '{cmd}' should have been blocked"
            assert "blocked" in reason.lower()

    # 6. Command output metadata
    def test_06_command_output_metadata(self):
        text = format_command_output_package(
            device_type="CUCM",
            ip="10.197.206.141",
            command="show version active",
            status="SUCCESS",
            output="Cisco Unified Communications Manager\nVersion 15.0.1",
            prompt="admin:",
            timestamp_str="2026-09-20 16:45:32 IST",
        )
        assert "VoiceOps AI - Device Command Output" in text
        assert "Device Type : CUCM" in text
        assert "Device IP   : 10.197.206.141" in text
        assert "Timestamp   : 2026-09-20 16:45:32 IST" in text
        assert "Command     : show version active" in text
        assert "Status      : SUCCESS" in text
        assert "REQUEST\n=======\n\nshow version active" in text
        assert "RESPONSE\n========\n\nadmin:show version active" in text

    # 7. Command output filename
    def test_07_command_output_filename(self):
        fixed_dt = datetime(2026, 9, 20, 16, 45, 32)
        fname = generate_command_filename("CUCM", "10.197.206.141", "show version active", dt=fixed_dt)
        assert fname == "CUCM_10.197.206.141_show-version-active_20260920_164532.txt"

    # 8. Trace manifest creation
    def test_08_trace_manifest_creation(self, temp_repo):
        manifest = temp_repo.process_and_store_artifact(
            request_id="req_m_1",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"sample trace content line\n",
            cucm_timestamp="2026-09-20T12:00:00",
            trace_type="SDL",
            transfer_method="sftp_file_get",
        )
        assert manifest.request_id == "req_m_1"
        assert manifest.normalized_filename == "SDL001_100_000087.txt"
        assert manifest.extraction_method == "plain_copy_no_gunzip"
        assert temp_repo.get_manifest_path("req_m_1").exists()

    # 9. Trace Library reload
    def test_09_trace_library_reload(self, temp_repo):
        temp_repo.process_and_store_artifact(
            request_id="req_re_1",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"trace content\n",
        )
        # Re-instantiate repository (simulating app restart / reload)
        fresh_repo = TraceArtifactRepository(storage_dir=temp_repo.storage_dir)
        manifests = fresh_repo.list_manifests()
        assert len(manifests) == 1
        assert manifests[0].request_id == "req_re_1"
        assert manifests[0].normalized_filename == "SDL001_100_000087.txt"

    # 10. TXT download
    def test_10_txt_download_evidence_package(self, temp_repo):
        manifest = temp_repo.process_and_store_artifact(
            request_id="req_dl_txt",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"00602802.000 |08:52:24.482 |FileHead |AppName: CCM\n",
            cucm_timestamp="2026-09-20T12:00:00",
        )
        export_text = temp_repo.generate_trace_export_text(manifest, download_timestamp="2026-09-20 16:45:32 IST")
        assert "VoiceOps AI - CUCM Trace Evidence" in export_text
        assert "Device IP   : 10.197.206.141" in export_text
        assert "CUCM File   : SDL001_100_000087.txt.gzo" in export_text
        assert "Normalized  : SDL001_100_000087.txt" in export_text
        assert "SHA256      : " in export_text
        assert "TRACE\n=====\n\n00602802.000 |08:52:24.482 |FileHead" in export_text

    # 11. AnalysisWorkspace creation
    def test_11_analysis_workspace_creation(self, tmp_path):
        pipeline = AnalysisPipelineService(storage_dir=tmp_path / "voiceops_traces")
        sample_isdn = "<PRI> ISDN Q.931 SETUP on Serial0/0/0:23 cr=0x8101\nISDN Q.931 CALL_PROCEEDING\n"
        ws = pipeline.ingest_trace_contents([("isdn.txt", sample_isdn)], trace_ids=["t1"])
        assert isinstance(ws, AnalysisWorkspace)
        assert ws.workspace_id.startswith("ws_")
        assert ws.ingestion_status == "READY"
        assert len(ws.events) > 0

    # 12. Analysis tab population
    def test_12_analysis_tab_population(self, tmp_path):
        pipeline = AnalysisPipelineService(storage_dir=tmp_path / "voiceops_traces")
        sample_dir = Path(__file__).parents[1] / "sample_data"
        isdn_text = (sample_dir / "isdn" / "sample_isdn_call.txt").read_text(encoding="utf-8")
        sip_text = (sample_dir / "sip" / "sample_sip_call.txt").read_text(encoding="utf-8")
        ws = pipeline.ingest_trace_contents([("isdn.txt", isdn_text), ("sip.txt", sip_text)])
        assert len(ws.events) >= 2
        assert ws.architecture is not None
        assert ws.protocol_counts.get("ISDN", 0) > 0
        assert ws.protocol_counts.get("SIP", 0) > 0

    # 13. Architecture detection for ISDN+MGCP+CUCM+SIP
    def test_13_architecture_detection_isdn_mgcp_cucm_sip(self):
        t0 = datetime(2026, 9, 20, 10, 32, 14)
        events = [
            VoiceEvent(raw="<PRI> ISDN Q.931 SETUP Serial0/0/0:23", timestamp=t0, protocol=ProtocolEnum.ISDN, direction=DirectionEnum.INBOUND, message_type="SETUP"),
            VoiceEvent(raw="CRCX 1234 s0/su1/ds1-0@vgr MGCP 0.1", timestamp=t0, protocol=ProtocolEnum.MGCP, direction=DirectionEnum.INBOUND, message_type="CRCX"),
            VoiceEvent(raw="00602822.000 |08:52:35.085 |AppInfo |MGCPHandler SdlSig", timestamp=t0, protocol=ProtocolEnum.MGCP, direction=DirectionEnum.INTERNAL, message_type="MGCPHandler"),
            VoiceEvent(raw="INVITE sip:2001@10.197.206.141 SIP/2.0", timestamp=t0, protocol=ProtocolEnum.SIP, direction=DirectionEnum.OUTBOUND, message_type="INVITE"),
        ]
        arch = detect_call_architecture(events)
        assert arch.architecture_name == "PSTN → ISDN PRI → Voice Gateway → MGCP → CUCM → SIP → Phone"
        assert arch.confidence == "High"
        assert "PSTN\n↓\nISDN PRI\n↓\nVoice Gateway\n↓\nMGCP\n↓\nCUCM\n↓\nSIP\n↓\nPhone" in arch.flow_vertical

    # 14. Architecture must NOT incorrectly report SIP Trunk for MGCP architecture
    def test_14_architecture_not_sip_trunk_for_mgcp(self):
        t0 = datetime(2026, 9, 20, 10, 32, 14)
        events = [
            VoiceEvent(raw="<PRI> ISDN Q.931 SETUP", timestamp=t0, protocol=ProtocolEnum.ISDN, direction=DirectionEnum.INBOUND, message_type="SETUP"),
            VoiceEvent(raw="CRCX 1234 s0/su1/ds1-0@vgr MGCP 0.1", timestamp=t0, protocol=ProtocolEnum.MGCP, direction=DirectionEnum.INBOUND, message_type="CRCX"),
            VoiceEvent(raw="INVITE sip:phone@10.1.1.1 SIP/2.0", timestamp=t0, protocol=ProtocolEnum.SIP, direction=DirectionEnum.OUTBOUND, message_type="INVITE"),
        ]
        arch = detect_call_architecture(events)
        assert "SIP Trunk" not in arch.architecture_name
        assert "SIP Trunk" not in arch.flow_vertical

    # 15. Agent analysis input construction
    def test_15_agent_analysis_input_construction(self, tmp_path):
        t0 = datetime(2026, 9, 20, 10, 32, 14)
        events = [
            VoiceEvent(raw="<PRI> ISDN Q.931 SETUP", timestamp=t0, protocol=ProtocolEnum.ISDN, direction=DirectionEnum.INBOUND, message_type="SETUP"),
            VoiceEvent(raw="CRCX 1234 s0/su1/ds1-0@vgr MGCP 0.1", timestamp=t0, protocol=ProtocolEnum.MGCP, direction=DirectionEnum.INBOUND, message_type="CRCX"),
        ]
        session = CallSession(session_id="call_99", architecture=CallArchitecture.ISDN_MGCP, events=events)
        ws = AnalysisWorkspace(events=events, call_sessions=[session], source_files=["SDL001_100_000087.txt"])

        analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        result = analyzer.analyze(ws)
        assert isinstance(result, AgentAnalysisResult)
        assert result.analysis_id.startswith("analysis_")
        assert len(result.executive_summary) > 0

    # 16. Evidence references
    def test_16_evidence_references(self):
        t0 = datetime(2026, 9, 20, 10, 32, 14)
        events = [
            VoiceEvent(
                raw="00602822.000 |08:52:35.085 |AppInfo |MGCPHandler received msg from: 10.197.206.240",
                timestamp=t0,
                protocol=ProtocolEnum.MGCP,
                direction=DirectionEnum.INBOUND,
                message_type="MGCPHandler",
                metadata={"source_file": "SDL001_100_000087.txt"},
            )
        ]
        obs = extract_sdl_observations(events, default_filename="SDL001_100_000087.txt")
        assert len(obs) > 0
        first = obs[0]
        assert first.filename == "SDL001_100_000087.txt"
        assert first.timestamp is not None
        assert "MGCP" in first.event_name or "MGCP" in (first.process_name or "")
        assert "10.197.206.240" in first.raw_evidence

    # 17. SDL analysis evidence mapping
    def test_17_sdl_analysis_evidence_mapping(self):
        t0 = datetime(2026, 9, 20, 8, 52, 35, 85000)
        events = [
            VoiceEvent(
                raw="00602823.000 |08:52:35.085 |SdlSig |MGCPNotify |wait |MGCPInit |MGCPHandler",
                timestamp=t0,
                protocol=ProtocolEnum.MGCP,
                direction=DirectionEnum.INTERNAL,
                message_type="MGCPNotify",
                metadata={"source_file": "SDL001_100_000087.txt"},
            )
        ]
        obs = extract_sdl_observations(events, default_filename="SDL001_100_000087.txt")
        assert len(obs) == 1
        assert obs[0].event_name == "MGCPNotify"
        assert "MGCPHandler" in obs[0].raw_evidence

    # 18. Analysis persistence
    def test_18_analysis_persistence(self, tmp_path):
        analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        t0 = datetime(2026, 9, 20, 10, 32, 14)
        events = [VoiceEvent(raw="ISDN SETUP", timestamp=t0, protocol=ProtocolEnum.ISDN, direction=DirectionEnum.INBOUND, message_type="SETUP")]
        ws = AnalysisWorkspace(events=events, source_files=["test.txt"])
        res1 = analyzer.analyze(ws)

        # Fresh instance
        fresh = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        loaded = fresh.load_saved_analysis()
        assert loaded is not None
        assert loaded.analysis_id == res1.analysis_id
        assert loaded.executive_summary == res1.executive_summary

    # 19. Refresh/reload
    def test_19_refresh_reload(self, tmp_path):
        pipeline = AnalysisPipelineService(storage_dir=tmp_path)
        ws = pipeline.ingest_trace_contents([("trace.txt", "ISDN SETUP\n")])
        pipeline.save_workspace(ws)

        # Re-read from disk
        reloaded = pipeline.load_saved_workspace()
        assert reloaded is not None
        assert reloaded.workspace_id == ws.workspace_id
        assert len(reloaded.events) == len(ws.events)

    # 20. Existing parser/correlation tests
    def test_20_existing_parser_correlation_compatibility(self):
        from app.parsers.isdn import ISDNParser
        from app.parsers.sip import SIPParser
        from app.parsers.mgcp import MGCPParser

        isdn = ISDNParser()
        sip = SIPParser()
        mgcp = MGCPParser()

        assert isdn is not None
        assert sip is not None
        assert mgcp is not None
