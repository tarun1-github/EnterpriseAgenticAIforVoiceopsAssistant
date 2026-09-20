"""Tests for VoiceOps deep engineering agent analyzer."""

from datetime import datetime
from pathlib import Path
import pytest

from app.analysis.workspace import AnalysisWorkspace
from app.analysis.architecture import detect_call_architecture
from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.agent.models import AgentAnalysisResult
from app.models.event import VoiceEvent, ProtocolEnum, DirectionEnum
from app.models.call_session import CallSession, CallArchitecture
from app.models.anomaly import CallAnomaly, AnomalySeverity, AnomalyCategory


def build_test_workspace() -> AnalysisWorkspace:
    t0 = datetime(2026, 9, 20, 10, 32, 14, 101000)
    t1 = datetime(2026, 9, 20, 10, 32, 14, 118000)
    t2 = datetime(2026, 9, 20, 10, 32, 14, 155000)
    t3 = datetime(2026, 9, 20, 10, 32, 15, 21000)

    events = [
        VoiceEvent(
            raw="<PRI> ISDN Q.931 SETUP on Serial0/0/0:23 cr=0x8101",
            timestamp=t0,
            protocol=ProtocolEnum.ISDN,
            direction=DirectionEnum.INBOUND,
            message_type="SETUP",
            call_reference="0x8101",
            metadata={"source_file": "SDL001_100_000087.txt"},
        ),
        VoiceEvent(
            raw="CRCX 1234 s0/su1/ds1-0@VGR.cciecollab.cisco.com MGCP 0.1",
            timestamp=t1,
            protocol=ProtocolEnum.MGCP,
            direction=DirectionEnum.INBOUND,
            message_type="CRCX",
            transaction_id="1234",
            metadata={"source_file": "SDL001_100_000087.txt"},
        ),
        VoiceEvent(
            raw="00602822.000 |08:52:35.085 |AppInfo |MGCPHandler received msg from: 10.197.206.240\nNTFY 852065671 *@VGR.cciecollab.cisco.com MGCP 0.1",
            timestamp=t2,
            protocol=ProtocolEnum.MGCP,
            direction=DirectionEnum.INBOUND,
            message_type="NTFY",
            transaction_id="852065671",
            metadata={"source_file": "SDL001_100_000087.txt"},
        ),
        VoiceEvent(
            raw="00602823.000 |08:52:35.085 |SdlSig |MGCPNotify |wait |MGCPInit |MGCPHandler",
            timestamp=t2,
            protocol=ProtocolEnum.MGCP,
            direction=DirectionEnum.INTERNAL,
            message_type="MGCPNotify",
            metadata={"source_file": "SDL001_100_000087.txt"},
        ),
        VoiceEvent(
            raw="INVITE sip:2001@10.197.206.141 SIP/2.0\nCall-ID: call-1234@cucm",
            timestamp=t3,
            protocol=ProtocolEnum.SIP,
            direction=DirectionEnum.OUTBOUND,
            message_type="INVITE",
            call_id="call-1234@cucm",
            metadata={"source_file": "SDL001_100_000087.txt"},
        ),
    ]

    arch_ev = detect_call_architecture(events)

    session = CallSession(
        session_id="call_001",
        architecture=CallArchitecture.ISDN_MGCP,
        calling_number="4085551000",
        called_number="2001",
        start_time=t0,
        end_time=t3,
        events=events,
        isdn_call_references=["0x8101"],
        mgcp_transaction_ids=["1234", "852065671"],
        sip_call_ids=["call-1234@cucm"],
    )

    return AnalysisWorkspace(
        trace_ids=["1095b756"],
        source_files=["SDL001_100_000087.txt"],
        events=events,
        call_sessions=[session],
        anomalies=[],
        architecture=arch_ev.architecture_name,
        architecture_evidence=arch_ev,
        timestamps={"start_time": t0.isoformat(), "end_time": t3.isoformat()},
        protocol_counts={"ISDN": 1, "MGCP": 3, "SIP": 1},
        ingestion_status="READY",
    )


class TestVoiceOpsAgentAnalyzer:
    """Test deep reasoning agent analysis, SDL investigation, and report structure."""

    def test_analyzer_generates_all_8_sections(self, tmp_path):
        analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        ws = build_test_workspace()

        result = analyzer.analyze(ws)

        assert isinstance(result, AgentAnalysisResult)
        assert result.analysis_id.startswith("analysis_")
        assert len(result.source_files) == 1
        assert result.source_files[0] == "SDL001_100_000087.txt"

        # Check section outputs
        # 1. Executive Summary
        assert len(result.executive_summary) > 20
        assert "PSTN → ISDN PRI → Voice Gateway → MGCP → CUCM → SIP → Phone" in result.executive_summary

        # 2. Detected Architecture
        assert result.architecture_name == "PSTN → ISDN PRI → Voice Gateway → MGCP → CUCM → SIP → Phone"
        assert "PSTN\n↓\nISDN PRI\n↓\nVoice Gateway\n↓\nMGCP\n↓\nCUCM\n↓\nSIP\n↓\nPhone" in result.architecture_flow
        assert result.architecture_confidence == "High"

        # 3. Call Flow
        assert len(result.call_flow) >= 3

        # 4. Signaling Analysis
        assert "ISDN" in result.signaling_analysis
        assert "SETUP" in result.signaling_analysis["ISDN"]
        assert "MGCP" in result.signaling_analysis
        assert "CRCX" in result.signaling_analysis["MGCP"]
        assert "SIP" in result.signaling_analysis
        assert "INVITE" in result.signaling_analysis["SIP"]

        # 5. CUCM SDL Analysis
        assert len(result.sdl_analysis) > 0
        first_sdl = result.sdl_analysis[0]
        assert first_sdl.filename == "SDL001_100_000087.txt"
        assert first_sdl.timestamp is not None
        assert first_sdl.interpretation is not None
        assert "MGCP" in first_sdl.event_name or "MGCP" in (first_sdl.process_name or "")

        # 6. Timing Analysis
        assert len(result.timing_analysis) > 0
        first_delta = result.timing_analysis[0]
        assert first_delta.delta_ms >= 0.0

        # 7. Anomaly Analysis
        assert isinstance(result.anomaly_analysis, list)

        # 8. Root Cause & Matrix
        assert result.root_cause_analysis is not None
        assert len(result.root_cause_analysis.facts) > 0
        assert len(result.root_cause_analysis.inferences) > 0

        # Markdown Report Formatting
        report = result.markdown_report
        assert "# VoiceOps AI Analysis" in report
        assert "## 1. Executive Summary" in report
        assert "## 2. Detected Architecture" in report
        assert "## 3. Call Flow" in report
        assert "## 4. Signaling Analysis" in report
        assert "## 5. CUCM SDL Analysis" in report
        assert "## 6. Timing Analysis" in report
        assert "## 7. Anomaly Analysis" in report
        assert "## 8. Root Cause / Most Likely Cause" in report
        assert "Facts" in report
        assert "Inferences" in report

    def test_analysis_persistence_and_rehydration(self, tmp_path):
        analyzer1 = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        ws = build_test_workspace()
        res1 = analyzer1.analyze(ws)

        # Check file exists on disk
        assert analyzer1.has_saved_analysis() is True
        assert analyzer1.analysis_file.exists()

        # Session 2: Reload with fresh analyzer instance
        analyzer2 = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        res2 = analyzer2.load_saved_analysis()

        assert res2 is not None
        assert res2.analysis_id == res1.analysis_id
        assert res2.architecture_name == res1.architecture_name
        assert len(res2.sdl_analysis) == len(res1.sdl_analysis)
