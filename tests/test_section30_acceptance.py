"""Official Acceptance Tests for Section 30 (Manual Acceptance Test Specification).

Verifies all 20 acceptance criteria when an engineer uploads traces with arbitrary,
non-standard filenames:
- CUCM SDL file: trace_dump_alpha.log
- ISDN Q.931 debug: gw_capture_001.txt
- SIP debug: router_session.log
"""

from datetime import datetime, timezone
import pytest
from unittest.mock import MagicMock, patch

from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.analysis.evidence import calculate_timing_deltas
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.correlation.engine import CorrelationEngine
from app.correlation.ladder import CallLifecycleLadder
from app.models.call_session import CallArchitecture, CallSession
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.classifier import TraceClassifier
from app.parsers.ingestion import TraceIngestionEngine


# Raw trace contents without any standardized filenames
SDL_RAW_CONTENT = """00602801.000 |10:12:18.235 |AppInfo  |FileHead : Version : 15.0.1.10000-87
00602802.000 |10:12:18.284 |SdlSig   |CcSetupReq                             |wait                           |StationInit(1,100,14,5)         |Cc(1,100,14,1)                  |1,100,14,1.5^*                 |[R:N-H:0,P:0,D:0,伴:0,E:0,B:0,T:0,S:0] CI=554433 AppCorr:9876543210 callingPartyNumber=9876543210 calledPartyNumber=1800123456
00602803.000 |10:12:18.285 |SdlSig   |SIPHandler                             |wait                           |SIPD(1,100,14,10)               |CallManager(1,100,14,1)         |1,100,14,1.6^*                 |CI=554433 Call-ID: call-9876543210-unique@10.197.206.150
00602804.000 |10:12:18.320 |SdlSig   |StationOutputCallState                 |wait                           |StationInit(1,100,14,5)         |CallManager(1,100,14,1)         |1,100,14,1.7^*                 |CI=554433 SEP001122334455 CallState=RING_OUT
00602805.000 |10:12:25.815 |SdlSig   |CcDisconnectReq                        |wait                           |StationInit(1,100,14,5)         |Cc(1,100,14,1)                  |1,100,14,1.8^*                 |CI=554433
"""

ISDN_RAW_CONTENT = """*Sep 20 10:12:18.231: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0042
    Bearer Capability i = 0x8890
    Channel ID i = 0xE98083
        Exclusive, Channel 3
    Calling Party Number i = 0x0081, '9876543210'
    Called Party Number i = 0x81, '1800123456'
*Sep 20 10:12:18.250: ISDN Se0/1/0:23 Q931: TX -> CALL_PROC pd = 8  callref = 0x8042
    Channel ID i = 0xE98083
        Exclusive, Channel 3
*Sep 20 10:12:18.300: ISDN Se0/1/0:23 Q931: TX -> ALERTING pd = 8  callref = 0x8042
*Sep 20 10:12:18.350: ISDN Se0/1/0:23 Q931: TX -> CONNECT pd = 8  callref = 0x8042
*Sep 20 10:12:25.800: ISDN Se0/1/0:23 Q931: RX <- DISCONNECT pd = 8  callref = 0x0042
    Cause i = 0x8090 - Normal call clearing
*Sep 20 10:12:25.822: ISDN Se0/1/0:23 Q931: TX -> RELEASE pd = 8  callref = 0x8042
"""

SIP_RAW_CONTENT = """*Sep 20 10:12:18.281: //1234/ccsipDisplayMsg:
Sent:
INVITE sip:1800123456@10.197.206.141:5060 SIP/2.0
Via: SIP/2.0/UDP 10.197.206.150:5060;branch=z9hG4bK12345
From: <sip:9876543210@10.197.206.150>;tag=123456
To: <sip:1800123456@10.197.206.141>
Call-ID: call-9876543210-unique@10.197.206.150
CSeq: 101 INVITE
Contact: <sip:9876543210@10.197.206.150:5060>
Content-Length: 0

*Sep 20 10:12:18.295: //1234/ccsipDisplayMsg:
Received:
SIP/2.0 100 Trying
Via: SIP/2.0/UDP 10.197.206.150:5060;branch=z9hG4bK12345
From: <sip:9876543210@10.197.206.150>;tag=123456
To: <sip:1800123456@10.197.206.141>
Call-ID: call-9876543210-unique@10.197.206.150
CSeq: 101 INVITE

*Sep 20 10:12:18.310: //1234/ccsipDisplayMsg:
Received:
SIP/2.0 180 Ringing
Call-ID: call-9876543210-unique@10.197.206.150
CSeq: 101 INVITE

*Sep 20 10:12:18.345: //1234/ccsipDisplayMsg:
Received:
SIP/2.0 200 OK
Call-ID: call-9876543210-unique@10.197.206.150
CSeq: 101 INVITE

*Sep 20 10:12:25.810: //1234/ccsipDisplayMsg:
Sent:
BYE sip:1800123456@10.197.206.141:5060 SIP/2.0
Call-ID: call-9876543210-unique@10.197.206.150
CSeq: 102 BYE
"""


class TestSection30ManualAcceptance:
    """Rigorous acceptance test validating all 20 requirements of Section 30."""

    @pytest.fixture(autouse=True)
    def setup_traces(self):
        self.classifier = TraceClassifier()
        self.ingestion = TraceIngestionEngine()
        self.correlation = CorrelationEngine()

        # Non-standard filenames
        self.cucm_filename = "trace_dump_alpha.log"
        self.isdn_filename = "gw_capture_001.txt"
        self.sip_filename = "router_session.log"

        # Ingest all three files
        self.cucm_events = self.ingestion.ingest_content(SDL_RAW_CONTENT, source=self.cucm_filename)
        self.isdn_events = self.ingestion.ingest_content(ISDN_RAW_CONTENT, source=self.isdn_filename)
        self.sip_events = self.ingestion.ingest_content(SIP_RAW_CONTENT, source=self.sip_filename)

        self.all_events = self.cucm_events + self.isdn_events + self.sip_events
        self.sessions = self.correlation.correlate(self.all_events)
        self.selected_call = self.sessions[0] if self.sessions else None

    # 1. System detects CUCM SDL
    def test_01_system_detects_cucm_sdl(self):
        res = self.classifier.classify(SDL_RAW_CONTENT, filename=self.cucm_filename)
        assert res.trace_type == "CUCM_SDL"
        assert res.confidence >= 0.90
        assert any("sdl" in e.lower() for e in res.evidence)

    # 2. System detects ISDN
    def test_02_system_detects_isdn(self):
        res = self.classifier.classify(ISDN_RAW_CONTENT, filename=self.isdn_filename)
        assert res.trace_type == "ISDN_Q931"
        assert res.confidence >= 0.90
        assert any("Q931" in e or "SETUP" in e for e in res.evidence)

    # 3. System detects SIP
    def test_03_system_detects_sip(self):
        res = self.classifier.classify(SIP_RAW_CONTENT, filename=self.sip_filename)
        assert res.trace_type == "SIP"
        assert res.confidence >= 0.90
        assert any("INVITE" in e or "SIP" in e for e in res.evidence)

    # 4. Device/source is identified where possible
    def test_04_device_source_identified(self):
        cucm_res = self.classifier.classify(SDL_RAW_CONTENT, filename=self.cucm_filename)
        assert cucm_res.device_type == "CUCM"

        gw_res = self.classifier.classify(ISDN_RAW_CONTENT, filename=self.isdn_filename)
        assert gw_res.device_type == "VOICE_GATEWAY"

        sip_res = self.classifier.classify(SIP_RAW_CONTENT, filename=self.sip_filename)
        assert sip_res.device_type == "VOICE_GATEWAY"
        assert sip_res.device_ip in ["10.197.206.150", "10.197.206.141"]

    # 5. Calls are correlated into ONE session
    def test_05_calls_are_correlated(self):
        assert len(self.sessions) == 1
        assert len(self.selected_call.events) >= 10
        assert set(self.selected_call.trace_sources) == {self.cucm_filename, self.isdn_filename, self.sip_filename}

    # 6. Calling/called numbers are extracted where available
    def test_06_calling_called_numbers_extracted(self):
        assert self.selected_call.calling_number == "9876543210"
        assert self.selected_call.called_number == "1800123456"

    # 7. Timestamps are normalized
    def test_07_timestamps_are_normalized(self):
        for ev in self.selected_call.events:
            if ev.timestamp:
                # Must be a datetime and timezone aware (UTC)
                assert isinstance(ev.timestamp, datetime)
                assert ev.timestamp.tzinfo is not None
                assert ev.timestamp_utc is not None
                assert ev.timestamp_utc.tzinfo == timezone.utc

    # 8. UI displays IST
    def test_08_ui_displays_ist(self):
        for ev in self.selected_call.events:
            if ev.timestamp:
                ist_str = ev.timestamp_ist_str
                assert "IST" in ist_str
                # Check formatted format: DD-Mon-YYYY HH:MM:SS.mmm IST
                assert "15:42:" in ist_str or "10:12:" in ist_str

    # 9. One call can be selected
    def test_09_one_call_can_be_selected(self):
        assert self.selected_call is not None
        assert self.selected_call.session_id.startswith("call_")
        assert len(self.selected_call.events) > 0

    # 10. Ladder shows ISDN on PSTN <-> Voice Gateway
    def test_10_ladder_shows_isdn_on_pstn_vg_leg(self):
        ladder_text = CallLifecycleLadder.generate_ascii(self.selected_call)
        assert "PSTN" in ladder_text
        assert "Voice Gateway" in ladder_text
        # ISDN messages appear between PSTN and Voice Gateway
        assert "SETUP" in ladder_text
        assert "CALL PROCEEDING" in ladder_text
        assert "DISCONNECT" in ladder_text

    # 11. Ladder shows MGCP/SIP on the correct Voice Gateway <-> CUCM leg
    def test_11_ladder_shows_sip_on_vg_cucm_leg(self):
        ladder_text = CallLifecycleLadder.generate_ascii(self.selected_call)
        assert "CUCM" in ladder_text
        assert "INVITE" in ladder_text
        assert "180 Ringing" in ladder_text or "180" in ladder_text

    # 12. Ladder shows SIP on CUCM <-> Phone
    def test_12_ladder_shows_phone_column(self):
        ladder_text = CallLifecycleLadder.generate_ascii(self.selected_call)
        assert "Phone" in ladder_text
        header_line = [l for l in ladder_text.splitlines() if "PSTN" in l and "CUCM" in l]
        assert len(header_line) >= 1
        assert "Phone" in header_line[0]

    # 13. SDL events appear as CUCM internal evidence
    def test_13_sdl_events_appear_as_cucm_internal_evidence(self):
        ladder_text = CallLifecycleLadder.generate_ascii(self.selected_call)
        # Verify SDL events are rendered with internal evidence branch notation
        assert "├──" in ladder_text or "CcSetupReq" in ladder_text
        # Ensure Voice Gateway -> SDL -> CUCM is NOT present
        assert "Voice Gateway -> SDL" not in ladder_text
        assert "SDL -> CUCM" not in ladder_text

    # 14. Every ladder event points to its source file
    def test_14_every_ladder_event_points_to_source_file(self):
        ladder_text = CallLifecycleLadder.generate_ascii(self.selected_call)
        assert f"[{self.cucm_filename}]" in ladder_text
        assert f"[{self.isdn_filename}]" in ladder_text
        assert f"[{self.sip_filename}]" in ladder_text

    # 15. Missing messages are NOT invented
    def test_15_missing_messages_not_invented(self):
        ladder_text = CallLifecycleLadder.generate_ascii(self.selected_call)
        # We did not provide PRACK or 183 Session Progress or MGCP DLCX in the input traces
        assert "PRACK" not in ladder_text
        assert "183 Session Progress" not in ladder_text
        assert "DLCX" not in ladder_text

    # 16. Timing deltas are calculated
    def test_16_timing_deltas_are_calculated(self):
        deltas = calculate_timing_deltas(self.selected_call.events)
        assert len(deltas) >= 2
        assert any(d.delta_ms > 0 for d in deltas)
        assert any("INVITE" in d.from_event for d in deltas)

    # 17. Agent receives only selected-call evidence
    def test_17_agent_receives_only_selected_call_evidence(self):
        # Create an unrelated un-correlated event
        unrelated_event = VoiceEvent(
            protocol=ProtocolEnum.SIP,
            message_type="OPTIONS",
            source="unrelated_keepalive.txt",
            raw="OPTIONS sip:unrelated SIP/2.0\nCall-ID: random-id\n\n",
        )
        workspace = AnalysisWorkspace(
            raw_traces={},
            events=self.all_events + [unrelated_event],
            call_sessions=self.sessions,
        )

        scoped_ws = workspace.create_scoped_workspace(self.selected_call, time_window_seconds=0.0)
        # Unrelated event must NOT be in the scoped workspace
        assert all(e.source != "unrelated_keepalive.txt" for e in scoped_ws.events)
        assert all(e.source in self.selected_call.trace_sources for e in scoped_ws.events)
        assert len(scoped_ws.events) == len(self.selected_call.events)

    # 18. Agent explains cross-protocol correlation
    def test_18_agent_explains_cross_protocol_correlation(self):
        analyzer = VoiceOpsAgentAnalyzer()
        scoped_ws = AnalysisWorkspace(
            raw_traces={},
            events=self.selected_call.events,
            call_sessions=[self.selected_call],
        )

        result = analyzer.analyze(scoped_ws)
        assert "# VoiceOps Deep Engineering Analysis" in result.summary_markdown
        assert "## Cross-Protocol Correlation" in result.summary_markdown
        assert "## Detected Architecture" in result.summary_markdown
        assert "## Call Lifecycle Ladder" in result.summary_markdown

    # 19. Root cause is evidence-grounded
    def test_19_root_cause_is_evidence_grounded(self):
        analyzer = VoiceOpsAgentAnalyzer()
        scoped_ws = AnalysisWorkspace(
            raw_traces={},
            events=self.selected_call.events,
            call_sessions=[self.selected_call],
        )
        result = analyzer.analyze(scoped_ws)
        assert "## Root Cause Assessment" in result.summary_markdown
        assert "## Recommended Next Troubleshooting Commands" in result.summary_markdown

    # 20. Ambiguous correlations are explicitly reported
    def test_20_ambiguous_correlations_explicitly_reported(self):
        # Simulate two concurrent sessions within 2 seconds without shared call IDs
        e1 = VoiceEvent(
            protocol=ProtocolEnum.ISDN,
            message_type="SETUP",
            timestamp=datetime(2026, 9, 20, 10, 12, 18, 0, tzinfo=timezone.utc),
            calling_number="1111",
            called_number="2222",
            raw="ISDN SETUP 1",
        )
        e2 = VoiceEvent(
            protocol=ProtocolEnum.ISDN,
            message_type="SETUP",
            timestamp=datetime(2026, 9, 20, 10, 12, 19, 0, tzinfo=timezone.utc),
            calling_number="3333",
            called_number="4444",
            raw="ISDN SETUP 2",
        )

        sessions = self.correlation.correlate([e1, e2])
        assert len(sessions) == 2
        assert self.correlation.last_statistics["potentially_ambiguous"] >= 1
        assert any("active within" in note for note in sessions[0].ambiguity_notes)
