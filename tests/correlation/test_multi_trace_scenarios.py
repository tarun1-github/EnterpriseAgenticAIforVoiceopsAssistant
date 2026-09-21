"""Comprehensive tests for all 22 VoiceOps multi-trace correlation scenarios (Requirement 28)."""

from datetime import datetime, timezone
import pytest

from app.analysis.architecture import detect_call_architecture
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.correlation.engine import CorrelationEngine
from app.correlation.ladder import CallLifecycleLadder
from app.models.call_session import CallArchitecture, CallSession
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.classifier import TraceClassifier
from app.parsers.ingestion import TraceIngestionEngine


# Sample raw trace contents for fixtures
SAMPLE_ISDN_RAW = """*Sep 20 10:12:18.231: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0042
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

SAMPLE_SIP_RAW = """*Sep 20 10:12:18.281: //1234/ccsipDisplayMsg:
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

SAMPLE_MGCP_RAW = """*Sep 20 10:12:18.244: MGCP Packet received from 10.197.206.141:2427
CRCX 4501 s0/su1/ds1-0/3@vg01.cisco.com MGCP 0.1
C: 0000000000000001
M: recvonly

*Sep 20 10:12:18.248: MGCP Packet sent to 10.197.206.141:2427
200 4501 OK
I: 998877
"""

SAMPLE_CUCM_SDL_RAW = """00602801.000 |10:12:18.235 |AppInfo  |FileHead : Version : 15.0.1.10000-87
00602802.000 |10:12:18.284 |SdlSig   |CcSetupReq                             |wait                           |StationInit(1,100,14,5)         |Cc(1,100,14,1)                  |1,100,14,1.5^*                 |[R:N-H:0,P:0,D:0,伴:0,E:0,B:0,T:0,S:0] CI=554433 AppCorr:9876543210 callingPartyNumber=9876543210 calledPartyNumber=1800123456
00602803.000 |10:12:18.285 |SdlSig   |SIPHandler                             |wait                           |SIPD(1,100,14,10)               |CallManager(1,100,14,1)         |1,100,14,1.6^*                 |CI=554433 Call-ID: call-9876543210-unique@10.197.206.150
00602804.000 |10:12:18.320 |SdlSig   |StationOutputCallState                 |wait                           |StationInit(1,100,14,5)         |CallManager(1,100,14,1)         |1,100,14,1.7^*                 |CI=554433 SEP001122334455 CallState=RING_OUT
00602805.000 |10:12:25.815 |SdlSig   |CcDisconnectReq                        |wait                           |StationInit(1,100,14,5)         |Cc(1,100,14,1)                  |1,100,14,1.8^*                 |CI=554433
"""


class TestVoiceOpsMultiTraceScenarios:
    """Validate all 22 required VoiceOps troubleshooting trace scenarios."""

    @pytest.fixture
    def ingestion(self):
        return TraceIngestionEngine()

    @pytest.fixture
    def correlation(self):
        return CorrelationEngine()

    # 1. CUCM SDL only
    def test_01_cucm_sdl_only(self, ingestion, correlation):
        events = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="cucm_sdl_log.txt")
        assert len(events) > 0
        sessions = correlation.correlate(events)
        assert len(sessions) >= 1
        assert sessions[0].calling_number == "9876543210"
        assert sessions[0].called_number == "1800123456"

    # 2. ISDN only
    def test_02_isdn_only(self, ingestion, correlation):
        events = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="isdn_debug.txt")
        assert len(events) >= 5
        sessions = correlation.correlate(events)
        assert len(sessions) == 1
        assert sessions[0].calling_number == "9876543210"
        assert sessions[0].called_number == "1800123456"
        assert "0x0042" in sessions[0].isdn_call_references or "0x8042" in sessions[0].isdn_call_references or "0x0042" in [r.lower() for r in sessions[0].isdn_call_references]

    # 3. SIP only
    def test_03_sip_only(self, ingestion, correlation):
        events = ingestion.ingest_content(SAMPLE_SIP_RAW, source="sip_debug.txt")
        assert len(events) >= 4
        sessions = correlation.correlate(events)
        assert len(sessions) == 1
        assert "call-9876543210-unique@10.197.206.150" in sessions[0].sip_call_ids

    # 4. MGCP only
    def test_04_mgcp_only(self, ingestion, correlation):
        events = ingestion.ingest_content(SAMPLE_MGCP_RAW, source="mgcp_debug.txt")
        assert len(events) >= 2
        sessions = correlation.correlate(events)
        assert len(sessions) == 1
        assert "4501" in sessions[0].mgcp_transaction_ids

    # 5. SDL + ISDN
    def test_05_sdl_plus_isdn(self, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="cucm_sdl.txt")
        ev2 = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="isdn_gw.txt")
        sessions = correlation.correlate(ev1 + ev2)
        assert len(sessions) == 1
        assert sessions[0].calling_number == "9876543210"
        assert "cucm_sdl.txt" in sessions[0].trace_sources
        assert "isdn_gw.txt" in sessions[0].trace_sources

    # 6. SDL + SIP
    def test_06_sdl_plus_sip(self, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="cucm_sdl.txt")
        ev2 = ingestion.ingest_content(SAMPLE_SIP_RAW, source="vg_sip.txt")
        sessions = correlation.correlate(ev1 + ev2)
        assert len(sessions) == 1
        assert "call-9876543210-unique@10.197.206.150" in sessions[0].sip_call_ids

    # 7. SDL + ISDN + SIP
    def test_07_sdl_plus_isdn_plus_sip(self, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="cucm_trace.txt")
        ev2 = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="router_isdn.txt")
        ev3 = ingestion.ingest_content(SAMPLE_SIP_RAW, source="router_sip.txt")
        sessions = correlation.correlate(ev1 + ev2 + ev3)
        assert len(sessions) == 1
        session = sessions[0]
        assert len(session.trace_sources) == 3
        assert session.architecture in [CallArchitecture.ISDN_SIP, CallArchitecture.ISDN_MGCP]
        assert session.confidence_level == "High"

    # 8. SDL + ISDN + MGCP + SIP
    def test_08_sdl_plus_isdn_plus_mgcp_plus_sip(self, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="cucm.txt")
        ev2 = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="gw_isdn.txt")
        ev3 = ingestion.ingest_content(SAMPLE_MGCP_RAW, source="gw_mgcp.txt")
        ev4 = ingestion.ingest_content(SAMPLE_SIP_RAW, source="gw_sip.txt")
        sessions = correlation.correlate(ev1 + ev2 + ev3 + ev4)
        assert len(sessions) == 1
        assert sessions[0].architecture == CallArchitecture.ISDN_MGCP

    # 9. Multiple simultaneous calls
    def test_09_multiple_simultaneous_calls(self, ingestion, correlation):
        call1_isdn = SAMPLE_ISDN_RAW
        call2_isdn = """*Sep 20 10:12:18.235: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0099
    Calling Party Number i = 0x0081, '5551234567'
    Called Party Number i = 0x81, '5559876543'
*Sep 20 10:12:18.260: ISDN Se0/1/0:23 Q931: TX -> CALL_PROC pd = 8  callref = 0x8099
"""
        ev1 = ingestion.ingest_content(call1_isdn, source="gw1.txt")
        ev2 = ingestion.ingest_content(call2_isdn, source="gw2.txt")
        sessions = correlation.correlate(ev1 + ev2)
        # Must produce 2 separate CallSessions without false merging
        assert len(sessions) == 2
        numbers = {s.calling_number for s in sessions}
        assert "9876543210" in numbers
        assert "5551234567" in numbers

    # 10. Different timezones
    def test_10_different_timezones(self, ingestion):
        events = ingestion.ingest_content(
            SAMPLE_ISDN_RAW,
            source="isdn_utc.txt",
            metadata_override={"timezone": "UTC"},
        )
        assert len(events) > 0
        first = events[0]
        assert first.timestamp is not None
        assert "IST" in first.timestamp_ist_str

    # 11. Missing call identifiers
    def test_11_missing_call_identifiers(self, ingestion, correlation):
        raw_partial = """*Sep 20 10:12:18.231: ISDN Se0/1/0:23 Q931: RX <- SETUP
    Calling Party Number i = 0x0081, '9876543210'
    Called Party Number i = 0x81, '1800123456'
*Sep 20 10:12:18.281: //ccsipDisplayMsg:
Sent:
INVITE sip:1800123456@10.197.206.141 SIP/2.0
From: <sip:9876543210@10.197.206.150>
To: <sip:1800123456@10.197.206.141>
"""
        ev1 = ingestion.ingest_content(raw_partial, source="partial.txt")
        sessions = correlation.correlate(ev1)
        assert len(sessions) == 1
        # Correlated via calling and called numbers without callref/call-id
        assert sessions[0].calling_number == "9876543210"

    # 12. Missing numbers
    def test_12_missing_numbers(self, ingestion, correlation):
        raw_id_only = """*Sep 20 10:12:18.281: //1234/ccsipDisplayMsg:
Sent:
INVITE sip:unknown@10.197.206.141 SIP/2.0
Call-ID: shared-token-xyz@10.197.206.150

*Sep 20 10:12:18.290: //1234/ccsipDisplayMsg:
Received:
SIP/2.0 100 Trying
Call-ID: shared-token-xyz@10.197.206.150
"""
        events = ingestion.ingest_content(raw_id_only, source="id_only.txt")
        sessions = correlation.correlate(events)
        assert len(sessions) == 1
        assert "shared-token-xyz@10.197.206.150" in sessions[0].sip_call_ids

    # 13. Ambiguous correlations
    def test_13_ambiguous_correlations(self, ingestion, correlation):
        # Two calls 2 seconds apart without shared IDs
        call1 = """*Sep 20 10:12:18.000: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0001\n"""
        call2 = """*Sep 20 10:12:20.000: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0002\n"""
        ev1 = ingestion.ingest_content(call1, source="c1.txt")
        ev2 = ingestion.ingest_content(call2, source="c2.txt")
        sessions = correlation.correlate(ev1 + ev2)
        assert len(sessions) == 2
        # Ambiguity notes should be captured
        all_notes = [n for s in sessions for n in s.ambiguity_notes]
        assert len(all_notes) > 0

    # 14. Incorrect filename but recognizable content (Section 1)
    def test_14_incorrect_filename_content_based(self, ingestion):
        clf = TraceClassifier()
        # Content is ISDN, but filename says cucm_trace.txt
        res = clf.classify(SAMPLE_ISDN_RAW, filename="cucm_trace.txt")
        assert res.trace_type == "ISDN_Q931"
        assert res.device_type == "VOICE_GATEWAY"
        assert res.confidence >= 0.80

    # 15. Unknown trace format
    def test_15_unknown_trace_format(self, ingestion):
        raw_unknown = "Some arbitrary system kernel message with no signaling tokens\n"
        events = ingestion.ingest_content(raw_unknown, source="random.txt")
        assert len(events) >= 1
        assert events[0].protocol == ProtocolEnum.UNKNOWN

    # 16. Architecture detection (Section 15, 16)
    def test_16_architecture_detection(self, ingestion, correlation):
        ev_isdn = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="isdn.txt")
        ev_sip = ingestion.ingest_content(SAMPLE_SIP_RAW, source="sip.txt")
        sessions = correlation.correlate(ev_isdn + ev_sip)
        assert len(sessions) == 1
        assert sessions[0].architecture == CallArchitecture.ISDN_SIP
        assert "ISDN PRI" in sessions[0].architecture_flow_vertical

    # 17. Ladder generation (Section 17)
    def test_17_ladder_generation(self, ingestion, correlation):
        ev_isdn = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="isdn.txt")
        ev_sip = ingestion.ingest_content(SAMPLE_SIP_RAW, source="sip.txt")
        sessions = correlation.correlate(ev_isdn + ev_sip)
        ladder = CallLifecycleLadder()
        ladder_txt = ladder.generate_ascii_ladder(sessions[0])
        assert "PSTN" in ladder_txt
        assert "Voice Gateway" in ladder_txt
        assert "CUCM" in ladder_txt
        assert "Phone" in ladder_txt

    # 18. SDL evidence placement (Section 19: SDL is internal CUCM leg)
    def test_18_sdl_evidence_placement(self, ingestion, correlation):
        ev_sdl = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="sdl.txt")
        sessions = correlation.correlate(ev_sdl)
        ladder = CallLifecycleLadder()
        steps = ladder.build_ladder(sessions[0])
        sdl_steps = [s for s in steps if s.is_internal_cucm]
        assert len(sdl_steps) > 0
        for s in sdl_steps:
            assert s.actor_from == "CUCM"
            assert s.actor_to == "CUCM"
            assert s.is_internal_cucm is True

    # 19. Event source-file tracking (Section 18)
    def test_19_event_source_file_tracking(self, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="file_A.txt")
        ev2 = ingestion.ingest_content(SAMPLE_SIP_RAW, source="file_B.txt")
        sessions = correlation.correlate(ev1 + ev2)
        ladder = CallLifecycleLadder()
        steps = ladder.build_ladder(sessions[0])
        source_files = {s.source_file for s in steps}
        assert "file_A.txt" in source_files
        assert "file_B.txt" in source_files

    # 20. Cross-file correlation confidence (Section 25)
    def test_20_cross_file_correlation_confidence(self, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_CUCM_SDL_RAW, source="cucm.txt")
        ev2 = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="isdn.txt")
        sessions = correlation.correlate(ev1 + ev2)
        assert len(sessions) == 1
        assert sessions[0].confidence_level in ["High", "Medium"]
        assert sessions[0].correlation_confidence >= 0.70

    # 21. No false correlation (Section 26)
    def test_21_no_false_correlation_different_calls(self, ingestion, correlation):
        # Two calls at exact same second with different phone numbers
        call_alpha = """*Sep 20 10:12:18.000: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0001
    Calling Party Number i = 0x0081, '1111111111'
    Called Party Number i = 0x81, '2222222222'
"""
        call_beta = """*Sep 20 10:12:18.005: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0002
    Calling Party Number i = 0x0081, '9999999999'
    Called Party Number i = 0x81, '8888888888'
"""
        ev1 = ingestion.ingest_content(call_alpha, source="alpha.txt")
        ev2 = ingestion.ingest_content(call_beta, source="beta.txt")
        sessions = correlation.correlate(ev1 + ev2)
        # Must NEVER merge different calls occurring at the same timestamp
        assert len(sessions) == 2

    # 22. Agent receives only selected-call evidence (Section 20 & 28)
    def test_22_agent_receives_only_selected_call(self, tmp_path, ingestion, correlation):
        ev1 = ingestion.ingest_content(SAMPLE_ISDN_RAW, source="isdn.txt")
        call2_raw = """*Sep 20 10:30:00.000: ISDN Se0/1/0:23 Q931: RX <- SETUP pd = 8  callref = 0x0099
    Calling Party Number i = 0x0081, '4085551234'
    Called Party Number i = 0x81, '4085559999'
"""
        ev2 = ingestion.ingest_content(call2_raw, source="isdn2.txt")
        all_events = ev1 + ev2
        sessions = correlation.correlate(all_events)
        assert len(sessions) == 2

        ws = AnalysisWorkspace(
            events=all_events,
            call_sessions=sessions,
            source_files=["isdn.txt", "isdn2.txt"],
        )

        analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
        # Scope specifically to the first session
        target_session = sessions[0]
        res = analyzer.analyze(ws, selected_session_id=target_session.session_id)

        assert res.calling_number == target_session.calling_number
        assert res.called_number == target_session.called_number
        # Report should not contain call2's numbers in Selected Call
        assert f"Calling:\n{target_session.calling_number}" in res.markdown_report
        assert "4085551234" not in res.markdown_report[:res.markdown_report.find("## Trace Sources")]
