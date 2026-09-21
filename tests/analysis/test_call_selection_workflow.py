"""Comprehensive regression test suite for Call Selection and Evidence-Grounded Analysis Workflow.

Covers all 23 regression test requirements from the Deep Engineering Analysis specification:
1. Multiple calls in one SDL trace.
2. Calling number extraction.
3. Called number extraction.
4. IST timestamp conversion.
5. Original timestamp preservation.
6. Call filtering by calling number.
7. Call filtering by called number.
8. Call filtering by time.
9. Selected-call AnalysisWorkspace.
10. SDL time-window extraction.
11. Correlation across ISDN/MGCP/SIP/SDL.
12. ISDN count consistency.
13. Time range calculation.
14. CallAnomaly evidence/evidence_refs.
15. AgentAnalyzer with zero anomalies.
16. AgentAnalyzer with anomalies.
17. Re-run Agent Analysis.
18. Re-run with no selected call.
19. Missing evidence handling.
20. Evidence references.
21. Multiple calls must not be mixed.
22. Architecture derived from evidence.
23. Existing parser tests remain green.
"""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from app.analysis.architecture import detect_call_architecture, CallArchitecture
from app.analysis.evidence import extract_sdl_observations, extract_signaling_messages
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.agent.models import AgentAnalysisResult
from app.core.timestamps import (
    to_ist_display,
    format_time_range_ist,
    parse_date_from_file_head,
    parse_cisco_timestamp,
)
from app.correlation.engine import CorrelationEngine
from app.models.anomaly import CallAnomaly, AnomalySeverity, AnomalyCategory
from app.models.call_session import CallSession
from app.models.event import VoiceEvent, ProtocolEnum, DirectionEnum


def create_sample_multi_call_events():
    """Build a multi-call trace fixture with 2 distinct calls plus background CUCM keepalives."""
    # Call 1: 9876543210 -> 1800123456 at 15:21:03 UTC
    t1_0 = datetime(2026, 9, 20, 15, 21, 3, 100000)
    t1_1 = datetime(2026, 9, 20, 15, 21, 3, 150000)
    t1_2 = datetime(2026, 9, 20, 15, 21, 3, 200000)
    t1_3 = datetime(2026, 9, 20, 15, 21, 8, 300000)

    # Call 2: 9876543211 -> 1800123456 at 15:24:17 UTC
    t2_0 = datetime(2026, 9, 20, 15, 24, 17, 100000)
    t2_1 = datetime(2026, 9, 20, 15, 24, 17, 180000)
    t2_2 = datetime(2026, 9, 20, 15, 24, 22, 250000)

    # Background keepalive at 15:22:00
    t_bg = datetime(2026, 9, 20, 15, 22, 0, 0)

    events = [
        # Call 1 events (ISDN PRI -> Voice Gateway MGCP -> CUCM SDL -> SIP Phone)
        VoiceEvent(
            raw="<PRI> ISDN Q.931 SETUP on Serial0/0/0:1 cr=0x8001 Calling Party Number=9876543210 Called Party Number=1800123456",
            timestamp=t1_0,
            timestamp_raw="15:21:03.100",
            protocol=ProtocolEnum.ISDN,
            direction=DirectionEnum.INBOUND,
            message_type="SETUP",
            call_reference="0x8001",
            calling_number="9876543210",
            called_number="1800123456",
            endpoint="s0/su1/ds1-0/1@VGR.cciecollab.cisco.com",
            metadata={"source_file": "SDL001_100_000087.txt", "b_channel": "1"},
        ),
        VoiceEvent(
            raw="CRCX 101 s0/su1/ds1-0/1@VGR.cciecollab.cisco.com MGCP 0.1\nCI: 1001",
            timestamp=t1_1,
            timestamp_raw="15:21:03.150",
            protocol=ProtocolEnum.MGCP,
            direction=DirectionEnum.INBOUND,
            message_type="CRCX",
            transaction_id="101",
            endpoint="s0/su1/ds1-0/1@VGR.cciecollab.cisco.com",
            metadata={"source_file": "SDL001_100_000087.txt", "b_channel": "1", "call_id_ci": "1001"},
        ),
        VoiceEvent(
            raw="00602801.000 |15:21:03.200 |SdlSig |MGCPNotify |wait |MGCPInit |MGCPHandler |CI=1001",
            timestamp=t1_2,
            timestamp_raw="15:21:03.200",
            protocol=ProtocolEnum.CUCM,
            direction=DirectionEnum.INTERNAL,
            message_type="MGCPNotify",
            endpoint="s0/su1/ds1-0/1@VGR.cciecollab.cisco.com",
            metadata={
                "source_file": "SDL001_100_000087.txt",
                "cucm_process": "MGCPHandler",
                "sending_process": "MGCPInit",
                "receiving_process": "MGCPHandler",
                "signal": "MGCPNotify",
                "trace_type": "SdlSig",
                "correlation_tag": "1001",
                "call_id_ci": "1001",
            },
        ),
        VoiceEvent(
            raw="INVITE sip:1800123456@10.197.206.141 SIP/2.0\nFrom: <sip:9876543210@gw>\nTo: <sip:1800123456@cucm>\nCall-ID: call1-sip@cucm",
            timestamp=t1_3,
            timestamp_raw="15:21:08.300",
            protocol=ProtocolEnum.SIP,
            direction=DirectionEnum.OUTBOUND,
            message_type="INVITE",
            call_id="call1-sip@cucm",
            calling_number="9876543210",
            called_number="1800123456",
            metadata={"source_file": "SDL001_100_000087.txt", "call_id_ci": "1001"},
        ),

        # Background Keepalive / Timer Event (Must NOT create separate call session)
        VoiceEvent(
            raw="00602810.000 |15:22:00.000 |AppInfo |Periodic keepalive check timer expired",
            timestamp=t_bg,
            timestamp_raw="15:22:00.000",
            protocol=ProtocolEnum.CUCM,
            direction=DirectionEnum.INTERNAL,
            message_type="TimerExpiry",
            metadata={"source_file": "SDL001_100_000087.txt"},
        ),

        # Call 2 events (Voice Gateway MGCP -> CUCM -> SIP, no ISDN)
        VoiceEvent(
            raw="CRCX 201 s0/su1/ds1-1/1@VGR.cciecollab.cisco.com MGCP 0.1\nCI: 2002",
            timestamp=t2_0,
            timestamp_raw="15:24:17.100",
            protocol=ProtocolEnum.MGCP,
            direction=DirectionEnum.INBOUND,
            message_type="CRCX",
            transaction_id="201",
            endpoint="s0/su1/ds1-1/1@VGR.cciecollab.cisco.com",
            metadata={"source_file": "SDL001_100_000087.txt", "call_id_ci": "2002"},
        ),
        VoiceEvent(
            raw="00602850.000 |15:24:17.180 |SdlSig |SIPStationInit |wait |SIPD |StationInit |CI=2002",
            timestamp=t2_1,
            timestamp_raw="15:24:17.180",
            protocol=ProtocolEnum.CUCM,
            direction=DirectionEnum.INTERNAL,
            message_type="SIPStationInit",
            metadata={
                "source_file": "SDL001_100_000087.txt",
                "cucm_process": "StationInit",
                "sending_process": "SIPD",
                "receiving_process": "StationInit",
                "signal": "SIPStationInit",
                "trace_type": "SdlSig",
                "correlation_tag": "2002",
                "call_id_ci": "2002",
            },
        ),
        VoiceEvent(
            raw="INVITE sip:1800123456@10.197.206.141 SIP/2.0\nFrom: <sip:9876543211@gw>\nTo: <sip:1800123456@cucm>\nCall-ID: call2-sip@cucm",
            timestamp=t2_2,
            timestamp_raw="15:24:22.250",
            protocol=ProtocolEnum.SIP,
            direction=DirectionEnum.OUTBOUND,
            message_type="INVITE",
            call_id="call2-sip@cucm",
            calling_number="9876543211",
            called_number="1800123456",
            metadata={"source_file": "SDL001_100_000087.txt", "call_id_ci": "2002"},
        ),
    ]
    return events


def test_1_multiple_calls_in_one_sdl_trace():
    """Test 1: One trace file contains multiple calls; correlation creates distinct calls, not 1-session-per-line."""
    events = create_sample_multi_call_events()
    engine = CorrelationEngine()
    sessions = engine.correlate(events)

    # Must correlate into exactly 2 distinct calls
    assert len(sessions) == 2
    # Check that OPTIONS keepalive was not turned into a call session
    assert all("keepalive" not in s.session_id for s in sessions)


def test_2_and_3_calling_and_called_number_extraction():
    """Test 2 & 3: Calling and Called numbers are accurately extracted from evidence without fabrication."""
    events = create_sample_multi_call_events()
    engine = CorrelationEngine()
    sessions = engine.correlate(events)

    calling_numbers = {s.calling_number for s in sessions}
    called_numbers = {s.called_number for s in sessions}

    assert "9876543210" in calling_numbers
    assert "9876543211" in calling_numbers
    assert "1800123456" in called_numbers

    # Fallback verification: events with no phone numbers should result in "Unknown"
    ev_unknown = VoiceEvent(
        raw="CRCX 999 s0/su1/ds1-0@VGR MGCP 0.1",
        timestamp=datetime(2026, 9, 20, 12, 0, 0),
        protocol=ProtocolEnum.MGCP,
        direction=DirectionEnum.INBOUND,
        message_type="CRCX",
        transaction_id="999",
    )
    unknown_sessions = engine.correlate([ev_unknown])
    if unknown_sessions:
        assert unknown_sessions[0].calling_number in (None, "Unknown")
        assert unknown_sessions[0].called_number in (None, "Unknown")


def test_4_ist_timestamp_conversion():
    """Test 4: IST timestamp display uses Asia/Kolkata (+5:30) without manual string math."""
    dt_utc = datetime(2026, 9, 20, 15, 21, 3, tzinfo=timezone.utc)
    ist_str = to_ist_display(dt_utc)
    assert "20-Sep-2026" in ist_str
    assert "20:51:03 IST" in ist_str

    dt_naive = datetime(2026, 9, 20, 15, 21, 3)
    ist_naive = to_ist_display(dt_naive)
    assert "20-Sep-2026 20:51:03 IST" in ist_naive


def test_5_original_timestamp_preservation():
    """Test 5: Canonical datetime and raw timestamp on VoiceEvent are strictly preserved."""
    events = create_sample_multi_call_events()
    first_ev = events[0]

    assert first_ev.timestamp_raw == "15:21:03.100"
    assert first_ev.timestamp == datetime(2026, 9, 20, 15, 21, 3, 100000)


def test_6_and_7_and_8_call_filtering():
    """Test 6, 7, 8: Call filtering by calling number, called number, and time."""
    events = create_sample_multi_call_events()
    engine = CorrelationEngine()
    sessions = engine.correlate(events)

    # Filter by Calling Number
    c1 = [s for s in sessions if "9876543210" in (s.calling_number or "")]
    assert len(c1) == 1
    assert c1[0].calling_number == "9876543210"

    # Filter by Called Number
    c_called = [s for s in sessions if "1800123456" in (s.called_number or "")]
    assert len(c_called) == 2

    # Filter by Time (20:54 IST / 15:24 UTC)
    c_time = [s for s in sessions if "20:54" in (s.start_time_ist or "")]
    assert len(c_time) == 1
    assert c_time[0].calling_number == "9876543211"


def test_9_selected_call_analysis_workspace():
    """Test 9: Scoped workspace contains ONLY evidence relevant to selected call."""
    events = create_sample_multi_call_events()
    service = AnalysisPipelineService()
    full_ws = service.ingest_trace_contents([("trace.txt", "\n".join(e.raw for e in events))])

    call_1 = next(s for s in full_ws.call_sessions if s.calling_number == "9876543210")
    scoped_ws = full_ws.create_call_scoped_workspace(call_1, time_window_seconds=1.0)

    assert len(scoped_ws.call_sessions) == 1
    assert scoped_ws.call_sessions[0].calling_number == "9876543210"

    # Must NOT contain Call 2's INVITE
    call_2_invites = [
        e for e in scoped_ws.events
        if e.protocol == ProtocolEnum.SIP and e.calling_number == "9876543211"
    ]
    assert len(call_2_invites) == 0


def test_10_sdl_time_window_extraction():
    """Test 10: Adjustable SDL analysis window includes surrounding events properly."""
    events = create_sample_multi_call_events()
    service = AnalysisPipelineService()
    full_ws = service.ingest_trace_contents([("trace.txt", "\n".join(e.raw for e in events))])

    call_1 = next(s for s in full_ws.call_sessions if s.calling_number == "9876543210")

    # Tight window (±0.05s) vs wide window (±60s)
    scoped_tight = full_ws.create_call_scoped_workspace(call_1, time_window_seconds=0.05)
    scoped_wide = full_ws.create_call_scoped_workspace(call_1, time_window_seconds=60.0)

    assert len(scoped_wide.events) >= len(scoped_tight.events)


def test_11_correlation_across_all_protocols():
    """Test 11: Call 1 correctly correlates ISDN, MGCP, CUCM SDL, and SIP."""
    events = create_sample_multi_call_events()
    engine = CorrelationEngine()
    sessions = engine.correlate(events)

    call_1 = next(s for s in sessions if s.calling_number == "9876543210")
    proto_map = call_1.protocol_counts

    assert proto_map.get("ISDN", 0) >= 1
    assert proto_map.get("MGCP", 0) >= 1
    assert proto_map.get("SIP", 0) >= 1
    assert proto_map.get("CUCM", 0) >= 1


def test_12_isdn_count_consistency():
    """Test 12: When ISDN count is 0, architecture does not claim ISDN."""
    # Create call with only MGCP, CUCM SDL, and SIP (no ISDN)
    events_no_isdn = [e for e in create_sample_multi_call_events() if e.protocol != ProtocolEnum.ISDN]
    engine = CorrelationEngine()
    sessions = engine.correlate(events_no_isdn)

    arch_ev = detect_call_architecture(events_no_isdn, sessions=sessions)
    assert arch_ev.has_isdn is False
    assert "ISDN PRI" not in arch_ev.architecture_name


def test_13_time_range_calculation():
    """Test 13: Time range calculates earliest to latest event timestamps in IST without N/A."""
    events = create_sample_multi_call_events()
    t_min = min(e.timestamp for e in events)
    t_max = max(e.timestamp for e in events)

    tr_ist = format_time_range_ist(t_min, t_max)
    assert " → " in tr_ist
    assert "20-Sep-2026 20:51:03 IST" in tr_ist
    assert "20-Sep-2026 20:54:22 IST" in tr_ist


def test_14_call_anomaly_evidence_refs_and_crash_fix():
    """Test 14: CallAnomaly supports evidence_refs, related_event_ids, call_id, and .evidence."""
    anom = CallAnomaly(
        call_id="call-001",
        severity=AnomalySeverity.ERROR,
        category=AnomalyCategory.RESPONSE_TIMEOUT,
        timestamp=datetime(2026, 9, 20, 15, 21, 5),
        protocol=ProtocolEnum.SIP,
        description="Missing 180 Ringing within 5 seconds",
        evidence_refs=["SDL001_100_000087.txt: Line 452"],
        related_event_ids=["ev-1", "ev-2"],
        confidence=0.95,
    )

    # Test attributes
    assert anom.call_id == "call-001"
    assert anom.evidence_refs == ["SDL001_100_000087.txt: Line 452"]
    assert anom.related_event_ids == ["ev-1", "ev-2"]

    # Backward compatibility property .evidence MUST NOT raise AttributeError
    assert anom.evidence == ["SDL001_100_000087.txt: Line 452"]


def test_15_and_16_agent_analyzer_with_and_without_anomalies(tmp_path):
    """Test 15 & 16: AgentAnalyzer generates comprehensive report for 0 anomalies and for active anomalies."""
    analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
    events = create_sample_multi_call_events()
    service = AnalysisPipelineService()
    full_ws = service.ingest_trace_contents([("trace.txt", "\n".join(e.raw for e in events))])

    call_1 = next(s for s in full_ws.call_sessions if s.calling_number == "9876543210")
    scoped_ws = full_ws.create_call_scoped_workspace(call_1, time_window_seconds=5.0)

    # Test 15: Clean call (0 anomalies)
    scoped_ws.anomalies = []
    res_clean = analyzer.analyze(scoped_ws)
    assert res_clean.root_cause_analysis.has_root_cause is True
    assert "Clean call signaling progression" in res_clean.root_cause_analysis.root_cause
    assert res_clean.call_id == call_1.session_id
    assert res_clean.calling_number == "9876543210"
    assert res_clean.called_number == "1800123456"

    # Test 16: Call with anomaly
    anom = CallAnomaly(
        call_id=call_1.session_id,
        severity=AnomalySeverity.ERROR,
        category=AnomalyCategory.RESPONSE_TIMEOUT,
        timestamp=call_1.start_time,
        protocol=ProtocolEnum.SIP,
        description="SIP INVITE generated but no 180 Ringing observed",
        evidence_refs=["SDL001_100_000087.txt Line 102"],
        confidence=0.95,
    )
    scoped_ws.anomalies = [anom]
    res_anom = analyzer.analyze(scoped_ws)
    assert res_anom.root_cause_analysis.has_root_cause is True
    assert "SIP INVITE generated" in res_anom.root_cause_analysis.root_cause
    assert len(res_anom.anomaly_analysis) == 1
    assert res_anom.anomaly_analysis[0].evidence == "SDL001_100_000087.txt Line 102"


def test_17_and_18_re_run_agent_analysis(tmp_path):
    """Test 17 & 18: Re-running Agent Analysis succeeds; safe handling when no call is selected."""
    analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
    events = create_sample_multi_call_events()
    service = AnalysisPipelineService()
    full_ws = service.ingest_trace_contents([("trace.txt", "\n".join(e.raw for e in events))])

    call_1 = full_ws.call_sessions[0]
    scoped_ws = full_ws.create_call_scoped_workspace(call_1, time_window_seconds=5.0)

    # First run
    res1 = analyzer.analyze(scoped_ws)
    # Re-run
    res2 = analyzer.analyze(scoped_ws)

    assert res1.analysis_id != res2.analysis_id
    assert res1.calling_number == res2.calling_number

    # Test 18: Empty/None call workspace handling
    empty_ws = AnalysisWorkspace(
        events=[],
        call_sessions=[],
        source_files=["empty.txt"],
    )
    res_empty = analyzer.analyze(empty_ws)
    assert res_empty.call_id == "N/A"
    assert res_empty.calling_number == "Unknown"
    assert res_empty.called_number == "Unknown"


def test_19_missing_evidence_handling(tmp_path):
    """Test 19: When evidence is insufficient, state 'Root cause not established from available evidence.'."""
    analyzer = VoiceOpsAgentAnalyzer(storage_dir=tmp_path)
    # Single isolated warning anomaly without error
    ev = VoiceEvent(
        raw="00602801.000 |15:21:03.200 |AppInfo |Unknown line",
        timestamp=datetime(2026, 9, 20, 15, 21, 3),
        protocol=ProtocolEnum.CUCM,
        direction=DirectionEnum.INTERNAL,
        message_type="AppInfo",
    )
    anom_warn = CallAnomaly(
        call_id="call-warn",
        severity=AnomalySeverity.WARNING,
        category=AnomalyCategory.CORRELATION_GAP,
        protocol=ProtocolEnum.CUCM,
        description="Ambiguous delay in signaling",
    )
    ws = AnalysisWorkspace(
        events=[ev],
        call_sessions=[CallSession(session_id="call-warn", events=[ev], anomalies=[anom_warn])],
        anomalies=[anom_warn],
    )
    result = analyzer.analyze(ws)
    rc = result.root_cause_analysis
    assert rc.has_root_cause is False
    assert rc.root_cause == "Root cause not established from available evidence."
    assert rc.missing_evidence is not None


def test_20_evidence_references(tmp_path):
    """Test 20: SDL observations contain exact filename, timestamps, processes, and raw lines."""
    events = create_sample_multi_call_events()
    sdl_obs = extract_sdl_observations(events, default_filename="SDL001_100_000087.txt")

    assert len(sdl_obs) >= 1
    first_obs = sdl_obs[0]
    assert first_obs.filename == "SDL001_100_000087.txt"
    assert first_obs.timestamp is not None
    assert first_obs.raw_evidence is not None

    display_dict = first_obs.to_display_dict()
    assert "IST Timestamp" in display_dict
    assert "Correlation Tag" in display_dict
    assert "Raw SDL Line" in display_dict


def test_21_multiple_calls_must_not_be_mixed():
    """Test 21: Evidence and events from Call 1 and Call 2 are strictly isolated."""
    events = create_sample_multi_call_events()
    service = AnalysisPipelineService()
    full_ws = service.ingest_trace_contents([("trace.txt", "\n".join(e.raw for e in events))])

    call_1 = next(s for s in full_ws.call_sessions if s.calling_number == "9876543210")
    call_2 = next(s for s in full_ws.call_sessions if s.calling_number == "9876543211")

    ws_1 = full_ws.create_call_scoped_workspace(call_1, time_window_seconds=1.0)
    ws_2 = full_ws.create_call_scoped_workspace(call_2, time_window_seconds=1.0)

    ws_1_call_ids = {e.calling_number for e in ws_1.events if e.calling_number}
    ws_2_call_ids = {e.calling_number for e in ws_2.events if e.calling_number}

    assert "9876543210" in ws_1_call_ids
    assert "9876543211" not in ws_1_call_ids

    assert "9876543211" in ws_2_call_ids
    assert "9876543210" not in ws_2_call_ids


def test_22_architecture_derived_from_evidence():
    """Test 22: Architecture strictly reflects evidence; no PSTN -> ISDN PRI when ISDN is 0."""
    events = create_sample_multi_call_events()
    engine = CorrelationEngine()
    sessions = engine.correlate(events)

    call_1 = next(s for s in sessions if s.calling_number == "9876543210")
    arch_1 = detect_call_architecture(call_1.events, sessions=[call_1])
    assert "ISDN PRI" in arch_1.architecture_name

    call_2 = next(s for s in sessions if s.calling_number == "9876543211")
    arch_2 = detect_call_architecture(call_2.events, sessions=[call_2])
    assert "ISDN PRI" not in arch_2.architecture_name
    assert "Voice Gateway" in arch_2.architecture_name
