"""Unit tests for CallFlowEngine and protocol State Machines."""

from datetime import datetime, timedelta, timezone
import pytest

from app.devices.cucm.sdl.call_flow import CallFlowEngine
from app.devices.cucm.sdl.models import Call, SDLEvent
from app.devices.cucm.sdl.state_machine import CallState, SIPStateMachine, Q931StateMachine


def create_event(signal: str, offset_seconds: float, protocol: str = "SIP") -> SDLEvent:
    base_t = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    ev_t = base_t + timedelta(seconds=offset_seconds)
    return SDLEvent(
        timestamp=ev_t,
        signal=signal,
        protocol=protocol,
        direction="INBOUND" if signal in ("INVITE", "200 OK") else "OUTBOUND",
        raw_text=f"Trace line for {signal}",
        source_file="sip.txt",
        source_line=int(offset_seconds) + 1,
    )


def test_normal_sip_state_progression():
    sm = SIPStateMachine()
    evs = [
        create_event("INVITE", 0),
        create_event("100 Trying", 0.1),
        create_event("180 Ringing", 0.5),
        create_event("200 OK", 2.0),
        create_event("ACK", 2.1),
        create_event("BYE", 10.0),
        create_event("200 OK", 10.1),
    ]

    states = [sm.step(e).to_state for e in evs]
    assert states == [
        CallState.CALL_SETUP,
        CallState.CALL_SETUP,
        CallState.ALERTING,
        CallState.CONNECT,
        CallState.ACTIVE,
        CallState.DISCONNECT,
        CallState.CALL_END,
    ]


def test_call_flow_missing_milestones():
    # Call with INVITE and 100 Trying, then immediate BYE without Ringing or 200 OK
    evs = [
        create_event("INVITE", 0),
        create_event("100 Trying", 0.1),
        create_event("BYE", 0.5),
    ]
    call = Call(
        id="c-missing",
        calling_number="1001",
        called_number="2002",
        start_time=evs[0].timestamp,
        end_time=evs[-1].timestamp,
        protocols=["SIP"],
        events=evs,
    )

    engine = CallFlowEngine()
    report = engine.analyze(call)

    assert len(report.missing_events) >= 1
    assert any("180 Ringing" in m for m in report.missing_events)


def test_large_time_gap_detection():
    # Call with 6.5 second delay between INVITE and 180 Ringing
    evs = [
        create_event("INVITE", 0),
        create_event("180 Ringing", 6.5),
    ]
    call = Call(
        id="c-gap",
        start_time=evs[0].timestamp,
        end_time=evs[-1].timestamp,
        protocols=["SIP"],
        events=evs,
    )

    engine = CallFlowEngine(time_gap_threshold_ms=4000.0)
    report = engine.analyze(call)

    assert len(report.large_time_gaps) == 1
    gap = report.large_time_gaps[0]
    assert gap["gap_ms"] == 6500.0
    assert gap["prior_event"] == "INVITE"
    assert gap["current_event"] == "180 Ringing"


def test_q931_state_machine():
    sm = Q931StateMachine()
    evs = [
        create_event("CcSetupReq", 0, protocol="Q931"),
        create_event("CcAlertInd", 0.5, protocol="Q931"),
        create_event("CcConnectInd", 1.5, protocol="Q931"),
        create_event("CcDisconnectReq", 5.0, protocol="Q931"),
        create_event("CcReleaseReq", 5.1, protocol="Q931"),
        create_event("CcReleaseComplete", 5.2, protocol="Q931"),
    ]

    states = [sm.step(e).to_state for e in evs]
    assert states == [
        CallState.CALL_SETUP,
        CallState.ALERTING,
        CallState.ACTIVE,
        CallState.DISCONNECT,
        CallState.RELEASE,
        CallState.CALL_END,
    ]
