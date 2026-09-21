"""Unit tests for CUCM SDL Call Correlation Engine."""

from datetime import datetime, timezone
import pytest

from app.devices.cucm.sdl.correlator import SDLCallCorrelator
from app.devices.cucm.sdl.models import SDLEvent


def make_event(
    signal: str,
    time_sec: int,
    ci: str = None,
    cdcc: str = None,
    call_id: str = None,
    calling: str = None,
    called: str = None,
    protocol: str = "SIP",
    device: str = None,
    node: str = "UCM15-HQ-PUB",
) -> SDLEvent:
    dt = datetime(2026, 9, 20, 10, 0, time_sec, tzinfo=timezone.utc)
    return SDLEvent(
        timestamp=dt,
        node=node,
        process="SIPHandler",
        signal=signal,
        ci=ci,
        cdcc=cdcc,
        call_id=call_id,
        calling_number=calling,
        called_number=called,
        device=device,
        protocol=protocol,
        raw_text=f"{signal} ev at {time_sec}",
        source_file="test.txt",
        source_line=time_sec,
    )


def test_transitive_multi_factor_correlation():
    # Event 1: SIP INVITE with Call-ID
    e1 = make_event("INVITE", 1, call_id="sip-call-12345", calling="1001", called="2002", device="SEP001122334455")
    # Event 2: CcSetupReq linking Call-ID and CI
    e2 = make_event("CcSetupReq", 2, call_id="sip-call-12345", ci="77777", cdcc="88888")
    # Event 3: CcAlertInd having CI only
    e3 = make_event("CcAlertInd", 3, ci="77777")
    # Event 4: 200 OK having CDCC only
    e4 = make_event("200 OK", 4, cdcc="88888")

    correlator = SDLCallCorrelator()
    calls = correlator.correlate([e1, e2, e3, e4])

    assert len(calls) == 1
    call = calls[0]
    assert call.ci == "77777"
    assert call.call_id == "sip-call-12345"
    assert call.cdcc == "88888"
    assert call.calling_number == "1001"
    assert call.called_number == "2002"
    assert call.event_count == 4


def test_simultaneous_unrelated_calls_not_merged():
    # Call A: 1001 -> 2002, CI=11111
    a1 = make_event("INVITE", 1, ci="11111", calling="1001", called="2002", call_id="call-a")
    a2 = make_event("200 OK", 3, ci="11111", call_id="call-a")

    # Call B: 3003 -> 4004, CI=22222 at the same time
    b1 = make_event("INVITE", 1, ci="22222", calling="3003", called="4004", call_id="call-b")
    b2 = make_event("200 OK", 3, ci="22222", call_id="call-b")

    correlator = SDLCallCorrelator()
    calls = correlator.correlate([a1, b1, a2, b2])

    assert len(calls) == 2
    cis = {c.ci for c in calls}
    assert cis == {"11111", "22222"}


def test_background_timer_noise_filtered_out():
    t_ev = SDLEvent(
        timestamp=datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc),
        node="UCM15-HQ-PUB",
        process="Db",
        signal="DbObjectCacheTimer",
        protocol="CUCM",
        raw_text="DbObjectCacheTimer initialized",
        source_file="test.txt",
        source_line=1,
    )
    correlator = SDLCallCorrelator()
    calls = correlator.correlate([t_ev])
    assert len(calls) == 0
