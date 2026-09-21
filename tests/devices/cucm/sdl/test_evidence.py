"""Unit tests for SDL Anomaly Detection and EvidencePack builder."""

from datetime import datetime, timedelta, timezone
import pytest

from app.devices.cucm.sdl.anomaly_detector import SDLAnomalyDetector
from app.devices.cucm.sdl.evidence import build_evidence_pack
from app.devices.cucm.sdl.models import Call, SDLEvent


def make_test_event(signal: str, offset: float, raw_text: str = None) -> SDLEvent:
    base = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    t = base + timedelta(seconds=offset)
    return SDLEvent(
        timestamp=t,
        signal=signal,
        protocol="SIP",
        raw_text=raw_text or f"Signal line {signal}",
        source_file="test_sdl.txt",
        source_line=int(offset * 10) + 1,
    )


def test_anomaly_detector_premature_disconnect():
    ev1 = make_test_event("INVITE", 0.0, "INVITE sip:2002@10.197.206.141 SIP/2.0")
    ev2 = make_test_event("100 Trying", 0.1, "SIP/2.0 100 Trying")
    ev3 = make_test_event("BYE", 0.4, "BYE sip:2002@10.197.206.141 SIP/2.0")

    call = Call(
        id="c-disc",
        calling_number="1001",
        called_number="2002",
        start_time=ev1.timestamp,
        end_time=ev3.timestamp,
        protocols=["SIP"],
        events=[ev1, ev2, ev3],
    )

    detector = SDLAnomalyDetector()
    anomalies = detector.detect(call)

    assert len(anomalies) >= 1
    types = {a.type for a in anomalies}
    assert "PREMATURE_DISCONNECT" in types
    assert "MISSING_EXPECTED_EVENT" in types


def test_anomaly_detector_sip_503_service_unavailable():
    ev1 = make_test_event("INVITE", 0.0, "INVITE sip:2002@10.197.206.141 SIP/2.0")
    ev2 = make_test_event("503 Service Unavailable", 0.2, "SIP/2.0 503 Service Unavailable\r\nReason: Q.850;cause=34")

    call = Call(
        id="c-503",
        calling_number="1001",
        called_number="2002",
        start_time=ev1.timestamp,
        end_time=ev2.timestamp,
        protocols=["SIP"],
        events=[ev1, ev2],
    )

    detector = SDLAnomalyDetector()
    anomalies = detector.detect(call)

    assert any(a.type == "REJECTED_RESPONSE" for a in anomalies)
    rej = next(a for a in anomalies if a.type == "REJECTED_RESPONSE")
    assert "503 Service Unavailable" in rej.description


def test_evidence_pack_construction_and_formatting():
    ev1 = make_test_event("INVITE", 0.0, "INVITE sip:2002@10.197.206.141 SIP/2.0")
    ev2 = make_test_event("180 Ringing", 1.0, "SIP/2.0 180 Ringing")
    ev3 = make_test_event("200 OK", 2.5, "SIP/2.0 200 OK")
    ev4 = make_test_event("ACK", 2.6, "ACK sip:2002@10.197.206.141 SIP/2.0")

    call = Call(
        id="c-pack",
        ci="998877",
        calling_number="1001",
        called_number="2002",
        start_time=ev1.timestamp,
        end_time=ev4.timestamp,
        nodes=["UCM15-HQ-PUB"],
        devices=["SEP001122334455"],
        protocols=["SIP"],
        events=[ev1, ev2, ev3, ev4],
    )

    pack = build_evidence_pack(call)
    assert pack.call["calling"] == "1001"
    assert pack.call["called"] == "2002"
    assert pack.call["timezone"] == "Asia/Kolkata"
    assert "IST" in pack.call["start_time_ist"]
    assert len(pack.flow) == 4
    assert pack.identifiers["CI"] == "998877"
    assert "test_sdl.txt" in pack.source_files

    # Check Markdown prompt context generation
    context = pack.to_prompt_context()
    assert "### CALL METADATA" in context
    assert "1001" in context
    assert "2002" in context
    assert "### CHRONOLOGICAL CALL FLOW" in context
    assert "### SUPPORTING RAW SDL EVIDENCE" in context
