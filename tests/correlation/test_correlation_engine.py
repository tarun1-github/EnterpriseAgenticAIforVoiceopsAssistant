"""Unit tests for the multi-signal Call Correlation Engine."""

from datetime import datetime
from pathlib import Path
import pytest
from app.analysis.anomaly_detector import AnomalyDetector
from app.correlation.engine import CorrelationEngine
from app.correlation.scoring import CorrelationConfig
from app.models.call_session import CallArchitecture
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.ingestion import TraceIngestionEngine

SAMPLE_DIR = Path(__file__).parents[2] / "sample_data"


@pytest.fixture
def engine() -> CorrelationEngine:
    detector = AnomalyDetector()
    return CorrelationEngine(anomaly_detector=detector)


@pytest.fixture
def ingestion() -> TraceIngestionEngine:
    return TraceIngestionEngine()


def test_strong_isdn_and_mgcp_correlation(engine: CorrelationEngine):
    """Scenario 1: Correlating ISDN call leg with MGCP gateway leg."""
    dt1 = datetime(2026, 9, 19, 14, 22, 1)
    dt2 = datetime(2026, 9, 19, 14, 22, 2)

    isdn_setup = VoiceEvent(
        timestamp=dt1,
        protocol=ProtocolEnum.ISDN,
        direction=DirectionEnum.INBOUND,
        message_type="SETUP",
        interface="Se0/2/0:23",
        call_reference="0x0082",
        calling_number="2001",
        called_number="5001",
        raw="ISDN SETUP",
    )
    mgcp_crcx = VoiceEvent(
        timestamp=dt2,
        protocol=ProtocolEnum.MGCP,
        direction=DirectionEnum.INBOUND,
        message_type="CRCX",
        transaction_id="1001",
        endpoint="S0/SU0/DS1-0/1@vg224.cisco.com",
        call_id="D000000001",
        calling_number="2001",
        called_number="5001",
        raw="MGCP CRCX",
    )
    mgcp_resp = VoiceEvent(
        timestamp=dt2,
        protocol=ProtocolEnum.MGCP,
        direction=DirectionEnum.OUTBOUND,
        message_type="200 OK",
        transaction_id="1001",
        call_id="D000000001",
        raw="MGCP 200 OK",
        metadata={"connection_id": "1", "response_code": 200},
    )

    sessions = engine.correlate([isdn_setup, mgcp_crcx, mgcp_resp])
    assert len(sessions) == 1
    session = sessions[0]
    assert session.architecture == CallArchitecture.ISDN_MGCP
    assert session.calling_number == "2001"
    assert session.called_number == "5001"
    assert "0x0082" in session.isdn_call_references
    assert "1001" in session.mgcp_transaction_ids
    assert session.correlation_confidence >= 0.70


def test_strong_isdn_and_sip_correlation(engine: CorrelationEngine):
    """Scenario 2: Correlating ISDN leg with SIP leg without MGCP."""
    dt1 = datetime(2026, 9, 19, 10, 0, 1)
    dt2 = datetime(2026, 9, 19, 10, 0, 2)

    isdn_setup = VoiceEvent(
        timestamp=dt1,
        protocol=ProtocolEnum.ISDN,
        direction=DirectionEnum.INBOUND,
        message_type="SETUP",
        call_reference="0x0099",
        calling_number="3001",
        called_number="6001",
        raw="ISDN SETUP",
    )
    sip_invite = VoiceEvent(
        timestamp=dt2,
        protocol=ProtocolEnum.SIP,
        direction=DirectionEnum.OUTBOUND,
        message_type="INVITE",
        call_id="call-999@gateway",
        calling_number="3001",
        called_number="6001",
        raw="SIP INVITE",
    )

    sessions = engine.correlate([isdn_setup, sip_invite])
    assert len(sessions) == 1
    session = sessions[0]
    assert session.architecture == CallArchitecture.ISDN_SIP
    assert "call-999@gateway" in session.sip_call_ids
    assert "0x0099" in session.isdn_call_references


def test_direct_sip_correlation(engine: CorrelationEngine):
    """Scenario 3: Direct SIP call without ISDN or MGCP."""
    dt = datetime(2026, 9, 19, 11, 0, 0)
    invite = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.SIP,
        direction=DirectionEnum.INBOUND,
        message_type="INVITE",
        call_id="direct-sip-123",
        calling_number="4001",
        called_number="7001",
        raw="INVITE",
    )
    ringing = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.SIP,
        direction=DirectionEnum.OUTBOUND,
        message_type="180 Ringing",
        call_id="direct-sip-123",
        calling_number="4001",
        called_number="7001",
        raw="180 Ringing",
    )

    sessions = engine.correlate([invite, ringing])
    assert len(sessions) == 1
    session = sessions[0]
    assert session.architecture == CallArchitecture.DIRECT_SIP
    assert "direct-sip-123" in session.sip_call_ids


def test_weak_correlation_behavior(engine: CorrelationEngine):
    """Scenario 4: Weak correlation below merge threshold is kept separate."""
    # Two events sharing only partial proximity but completely different identifiers and numbers
    dt1 = datetime(2026, 9, 19, 12, 0, 0)
    dt2 = datetime(2026, 9, 19, 12, 0, 20)

    e1 = VoiceEvent(
        timestamp=dt1,
        protocol=ProtocolEnum.SIP,
        message_type="OPTIONS",
        call_id="opt-1",
        raw="OPTIONS",
    )
    e2 = VoiceEvent(
        timestamp=dt2,
        protocol=ProtocolEnum.SIP,
        message_type="OPTIONS",
        call_id="opt-2",
        raw="OPTIONS",
    )

    sessions = engine.correlate([e1, e2])
    assert len(sessions) == 2


def test_incorrect_correlation_rejection(engine: CorrelationEngine):
    """Scenario 5: Explicitly reject correlation when ANI and DNIS conflict."""
    dt = datetime(2026, 9, 19, 13, 0, 0)
    call_a = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.SIP,
        message_type="INVITE",
        call_id="cid-a",
        calling_number="1111",
        called_number="2222",
        raw="INVITE A",
    )
    call_b = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.SIP,
        message_type="INVITE",
        call_id="cid-b",
        calling_number="8888",
        called_number="9999",
        raw="INVITE B",
    )

    sessions = engine.correlate([call_a, call_b])
    assert len(sessions) == 2


def test_timestamp_proximity(engine: CorrelationEngine):
    """Scenario 6: Events far apart in time (>45s) do not merge despite matching numbers."""
    dt_early = datetime(2026, 9, 19, 8, 0, 0)
    dt_late = datetime(2026, 9, 19, 15, 0, 0)

    call1 = VoiceEvent(
        timestamp=dt_early,
        protocol=ProtocolEnum.SIP,
        message_type="INVITE",
        call_id="morning-call",
        calling_number="2001",
        called_number="5001",
        raw="INVITE 1",
    )
    call2 = VoiceEvent(
        timestamp=dt_late,
        protocol=ProtocolEnum.SIP,
        message_type="INVITE",
        call_id="afternoon-call",
        calling_number="2001",
        called_number="5001",
        raw="INVITE 2",
    )

    sessions = engine.correlate([call1, call2])
    assert len(sessions) == 2


def test_multiple_simultaneous_calls(engine: CorrelationEngine):
    """Scenario 7 & 8: Multiple simultaneous calls with different Call-IDs."""
    dt = datetime(2026, 9, 19, 14, 0, 0)

    # Call 1: Alice -> Bob
    c1_inv = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="INVITE", call_id="c1", calling_number="2001", called_number="5001", raw="C1 INV")
    c1_ack = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="ACK", call_id="c1", calling_number="2001", called_number="5001", raw="C1 ACK")

    # Call 2: Charlie -> Dave
    c2_inv = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="INVITE", call_id="c2", calling_number="3001", called_number="6001", raw="C2 INV")
    c2_ack = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="ACK", call_id="c2", calling_number="3001", called_number="6001", raw="C2 ACK")

    sessions = engine.correlate([c1_inv, c2_inv, c1_ack, c2_ack])
    assert len(sessions) == 2
    cids = {s.sip_call_ids[0] for s in sessions}
    assert "c1" in cids
    assert "c2" in cids


def test_different_isdn_call_references(engine: CorrelationEngine):
    """Scenario 9: Multiple ISDN calls on the same PRI interface with different call references."""
    dt = datetime(2026, 9, 19, 14, 10, 0)

    call1 = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.ISDN, message_type="SETUP", interface="Se0/2/0:23", call_reference="0x0001", calling_number="2001", called_number="5001", raw="SETUP 1")
    call2 = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.ISDN, message_type="SETUP", interface="Se0/2/0:23", call_reference="0x0002", calling_number="9999", called_number="8888", raw="SETUP 2")

    sessions = engine.correlate([call1, call2])
    assert len(sessions) == 2


def test_multiple_mgcp_transactions_in_same_call(engine: CorrelationEngine):
    """Scenario 10: Multiple MGCP transactions (CRCX, MDCX, DLCX) correlated to the same Call-ID."""
    dt = datetime(2026, 9, 19, 14, 20, 0)

    crcx = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.MGCP, message_type="CRCX", transaction_id="101", call_id="mgcp-call-77", endpoint="ds0/1@vg", raw="CRCX")
    mdcx = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.MGCP, message_type="MDCX", transaction_id="102", call_id="mgcp-call-77", endpoint="ds0/1@vg", raw="MDCX")
    dlcx = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.MGCP, message_type="DLCX", transaction_id="103", call_id="mgcp-call-77", endpoint="ds0/1@vg", raw="DLCX")

    sessions = engine.correlate([crcx, mdcx, dlcx])
    assert len(sessions) == 1
    session = sessions[0]
    assert set(session.mgcp_transaction_ids) == {"101", "102", "103"}
    assert "mgcp-call-77" in session.mgcp_call_ids


def test_mixed_protocol_single_gateway_file(ingestion: TraceIngestionEngine, engine: CorrelationEngine):
    """Scenario 11: Ingesting a single file with interleaved ISDN + MGCP + SIP and correlating into one session."""
    mixed_path = SAMPLE_DIR / "mixed" / "sample_mixed_gateway.txt"
    events = ingestion.ingest_file(mixed_path)

    assert len(events) >= 8
    protocols = {e.protocol for e in events}
    assert ProtocolEnum.ISDN in protocols
    assert ProtocolEnum.MGCP in protocols
    assert ProtocolEnum.SIP in protocols

    sessions = engine.correlate(events)
    assert len(sessions) == 1
    session = sessions[0]
    assert session.architecture == CallArchitecture.ISDN_MGCP
    assert session.calling_number == "2001"
    assert session.called_number == "5001"
    assert "0x0082" in session.isdn_call_references
    assert "456789@10.1.1.20" in session.sip_call_ids
