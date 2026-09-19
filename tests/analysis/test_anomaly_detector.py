"""Unit tests for the deterministic signaling anomaly detector."""

from datetime import datetime
import pytest
from app.analysis.anomaly_detector import AnomalyDetector
from app.models.anomaly import AnomalyCategory, AnomalySeverity
from app.models.call_session import CallArchitecture, CallSession
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent


@pytest.fixture
def detector() -> AnomalyDetector:
    return AnomalyDetector()


def test_detect_isdn_setup_without_progression(detector: AnomalyDetector):
    dt = datetime(2026, 9, 19, 10, 0, 0)
    setup = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.ISDN,
        direction=DirectionEnum.INBOUND,
        message_type="SETUP",
        call_reference="0x0011",
        raw="SETUP",
    )
    session = CallSession(
        architecture=CallArchitecture.UNKNOWN,
        events=[setup],
    )
    anomalies = detector.detect_anomalies(session)
    assert len(anomalies) == 1
    anom = anomalies[0]
    assert anom.category == AnomalyCategory.MISSING_MESSAGE
    assert anom.protocol == ProtocolEnum.ISDN
    assert "SETUP" in anom.description


def test_detect_isdn_abnormal_cause_code(detector: AnomalyDetector):
    dt = datetime(2026, 9, 19, 10, 0, 0)
    disc = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.ISDN,
        direction=DirectionEnum.INBOUND,
        message_type="DISCONNECT",
        cause_code="0x8091 - User busy",
        call_reference="0x0011",
        raw="DISCONNECT",
    )
    rel = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.ISDN,
        direction=DirectionEnum.OUTBOUND,
        message_type="RELEASE",
        call_reference="0x8011",
        raw="RELEASE",
    )
    session = CallSession(
        architecture=CallArchitecture.UNKNOWN,
        events=[disc, rel],
    )
    anomalies = detector.detect_anomalies(session)
    cause_anoms = [a for a in anomalies if a.category == AnomalyCategory.CAUSE_CODE]
    assert len(cause_anoms) == 1
    assert "User busy" in cause_anoms[0].description


def test_detect_sip_200_without_ack(detector: AnomalyDetector):
    dt = datetime(2026, 9, 19, 10, 0, 0)
    invite = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="INVITE", call_id="cid-1", raw="INV")
    ok = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="200 OK", call_id="cid-1", raw="200")

    session = CallSession(architecture=CallArchitecture.DIRECT_SIP, events=[invite, ok])
    anomalies = detector.detect_anomalies(session)

    ack_anoms = [a for a in anomalies if a.category == AnomalyCategory.SEQUENCE_ERROR]
    assert len(ack_anoms) == 1
    assert "ACK" in ack_anoms[0].expected_message


def test_detect_sip_4xx_failure_response(detector: AnomalyDetector):
    dt = datetime(2026, 9, 19, 10, 0, 0)
    invite = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="INVITE", call_id="cid-2", raw="INV")
    resp_404 = VoiceEvent(timestamp=dt, protocol=ProtocolEnum.SIP, message_type="404 Not Found", call_id="cid-2", raw="404")

    session = CallSession(architecture=CallArchitecture.DIRECT_SIP, events=[invite, resp_404])
    anomalies = detector.detect_anomalies(session)

    fail_anoms = [a for a in anomalies if a.category == AnomalyCategory.CAUSE_CODE]
    assert len(fail_anoms) == 1
    assert "404 Not Found" in fail_anoms[0].description


def test_detect_mgcp_unresponded_transaction(detector: AnomalyDetector):
    dt = datetime(2026, 9, 19, 10, 0, 0)
    crcx = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.MGCP,
        message_type="CRCX",
        transaction_id="5555",
        raw="CRCX",
        metadata={"command": "CRCX"},
    )

    session = CallSession(architecture=CallArchitecture.UNKNOWN, events=[crcx])
    anomalies = detector.detect_anomalies(session)

    to_anoms = [a for a in anomalies if a.category == AnomalyCategory.RESPONSE_TIMEOUT]
    assert len(to_anoms) == 1
    assert "5555" in to_anoms[0].description
