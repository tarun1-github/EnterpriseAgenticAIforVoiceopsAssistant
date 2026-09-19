"""Unit tests for the EvidencePack generator and JSON serialization."""

import json
from datetime import datetime
from app.analysis.evidence_builder import build_evidence_pack
from app.models.anomaly import AnomalyCategory, AnomalySeverity, CallAnomaly
from app.models.call_session import CallArchitecture, CallSession
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent


def test_evidence_pack_generation_and_serialization():
    dt = datetime(2026, 9, 19, 14, 22, 1)
    ev1 = VoiceEvent(
        timestamp=dt,
        protocol=ProtocolEnum.ISDN,
        direction=DirectionEnum.INBOUND,
        message_type="SETUP",
        call_reference="0x0082",
        calling_number="2001",
        called_number="5001",
        raw="SETUP",
    )
    anom = CallAnomaly(
        category=AnomalyCategory.MISSING_MESSAGE,
        protocol=ProtocolEnum.ISDN,
        severity=AnomalySeverity.ERROR,
        description="Detected anomaly: Missing CONNECT",
        expected_message="CONNECT",
    )
    session = CallSession(
        session_id="call_test_123",
        architecture=CallArchitecture.ISDN_SIP,
        calling_number="2001",
        called_number="5001",
        start_time=dt,
        end_time=dt,
        events=[ev1],
        isdn_call_references=["0x0082"],
        correlation_confidence=0.95,
        correlation_evidence=["Matched ANI and DNIS"],
        anomalies=[anom],
    )

    pack = build_evidence_pack(session)

    assert pack.architecture == CallArchitecture.ISDN_SIP
    assert len(pack.timeline) == 1
    assert pack.protocol_summaries.get("ISDN") == 1
    assert "CONNECT" in pack.missing_expected_messages
    assert pack.important_identifiers["calling_party"] == "2001"

    # Verify 100% JSON serializability
    json_str = pack.to_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["architecture"] == "ISDN_SIP"
    assert parsed["call_session"]["session_id"] == "call_test_123"
