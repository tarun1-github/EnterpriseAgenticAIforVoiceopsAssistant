"""Unit tests for SDLAnalystAgent."""

from datetime import datetime, timedelta, timezone
import pytest

from app.agents.sdl_analyst import SDLAnalystAgent
from app.devices.cucm.sdl.models import Call, SDLEvent
from app.knowledge.retriever import InMemoryKnowledgeRetriever


def make_agent_event(signal: str, offset: float, raw: str) -> SDLEvent:
    t0 = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    return SDLEvent(
        timestamp=t0 + timedelta(seconds=offset),
        signal=signal,
        protocol="SIP",
        raw_text=raw,
        source_file="SDL001_100_000087.txt",
        source_line=int(offset * 10) + 1,
    )


def test_agent_with_explicit_sip_503_rejection():
    e1 = make_agent_event("INVITE", 0.0, "INVITE sip:2002@10.197.206.141 SIP/2.0\r\nCall-ID: call-503@cisco.com")
    e2 = make_agent_event("503 Service Unavailable", 0.2, "SIP/2.0 503 Service Unavailable\r\nReason: Q.850;cause=34")

    call = Call(
        id="call-reject",
        call_id="call-503@cisco.com",
        calling_number="1001",
        called_number="2002",
        start_time=e1.timestamp,
        end_time=e2.timestamp,
        nodes=["UCM15-HQ-PUB"],
        protocols=["SIP"],
        events=[e1, e2],
    )

    agent = SDLAnalystAgent()
    result = agent.analyze_call(call)

    assert result.confidence == "High"
    assert "explicit signaling rejection" in result.root_cause
    assert "503 Service Unavailable" in result.root_cause
    assert "CUCM SDL TRACE ANALYSIS" in result.formatted_report
    assert "FAILURE POINT" in result.formatted_report
    assert "RECOMMENDED CHECKS" in result.formatted_report
    assert result.agent_version == "1.0.0"
    assert result.parser_version == "1.0.0"
    assert result.knowledge_version == "1.0.0"


def test_agent_with_insufficient_evidence():
    # Call with premature disconnect without any SIP failure code
    e1 = make_agent_event("INVITE", 0.0, "INVITE sip:2002@10.197.206.141 SIP/2.0")
    e2 = make_agent_event("100 Trying", 0.1, "SIP/2.0 100 Trying")
    e3 = make_agent_event("BYE", 0.5, "BYE sip:2002@10.197.206.141 SIP/2.0")

    call = Call(
        id="call-insufficient",
        calling_number="1001",
        called_number="2002",
        start_time=e1.timestamp,
        end_time=e3.timestamp,
        nodes=["UCM15-HQ-PUB"],
        protocols=["SIP"],
        events=[e1, e2, e3],
    )

    agent = SDLAnalystAgent()
    result = agent.analyze_call(call)

    assert "Root cause cannot be confirmed from CUCM SDL evidence alone." in result.root_cause
    assert len(result.additional_evidence_required) > 0
    assert any("Packet captures" in e for e in result.additional_evidence_required)
    assert result.confidence in ("Medium", "Low")
