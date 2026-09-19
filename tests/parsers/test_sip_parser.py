"""Unit tests for the SIP parser."""

from pathlib import Path
import pytest
from app.models.event import DirectionEnum, ProtocolEnum
from app.parsers.sip.parser import SIPParser

SAMPLE_SIP_PATH = Path(__file__).parents[2] / "sample_data" / "sip" / "sample_sip_call.txt"


@pytest.fixture
def sip_parser() -> SIPParser:
    return SIPParser()


@pytest.fixture
def sample_sip_text() -> str:
    return SAMPLE_SIP_PATH.read_text(encoding="utf-8")


def test_sip_parser_empty_content(sip_parser: SIPParser):
    events = sip_parser.parse("")
    assert events == []


def test_sip_parser_sample_call_flow(sip_parser: SIPParser, sample_sip_text: str):
    events = sip_parser.parse(sample_sip_text, source="sample_sip_call.txt")

    assert len(events) == 7

    # 1. INVITE
    invite = events[0]
    assert invite.protocol == ProtocolEnum.SIP
    assert invite.direction == DirectionEnum.INBOUND
    assert invite.message_type == "INVITE"
    assert invite.call_id == "456789@10.1.1.20"
    assert invite.transaction_id == "101 INVITE"
    assert invite.calling_number == "2001"
    assert invite.called_number == "5001"
    assert invite.metadata.get("rtp_ip") == "10.1.1.20"
    assert invite.metadata.get("rtp_port") == 16400

    # 2. 100 Trying
    trying = events[1]
    assert trying.direction == DirectionEnum.OUTBOUND
    assert trying.message_type == "100 Trying"
    assert trying.call_id == "456789@10.1.1.20"

    # 3. 180 Ringing
    ringing = events[2]
    assert ringing.direction == DirectionEnum.OUTBOUND
    assert ringing.message_type == "180 Ringing"

    # 4. 200 OK (Answer)
    ok_answer = events[3]
    assert ok_answer.direction == DirectionEnum.OUTBOUND
    assert ok_answer.message_type == "200 OK"
    assert ok_answer.metadata.get("rtp_ip") == "10.1.1.10"
    assert ok_answer.metadata.get("rtp_port") == 24500

    # 5. ACK
    ack = events[4]
    assert ack.direction == DirectionEnum.INBOUND
    assert ack.message_type == "ACK"

    # 6. BYE
    bye = events[5]
    assert bye.direction == DirectionEnum.INBOUND
    assert bye.message_type == "BYE"

    # 7. 200 OK (BYE ack)
    ok_bye = events[6]
    assert ok_bye.direction == DirectionEnum.OUTBOUND
    assert ok_bye.message_type == "200 OK"


def test_sip_parser_standalone_message(sip_parser: SIPParser):
    raw_sip = """
    SIP/2.0 404 Not Found
    Via: SIP/2.0/UDP 10.1.1.20:5060;branch=z9hG4bKabc
    From: <sip:1000@10.1.1.20>;tag=111
    To: <sip:9999@10.1.1.10>;tag=222
    Call-ID: deadbeef@10.1.1.20
    CSeq: 1 INVITE
    Content-Length: 0
    """
    events = sip_parser.parse(raw_sip)
    assert len(events) == 1
    ev = events[0]
    assert ev.message_type == "404 Not Found"
    assert ev.call_id == "deadbeef@10.1.1.20"
    assert ev.calling_number == "1000"
    assert ev.called_number == "9999"
    assert ev.cause_code == "SIP 404 Not Found"
