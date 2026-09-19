"""Unit tests for the ISDN / Q.931 parser."""

from pathlib import Path
import pytest
from app.models.event import DirectionEnum, ProtocolEnum
from app.parsers.isdn.parser import ISDNParser

SAMPLE_ISDN_PATH = Path(__file__).parents[2] / "sample_data" / "isdn" / "sample_isdn_call.txt"


@pytest.fixture
def isdn_parser() -> ISDNParser:
    return ISDNParser()


@pytest.fixture
def sample_isdn_text() -> str:
    return SAMPLE_ISDN_PATH.read_text(encoding="utf-8")


def test_isdn_parser_empty_content(isdn_parser: ISDNParser):
    events = isdn_parser.parse("")
    assert events == []


def test_isdn_parser_sample_call_flow(isdn_parser: ISDNParser, sample_isdn_text: str):
    events = isdn_parser.parse(sample_isdn_text, source="sample_isdn_call.txt")

    # Expect 8 Q.931 messages in sequence
    assert len(events) == 8

    # 1. SETUP
    setup = events[0]
    assert setup.protocol == ProtocolEnum.ISDN
    assert setup.direction == DirectionEnum.INBOUND
    assert setup.message_type == "SETUP"
    assert setup.interface == "Se0/2/0:23"
    assert setup.call_reference == "0x0082"
    assert setup.calling_number == "2001"
    assert setup.called_number == "5001"
    assert setup.metadata.get("b_channel") == "1"
    assert "SETUP" in setup.raw

    # 2. CALL PROCEEDING
    call_proc = events[1]
    assert call_proc.direction == DirectionEnum.OUTBOUND
    assert call_proc.message_type == "CALL PROCEEDING"
    assert call_proc.call_reference == "0x8082"

    # 3. ALERTING
    alerting = events[2]
    assert alerting.direction == DirectionEnum.OUTBOUND
    assert alerting.message_type == "ALERTING"

    # 4. CONNECT
    connect = events[3]
    assert connect.direction == DirectionEnum.OUTBOUND
    assert connect.message_type == "CONNECT"

    # 5. CONNECT ACKNOWLEDGE
    connect_ack = events[4]
    assert connect_ack.direction == DirectionEnum.INBOUND
    assert connect_ack.message_type == "CONNECT ACKNOWLEDGE"

    # 6. DISCONNECT
    disconnect = events[5]
    assert disconnect.direction == DirectionEnum.INBOUND
    assert disconnect.message_type == "DISCONNECT"
    assert disconnect.cause_code == "0x8090 - Normal call clearing"

    # 7. RELEASE
    release = events[6]
    assert release.direction == DirectionEnum.OUTBOUND
    assert release.message_type == "RELEASE"

    # 8. RELEASE COMPLETE
    rel_comp = events[7]
    assert rel_comp.direction == DirectionEnum.INBOUND
    assert rel_comp.message_type == "RELEASE COMPLETE"


def test_isdn_parser_resilience_on_malformed_lines(isdn_parser: ISDNParser):
    garbage = """
    Random router log line
    Translating address...
    *Sep 19 14:22:01.123: ISDN Se0/2/0:23 Q931: RX <- UNKNOWN_MSG pd = 8  callref = 0x9999
    Random text inside body
    """
    events = isdn_parser.parse(garbage)
    assert len(events) == 1
    assert events[0].message_type == "UNKNOWN_MSG"
    assert events[0].call_reference == "0x9999"
