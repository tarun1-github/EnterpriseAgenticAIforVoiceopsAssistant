"""Unit tests for the MGCP parser."""

from pathlib import Path
import pytest
from app.models.event import DirectionEnum, ProtocolEnum
from app.parsers.mgcp.parser import MGCPParser

SAMPLE_MGCP_PATH = Path(__file__).parents[2] / "sample_data" / "mgcp" / "sample_mgcp_call.txt"


@pytest.fixture
def mgcp_parser() -> MGCPParser:
    return MGCPParser()


@pytest.fixture
def sample_mgcp_text() -> str:
    return SAMPLE_MGCP_PATH.read_text(encoding="utf-8")


def test_mgcp_parser_empty_content(mgcp_parser: MGCPParser):
    events = mgcp_parser.parse("")
    assert events == []


def test_mgcp_parser_sample_call_flow(mgcp_parser: MGCPParser, sample_mgcp_text: str):
    events = mgcp_parser.parse(sample_mgcp_text, source="sample_mgcp_call.txt")

    assert len(events) == 6

    # 1. CRCX
    crcx = events[0]
    assert crcx.protocol == ProtocolEnum.MGCP
    assert crcx.direction == DirectionEnum.INBOUND
    assert crcx.message_type == "CRCX"
    assert crcx.transaction_id == "1001"
    assert crcx.endpoint == "S0/SU0/DS1-0/1@vg224.cisco.com"
    assert crcx.call_id == "D000000001"
    assert crcx.metadata.get("mode") == "recvonly"

    # 2. 200 OK for CRCX
    resp_crcx = events[1]
    assert resp_crcx.direction == DirectionEnum.OUTBOUND
    assert resp_crcx.message_type == "200 OK"
    assert resp_crcx.transaction_id == "1001"
    assert resp_crcx.metadata.get("connection_id") == "1"
    assert resp_crcx.metadata.get("rtp_ip") == "10.1.1.20"
    assert resp_crcx.metadata.get("rtp_port") == 16402

    # 3. MDCX
    mdcx = events[2]
    assert mdcx.direction == DirectionEnum.INBOUND
    assert mdcx.message_type == "MDCX"
    assert mdcx.transaction_id == "1002"
    assert mdcx.metadata.get("mode") == "sendrecv"

    # 4. 200 OK for MDCX
    resp_mdcx = events[3]
    assert resp_mdcx.direction == DirectionEnum.OUTBOUND
    assert resp_mdcx.message_type == "200 OK"
    assert resp_mdcx.transaction_id == "1002"

    # 5. DLCX
    dlcx = events[4]
    assert dlcx.direction == DirectionEnum.INBOUND
    assert dlcx.message_type == "DLCX"
    assert dlcx.transaction_id == "1003"

    # 6. 250 OK for DLCX
    resp_dlcx = events[5]
    assert resp_dlcx.direction == DirectionEnum.OUTBOUND
    assert resp_dlcx.message_type == "250 OK"
    assert resp_dlcx.transaction_id == "1003"


def test_mgcp_parser_standalone_command(mgcp_parser: MGCPParser):
    raw_mgcp = """
    AUEP 999 S0/SU0/DS1-0/1@vg224.cisco.com MGCP 0.1
    F: A
    """
    events = mgcp_parser.parse(raw_mgcp)
    assert len(events) == 1
    ev = events[0]
    assert ev.message_type == "AUEP"
    assert ev.transaction_id == "999"
    assert ev.endpoint == "S0/SU0/DS1-0/1@vg224.cisco.com"


def test_mgcp_parser_rqnt_and_rsip(mgcp_parser: MGCPParser):
    raw_mgcp = """
    RQNT 2001 S0/SU0/DS1-0/1@vg224.cisco.com MGCP 0.1
    X: 10
    S: rg

    RSIP 3001 S0/SU0/DS1-0/1@vg224.cisco.com MGCP 0.1
    RM: restart
    """
    events = mgcp_parser.parse(raw_mgcp)
    assert len(events) == 2
    rqnt = events[0]
    assert rqnt.message_type == "RQNT"
    assert rqnt.transaction_id == "2001"
    assert rqnt.metadata.get("command") == "RQNT"

    rsip = events[1]
    assert rsip.message_type == "RSIP"
    assert rsip.transaction_id == "3001"
    assert rsip.metadata.get("command") == "RSIP"

