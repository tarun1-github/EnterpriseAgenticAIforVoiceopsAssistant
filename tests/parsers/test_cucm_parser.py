"""Unit tests for the CUCM parser."""

from app.models.event import ProtocolEnum
from app.parsers.cucm.parser import CUCMParser


def test_cucm_parser_basic_lines():
    parser = CUCMParser()
    sample_cucm = """
    2026-09-19 14:22:01.123 |Process:StationInit:msgData|CI=123456 callingPartyNumber=2001 calledPartyNumber=5001 SEP001122334455
    2026-09-19 14:22:01.180 |SIP/2.0|Call-ID: 456789@10.1.1.20 |Incoming SIP Invite
    """
    events = parser.parse(sample_cucm, source="cucm_sdl.txt")
    assert len(events) == 2

    ev1 = events[0]
    assert ev1.protocol == ProtocolEnum.CUCM
    assert ev1.calling_number == "2001"
    assert ev1.called_number == "5001"
    assert ev1.device == "SEP001122334455"
    assert ev1.call_reference == "CI_123456"

    ev2 = events[1]
    assert ev2.protocol == ProtocolEnum.CUCM
    assert ev2.call_id == "456789@10.1.1.20"
