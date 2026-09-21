"""Unit tests for CUCM SDL parser and data models."""

from datetime import date, timezone
from zoneinfo import ZoneInfo
import pytest

from app.devices.cucm.sdl.models import SDLEvent
from app.devices.cucm.sdl.normalizer import parse_filehead_metadata, to_ist
from app.devices.cucm.sdl.parser import SDLParser

SAMPLE_FILEHEAD = (
    "00644027.000 |13:35:15.018 |FileHead |UTC:+00:00,Date: 2026/09/20, "
    "AppName: CCM, AppId: 100, AppNodeId: 1, AppVersion: CUCM Install=15.0.1.12900-234, "
    "HostName: UCM15-HQ-PUB, HostIPAddress: ::ffff:10.197.206.141, TraceVer: 3.0"
)

SAMPLE_SDLSIG = (
    "00644028.000 |13:35:15.018 |SdlSig   |DbObjectCacheTimer                     "
    "|initialized                    |Db(1,100,50,1)                   |SdlTimerService(1,100,3,1)       "
    "|1,100,113,1.2^*^*                        |[T:H-H:0,N:0,L:0,V:0,Z:0,D:0]  AppCorr: 0"
)

SAMPLE_MULTILINE_APPINFO = """00644037.000 |13:35:20.374 |AppInfo  |MGCPHandler received msg from: 10.197.206.240
NTFY 852066793 *@VGR.cciecollab.cisco.com MGCP 0.1
X: 0
O:
00644038.000 |13:35:20.374 |SdlSig   |MGCPNotify                             |wait                           |MGCPInit(1,100,91,1)             |MGCPHandler(1,100,90,1)          |1,100,90,1.6216^*^*                      |[R:N-H:0,N:0,L:0,V:0,Z:0,D:0] *@VGR.cciecollab.cisco.com - portNum= 0 NTFY 852066793 Observed event=0 pkg=1 optStr="""

SAMPLE_SIP_INVITE = """00644090.000 |13:36:00.123 |AppInfo  |SIPHandler received msg from: 10.197.206.241:5060
INVITE sip:2002@10.197.206.141:5060 SIP/2.0
Via: SIP/2.0/TCP 10.197.206.241:5060;branch=z9hG4bK1234
From: <sip:1001@10.197.206.241>;tag=abcd123
To: <sip:2002@10.197.206.141>
Call-ID: c987654321-callid@cisco.com
CSeq: 101 INVITE
Contact: <sip:1001@10.197.206.241:5060>
Content-Length: 0

00644091.000 |13:36:00.125 |SdlSig   |CcSetupReq                             |wait                           |SIPCdpc(1,100,185,10)            |SIPHandler(1,100,183,1)          |1,100,14,1.55^*^*                        |[R:N-H:0,N:0,L:0,V:0,Z:0,D:0]  CI=33554432 cdcc=1234567 callingPartyNumber=1001 calledPartyNumber=2002"""


def test_filehead_metadata_parsing():
    ref_date, tz, node = parse_filehead_metadata(SAMPLE_FILEHEAD)
    assert ref_date == date(2026, 9, 20)
    assert tz == timezone.utc
    assert node == "UCM15-HQ-PUB"


def test_sdlsig_parsing():
    parser = SDLParser()
    events = list(parser.parse_stream(SAMPLE_SDLSIG.splitlines(), source_file="test.txt"))
    assert len(events) == 1
    ev = events[0]
    assert ev.signal == "DbObjectCacheTimer"
    assert ev.process == "Db"
    assert ev.source_file == "test.txt"
    assert ev.source_line == 1
    assert ev.attributes.get("state") == "initialized"
    assert ev.attributes.get("sequence_num") == "00644028.000"
    assert ev.direction == "OUTBOUND"  # [T:...


def test_multiline_record_handling():
    parser = SDLParser()
    events = list(parser.parse_stream(SAMPLE_MULTILINE_APPINFO.splitlines(), source_file="mgcp.txt"))
    assert len(events) == 2

    ev1 = events[0]
    assert ev1.signal == "NTFY"
    assert ev1.process == "MGCPHandler"
    assert "NTFY 852066793" in ev1.raw_text
    assert ev1.ip_address == "10.197.206.240"
    assert ev1.source_line == 1
    assert ev1.protocol == "MGCP"
    assert ev1.direction == "INBOUND"

    ev2 = events[1]
    assert ev2.signal == "MGCPNotify"
    assert ev2.source_line == 5
    assert ev2.protocol == "MGCP"


def test_sip_invite_and_ccsetup_identifiers():
    parser = SDLParser()
    events = list(parser.parse_stream(SAMPLE_SIP_INVITE.splitlines(), source_file="sip.txt"))
    assert len(events) == 2

    # Check SIP INVITE event
    invite = events[0]
    assert invite.protocol == "SIP"
    assert invite.call_id == "c987654321-callid@cisco.com"
    assert invite.calling_number == "1001"
    assert invite.called_number == "2002"
    assert invite.ip_address == "10.197.206.241"

    # Check CcSetupReq internal event
    ccsetup = events[1]
    assert ccsetup.signal == "CcSetupReq"
    assert ccsetup.ci == "33554432"
    assert ccsetup.cdcc == "1234567"
    assert ccsetup.calling_number == "1001"
    assert ccsetup.called_number == "2002"


def test_timezone_handling_and_ist_conversion():
    lines = [SAMPLE_FILEHEAD, SAMPLE_SDLSIG]
    parser = SDLParser()
    events = list(parser.parse_stream(lines, source_file="tz_test.txt"))
    assert len(events) == 2

    ev = events[1]
    assert ev.timestamp.tzinfo is not None
    # 13:35:15.018 UTC + 5:30 = 19:05:15.018 IST
    ist_time = ev.timestamp_ist
    assert ist_time.hour == 19
    assert ist_time.minute == 5
    assert ist_time.second == 15
    assert "19:05:15.018 IST" in ev.timestamp_ist_str


def test_malformed_line_non_crashing():
    malformed = [
        "THIS IS A GARBAGE PREAMBLE LINE",
        SAMPLE_SDLSIG,
        "ANOTHER RANDOM CORRUPT TEXT",
    ]
    parser = SDLParser()
    events = list(parser.parse_stream(malformed, source_file="corrupt.txt"))
    # The valid event should still be returned, garbage buffered or logged
    assert len(events) >= 1
    assert any(e.signal == "DbObjectCacheTimer" for e in events)
    assert len(parser.malformed_records) >= 1
