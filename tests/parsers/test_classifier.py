"""Unit tests for content-based TraceClassifier."""

import pytest
from app.parsers.classifier import TraceClassifier

SAMPLE_ISDN_RAW = """
*Sep 20 15:42:18.231: ISDN Se0/2/0:23 Q931: RX <- SETUP pd = 9  callref = 0x0082
        Bearer Capability i = 0x8090A2
                Standard = CCITT
                Transfer Capability = Speech
                Transfer Mode = Circuit
                Transfer Rate = 64 kbit/s
        Channel ID i = 0xA98381
                Exclusive, Channel 1
        Calling Party Number i = 0x0081, '9876543210'
        Called Party Number i = 0x81, '1800123456'
"""

SAMPLE_SIP_RAW = """
*Sep 20 15:42:18.280: //6980/ccsipDisplayMsg:
Received:
INVITE sip:1800123456@10.197.206.141:5060 SIP/2.0
Via: SIP/2.0/UDP 10.197.206.150:5060;branch=z9hG4bK23A10
From: <sip:9876543210@10.197.206.150>;tag=123456-ABC
To: <sip:1800123456@10.197.206.141>
Date: Sun, 20 Sep 2026 15:42:18 GMT
Call-ID: B837261A-5432-11EB-8001-CiscoSIP@10.197.206.150
CSeq: 101 INVITE
Contact: <sip:9876543210@10.197.206.150:5060>
Content-Type: application/sdp
Content-Length: 180

v=0
o=CiscoSystemsSIP-GW-UserAgent 5000 5000 IN IP4 10.197.206.150
s=SIP Call
c=IN IP4 10.197.206.150
t=0 0
m=audio 16400 RTP/AVP 0 101
"""

SAMPLE_CUCM_SDL_RAW = """
00644027.000 |13:35:15.018 |FileHead |UTC:+00:00,Date: 2026/09/20, AppName: CCM, AppId: 100, AppNodeId: 1, AppVersion: CUCM Install=15.0.1.12900-234 Build=15.0.1.12900-234 (d3f126) memlog=20, HostName: UCM15-HQ-PUB, HostIPAddress: ::ffff:10.197.206.141, AppStartTime: 2026/09/16 10:55:48, FileNumber: 26, TraceVer: 3.0
00644028.000 |13:35:15.018 |SdlSig   |DbObjectCacheTimer                     |initialized                    |Db(1,100,50,1)                   |SdlTimerService(1,100,3,1)       |1,100,113,1.2^*^*                        |[T:H-H:0,N:0,L:0,V:0,Z:0,D:0]  AppCorr: 0
"""

SAMPLE_MGCP_RAW = """
*Sep 20 15:42:18.244: MGCP Packet received from 10.197.206.141:2427--->
CRCX 1001 S0/SU0/DS1-0/1@VGR.cciecollab.cisco.com MGCP 0.1
C: D000000001
L: p:20, a:PCMU, s:off
M: recvonly
X: 00000001
I: 1
"""


def test_classify_isdn_from_arbitrary_filename():
    classifier = TraceClassifier()
    # File named completely arbitrarily
    res = classifier.classify(SAMPLE_ISDN_RAW, filename="router_capture_99.txt")
    assert res.trace_type == "ISDN_Q931"
    assert res.device_type == "VOICE_GATEWAY"
    assert res.confidence >= 0.85
    assert any("Q931" in e or "SETUP" in e or "callref" in e for e in res.evidence)
    assert res.recommended_filename is not None
    assert "ISDN_Q931" in res.recommended_filename


def test_classify_sip_from_arbitrary_filename():
    classifier = TraceClassifier()
    res = classifier.classify(SAMPLE_SIP_RAW, filename="random_debug_output.txt")
    assert res.trace_type == "SIP"
    assert res.device_type in ("VOICE_GATEWAY", "CUBE")
    assert res.confidence >= 0.85
    assert any("SIP/2.0" in e or "INVITE" in e for e in res.evidence)
    assert res.device_ip == "10.197.206.141" or res.device_ip == "10.197.206.150"


def test_classify_cucm_sdl_from_arbitrary_filename():
    classifier = TraceClassifier()
    res = classifier.classify(SAMPLE_CUCM_SDL_RAW, filename="unknown_dump.log")
    assert res.trace_type == "CUCM_SDL"
    assert res.device_type == "CUCM"
    assert res.confidence >= 0.90
    assert any("FileHead" in e or "SdlSig" in e for e in res.evidence)
    assert res.device_name == "UCM15-HQ-PUB"
    assert res.device_ip == "10.197.206.141"


def test_classify_mgcp_from_arbitrary_filename():
    classifier = TraceClassifier()
    res = classifier.classify(SAMPLE_MGCP_RAW, filename="log_file.txt")
    assert res.trace_type == "MGCP"
    assert res.device_type == "VOICE_GATEWAY"
    assert res.confidence >= 0.85
    assert any("MGCP" in e or "CRCX" in e for e in res.evidence)
