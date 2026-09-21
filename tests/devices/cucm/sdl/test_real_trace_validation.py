"""Phase 21 Acceptance Test: End-to-end multi-call validation using realistic CUCM 15 SDL trace."""

from datetime import date, datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
import pytest

from app.agents.sdl_analyst import SDLAnalystAgent
from app.devices.cucm.sdl.call_flow import CallFlowEngine
from app.devices.cucm.sdl.call_index import CallIndex
from app.devices.cucm.sdl.correlator import SDLCallCorrelator
from app.devices.cucm.sdl.evidence import build_evidence_pack
from app.devices.cucm.sdl.models import Call, SDLEvent
from app.devices.cucm.sdl.parser import SDLParser

IST_TZ = ZoneInfo("Asia/Kolkata")

# Realistic CUCM 15 SDL Trace containing 2 distinct calls:
# Call 1: Successful SIP Station Call (1001 -> 2002), CI=1010101, CDCC=2020202
# Call 2: Failed SIP Trunk Outbound Call (1001 -> 95551212) receiving SIP 503 Service Unavailable, CI=3030303, CDCC=4040404
REALISTIC_MULTI_CALL_SDL_TRACE = """00644027.000 |13:35:15.018 |FileHead |UTC:+00:00,Date: 2026/09/20, AppName: CCM, AppId: 100, AppNodeId: 1, AppVersion: CUCM Install=15.0.1.12900-234 Build=15.0.1.12900-234 (d3f126) memlog=20, HostName: UCM15-HQ-PUB, HostIPAddress: ::ffff:10.197.206.141, AppStartTime: 2026/09/16 10:55:48, FileNumber: 26, TraceVer: 3.0
00644028.000 |13:35:15.018 |SdlSig   |DbObjectCacheTimer                     |initialized                    |Db(1,100,50,1)                   |SdlTimerService(1,100,3,1)       |1,100,113,1.2^*^*                        |[T:H-H:0,N:0,L:0,V:0,Z:0,D:0]  AppCorr: 0
00644029.000 |13:35:16.100 |AppInfo  |SIPHandler received msg from: 10.197.206.241:5060
INVITE sip:2002@10.197.206.141:5060 SIP/2.0
Via: SIP/2.0/TCP 10.197.206.241:5060;branch=z9hG4bK_call1
From: "Alice" <sip:1001@10.197.206.141>;tag=tag_call1
To: <sip:2002@10.197.206.141>
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 101 INVITE
Contact: <sip:1001@10.197.206.241:5060>
Content-Length: 0

00644030.000 |13:35:16.105 |SdlSig   |CcSetupReq                             |wait                           |SIPCdpc(1,100,185,1)             |SIPHandler(1,100,183,1)          |1,100,14,1.1^*^*                         |[R:N-H:0,N:0,L:0,V:0,Z:0,D:0]  CI=1010101 cdcc=2020202 callingPartyNumber=1001 calledPartyNumber=2002
00644031.000 |13:35:16.200 |AppInfo  |SIPHandler send msg SUCCESSFULLY to: 10.197.206.241:5060
SIP/2.0 100 Trying
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 101 INVITE

00644032.000 |13:35:16.800 |SdlSig   |CcAlertInd                             |wait                           |SIPCdpc(1,100,185,1)             |Cdcc(1,100,20,1)                 |1,100,14,1.1^*^*                         |[R:N-H:0,N:0,L:0,V:0,Z:0,D:0]  CI=1010101 cdcc=2020202
00644033.000 |13:35:16.805 |AppInfo  |SIPHandler send msg SUCCESSFULLY to: 10.197.206.241:5060
SIP/2.0 180 Ringing
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 101 INVITE

00644034.000 |13:35:19.400 |SdlSig   |CcConnectInd                           |wait                           |SIPCdpc(1,100,185,1)             |Cdcc(1,100,20,1)                 |1,100,14,1.1^*^*                         |[R:N-H:0,N:0,L:0,V:0,Z:0,D:0]  CI=1010101 cdcc=2020202
00644035.000 |13:35:19.405 |AppInfo  |SIPHandler send msg SUCCESSFULLY to: 10.197.206.241:5060
SIP/2.0 200 OK
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 101 INVITE

00644036.000 |13:35:19.450 |AppInfo  |SIPHandler received msg from: 10.197.206.241:5060
ACK sip:2002@10.197.206.141:5060 SIP/2.0
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 101 ACK

00644037.000 |13:35:28.000 |AppInfo  |SIPHandler received msg from: 10.197.206.241:5060
BYE sip:2002@10.197.206.141:5060 SIP/2.0
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 102 BYE

00644038.000 |13:35:28.010 |AppInfo  |SIPHandler send msg SUCCESSFULLY to: 10.197.206.241:5060
SIP/2.0 200 OK
Call-ID: call1-sip-id-9999@10.197.206.241
CSeq: 102 BYE

00644040.000 |13:36:10.000 |AppInfo  |SIPHandler received msg from: 10.197.206.241:5060
INVITE sip:95551212@10.197.206.141:5060 SIP/2.0
Via: SIP/2.0/TCP 10.197.206.241:5060;branch=z9hG4bK_call2
From: "Alice" <sip:1001@10.197.206.141>;tag=tag_call2
To: <sip:95551212@10.197.206.141>
Call-ID: call2-sip-id-8888@10.197.206.241
CSeq: 201 INVITE
Content-Length: 0

00644041.000 |13:36:10.005 |SdlSig   |CcSetupReq                             |wait                           |SIPCdpc(1,100,185,2)             |SIPHandler(1,100,183,1)          |1,100,14,1.2^*^*                         |[R:N-H:0,N:0,L:0,V:0,Z:0,D:0]  CI=3030303 cdcc=4040404 callingPartyNumber=1001 calledPartyNumber=95551212
00644042.000 |13:36:10.150 |AppInfo  |SIPHandler send msg SUCCESSFULLY to: 10.197.206.241:5060
SIP/2.0 100 Trying
Call-ID: call2-sip-id-8888@10.197.206.241
CSeq: 201 INVITE

00644043.000 |13:36:10.500 |AppInfo  |SIPHandler send msg SUCCESSFULLY to: 10.197.206.241:5060
SIP/2.0 503 Service Unavailable
Via: SIP/2.0/TCP 10.197.206.241:5060;branch=z9hG4bK_call2
Call-ID: call2-sip-id-8888@10.197.206.241
CSeq: 201 INVITE
Reason: Q.850;cause=34;text="No circuit/channel available"
"""


def test_real_trace_end_to_end_acceptance(tmp_path):
    trace_file = tmp_path / "realistic_cucm15_trace.txt"
    trace_file.write_text(REALISTIC_MULTI_CALL_SDL_TRACE, encoding="utf-8")

    # 1. Parse trace deterministically
    parser = SDLParser()
    events = parser.parse_file(trace_file)
    assert len(events) >= 12

    # Verify node and date propagation from FileHead
    assert events[0].node == "UCM15-HQ-PUB"
    assert events[0].timestamp.date() == date(2026, 9, 20)

    # 2. Correlate events into logical calls
    correlator = SDLCallCorrelator()
    calls = correlator.correlate(events)
    assert len(calls) == 2, f"Expected exactly 2 distinct calls, got {len(calls)}"

    call_success = next(c for c in calls if c.called_number == "2002")
    call_failed = next(c for c in calls if c.called_number == "95551212")

    # 3. Verify Display Calling, Called, and Timezone conversion to IST
    assert call_success.calling_number == "1001"
    assert call_success.called_number == "2002"
    # 13:35:16 UTC -> 19:05:16 IST
    assert "19:05:16" in call_success.start_time_ist_str
    assert "IST" in call_success.start_time_ist_str

    assert call_failed.calling_number == "1001"
    assert call_failed.called_number == "95551212"
    assert "19:06:10" in call_failed.start_time_ist_str
    assert "IST" in call_failed.start_time_ist_str

    # 4. Verify Call Indexing and search
    index = CallIndex()
    index.add_calls(calls)
    assert index.total_calls == 2

    search_1001 = index.find_calls(calling_number="1001")
    assert len(search_1001) == 2

    search_9555 = index.find_calls(called_number="95551212")
    assert len(search_9555) == 1
    assert search_9555[0].ci == "3030303"

    # 5. Build Call Flow and State Machine Progression for both calls
    flow_engine = CallFlowEngine()
    flow_success = flow_engine.analyze(call_success)
    assert len(flow_success.missing_events) == 0

    flow_failed = flow_engine.analyze(call_failed)
    # The failed call never reached 180 Ringing or 200 OK
    assert len(flow_failed.missing_events) >= 1

    # 6. Generate EvidencePack for the failed call
    pack = build_evidence_pack(call_failed, flow_report=flow_failed)
    assert pack.call["calling"] == "1001"
    assert pack.call["called"] == "95551212"
    assert pack.call["timezone"] == "Asia/Kolkata"
    assert pack.identifiers["CI"] == "3030303"
    assert any(a["type"] == "REJECTED_RESPONSE" for a in pack.anomalies)

    # 7. Run Agent Analysis
    agent = SDLAnalystAgent()
    rca_res = agent.analyze_call(call_failed)

    # 8. Verify Evidence-Based RCA Output
    assert rca_res.confidence == "High"
    assert "explicit signaling rejection" in rca_res.root_cause
    assert "503 Service Unavailable" in rca_res.root_cause
    assert "CUCM SDL TRACE ANALYSIS" in rca_res.formatted_report
    assert "CALL FLOW" in rca_res.formatted_report
    assert "OBSERVATIONS" in rca_res.formatted_report
    assert "FAILURE POINT" in rca_res.formatted_report
    assert "POSSIBLE FAILURE DOMAINS" in rca_res.formatted_report
    assert "ROOT CAUSE" in rca_res.formatted_report
    assert "RECOMMENDED CHECKS" in rca_res.formatted_report
    assert "CONFIDENCE" in rca_res.formatted_report
    assert "High" in rca_res.formatted_report
