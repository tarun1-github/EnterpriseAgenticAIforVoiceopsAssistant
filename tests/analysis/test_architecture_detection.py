"""Tests for evidence-driven call architecture detection."""

import pytest
from datetime import datetime

from app.models.event import VoiceEvent, ProtocolEnum, DirectionEnum
from app.models.call_session import CallSession, CallArchitecture
from app.analysis.architecture import detect_call_architecture, ArchitectureEvidence


def make_event(protocol: ProtocolEnum, msg_type: str, raw: str = "") -> VoiceEvent:
    return VoiceEvent(
        raw=raw or f"{protocol.value} {msg_type} test log entry",
        timestamp=datetime(2026, 9, 20, 10, 32, 14),
        protocol=protocol,
        direction=DirectionEnum.INBOUND,
        message_type=msg_type,
    )


class TestArchitectureDetection:
    """Test evidence-based topology and architecture inference."""

    def test_isdn_mgcp_cucm_sip_architecture(self):
        """Req 13 & 14: ISDN + MGCP + CUCM SDL + SIP yields PSTN -> ISDN PRI -> Voice Gateway -> MGCP -> CUCM -> SIP -> Phone."""
        events = [
            make_event(ProtocolEnum.ISDN, "SETUP", raw="<PRI> ISDN Q.931 SETUP on Serial0/0/0:23"),
            make_event(ProtocolEnum.ISDN, "CALL_PROCEEDING", raw="ISDN Q.931 CALL_PROCEEDING"),
            make_event(ProtocolEnum.MGCP, "CRCX", raw="CRCX 1234 s0/su1/ds1-0@vgr MGCP 0.1"),
            make_event(ProtocolEnum.MGCP, "200", raw="200 1234 OK"),
            make_event(ProtocolEnum.SIP, "INVITE", raw="00602822.000 |08:52:35.085 |AppInfo |MGCPHandler SdlSig INVITE sip:1001@10.197.206.141"),
            make_event(ProtocolEnum.SIP, "180 Ringing", raw="SIP/2.0 180 Ringing"),
        ]

        arch = detect_call_architecture(events)

        assert arch.architecture_name == "PSTN → ISDN PRI → Voice Gateway → MGCP → CUCM → SIP → Phone"
        assert arch.architecture_enum == CallArchitecture.ISDN_MGCP
        assert "PSTN\n↓\nISDN PRI\n↓\nVoice Gateway\n↓\nMGCP\n↓\nCUCM\n↓\nSIP\n↓\nPhone" in arch.flow_vertical
        assert arch.confidence == "High"
        assert arch.confidence_score >= 0.85

        # Check evidence items
        checklist_str = " ".join(arch.evidence_checklist)
        assert "ISDN Q.931 detected" in checklist_str
        assert "PRI interface signaling detected" in checklist_str
        assert "MGCP packets detected" in checklist_str
        assert "CUCM SDL events detected" in checklist_str
        assert "SIP signaling detected" in checklist_str
        assert "H.323" not in checklist_str
        assert "H323" not in arch.architecture_name

    def test_never_report_sip_trunk_for_mgcp_architecture(self):
        """Req 14: Must NOT report SIP Trunk merely because SIP messages exist in an ISDN/MGCP call."""
        events = [
            make_event(ProtocolEnum.ISDN, "SETUP", raw="ISDN Q.931 SETUP call_ref 0x8101"),
            make_event(ProtocolEnum.MGCP, "NTFY", raw="NTFY 852065671 *@VGR.cciecollab.cisco.com MGCP 0.1"),
            make_event(ProtocolEnum.SIP, "INVITE", raw="INVITE sip:2001@10.197.206.141 SIP/2.0"),
            make_event(ProtocolEnum.SIP, "200 OK", raw="SIP/2.0 200 OK"),
        ]

        # Ingestion contains a SIP phone leg
        arch = detect_call_architecture(events)

        assert "SIP Trunk" not in arch.architecture_name
        assert "SIP Trunk" not in arch.flow_vertical
        assert arch.architecture_enum == CallArchitecture.ISDN_MGCP
        assert "MGCP" in arch.architecture_name

    def test_pure_sip_architecture(self):
        """Req 13: Pure SIP events yield SIP -> CUCM -> SIP Phone."""
        events = [
            make_event(ProtocolEnum.SIP, "INVITE", raw="INVITE sip:3001@cucm.local SIP/2.0"),
            make_event(ProtocolEnum.SIP, "100 Trying", raw="SIP/2.0 100 Trying"),
            make_event(ProtocolEnum.SIP, "200 OK", raw="SIP/2.0 200 OK"),
        ]

        arch = detect_call_architecture(events)

        assert arch.architecture_name == "SIP → CUCM → SIP Phone"
        assert arch.architecture_enum == CallArchitecture.DIRECT_SIP
        assert "SIP\n↓\nCUCM\n↓\nSIP Phone" in arch.flow_vertical
        assert "H.323" not in arch.architecture_name

    def test_isdn_sip_gateway_architecture(self):
        """Req 13: ISDN + SIP without MGCP yields PSTN -> ISDN PRI -> Voice Gateway -> SIP -> CUCM -> SIP -> Phone."""
        events = [
            make_event(ProtocolEnum.ISDN, "SETUP", raw="ISDN Q.931 SETUP on PRI Serial0/0/0:23"),
            make_event(ProtocolEnum.SIP, "INVITE", raw="INVITE sip:4001@10.197.206.141 from Gateway"),
            make_event(ProtocolEnum.SIP, "200 OK", raw="SIP/2.0 200 OK"),
        ]

        arch = detect_call_architecture(events)

        assert arch.architecture_name == "PSTN → ISDN PRI → Voice Gateway → SIP → CUCM → SIP → Phone"
        assert arch.architecture_enum == CallArchitecture.ISDN_SIP
        assert arch.confidence in ("High", "Medium")
