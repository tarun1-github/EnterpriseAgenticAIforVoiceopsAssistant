"""Evidence-driven call architecture detection and topology analysis."""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.models.event import VoiceEvent, ProtocolEnum
from app.models.call_session import CallSession, CallArchitecture


class ArchitectureEvidence(BaseModel):
    """Structured architectural topology detection with evidence and confidence."""

    architecture_name: str = Field(..., description="Human readable architecture designation")
    architecture_enum: CallArchitecture = Field(..., description="Internal CallArchitecture enum")
    flow_vertical: str = Field(..., description="Vertical ASCII flow representation")
    flow_horizontal: str = Field(..., description="Horizontal flow representation")
    evidence_checklist: List[str] = Field(default_factory=list, description="Verified signaling evidence bullets")
    confidence: str = Field("Low", description="High / Medium / Low evidence confidence")
    confidence_score: float = Field(0.0, description="Numerical confidence (0.0 - 1.0)")
    protocol_counts: Dict[str, int] = Field(default_factory=dict, description="Protocol breakdown")
    has_isdn: bool = False
    has_pri_interface: bool = False
    has_mgcp: bool = False
    has_cucm_sdl: bool = False
    has_sip: bool = False


def detect_call_architecture(
    events: List[VoiceEvent],
    sessions: Optional[List[CallSession]] = None,
) -> ArchitectureEvidence:
    """Derive end-to-end call architecture strictly from correlated protocol evidence.

    Rules:
    1. ISDN + MGCP (+ CUCM/SIP) ->
       PSTN -> ISDN PRI -> Voice Gateway -> MGCP -> CUCM -> SIP -> Phone
    2. ISDN + SIP (no MGCP) ->
       PSTN -> ISDN PRI -> Voice Gateway -> SIP -> CUCM -> SIP -> Phone
    3. Pure SIP (no ISDN, no MGCP) ->
       SIP -> CUCM -> SIP Phone
    4. Never infer "SIP Trunk" merely because SIP messages exist between CUCM and phones.
    5. Never introduce H.323.
    """
    if not events and not sessions:
        return ArchitectureEvidence(
            architecture_name="UNKNOWN",
            architecture_enum=CallArchitecture.UNKNOWN,
            flow_vertical="UNKNOWN",
            flow_horizontal="UNKNOWN",
            evidence_checklist=["No trace events available for architecture analysis"],
            confidence="Low",
            confidence_score=0.0,
        )

    # Collect protocol counts and signals
    proto_counts: Dict[str, int] = {}
    has_isdn = False
    has_pri = False
    has_mgcp = False
    has_cucm_sdl = False
    has_sip = False

    for ev in events:
        p_val = ev.protocol.value if ev.protocol else "UNKNOWN"
        proto_counts[p_val] = proto_counts.get(p_val, 0) + 1

        if ev.protocol == ProtocolEnum.ISDN:
            has_isdn = True
            # PRI detection from interface or channel indicators
            raw_lower = ev.raw.lower()
            if (
                "pri" in raw_lower
                or "serial" in raw_lower
                or "controller" in raw_lower
                or "channel id" in raw_lower
                or "bearer capability" in raw_lower
                or "q.931" in raw_lower
            ):
                has_pri = True

        elif ev.protocol == ProtocolEnum.MGCP:
            has_mgcp = True

        elif ev.protocol == ProtocolEnum.SIP:
            has_sip = True

        # CUCM SDL detection
        raw_text = ev.raw
        if (
            "SdlSig" in raw_text
            or "FileHead" in raw_text
            or "MGCPHandler" in raw_text
            or "MGCPManager" in raw_text
            or "SIPD" in raw_text
            or "StationInit" in raw_text
            or "Cc" in raw_text
            or "ccm" in raw_text.lower()
            or "cucm" in raw_text.lower()
            or (ev.metadata and "sdl" in str(ev.metadata).lower())
        ):
            has_cucm_sdl = True

    # Also inspect session-level aggregates if available
    if sessions:
        for s in sessions:
            if s.isdn_call_references or any(e.protocol == ProtocolEnum.ISDN for e in s.events):
                has_isdn = True
            if s.mgcp_transaction_ids or s.mgcp_call_ids or s.endpoints or any(e.protocol == ProtocolEnum.MGCP for e in s.events):
                has_mgcp = True
            if s.sip_call_ids or any(e.protocol == ProtocolEnum.SIP for e in s.events):
                has_sip = True
            if s.architecture == CallArchitecture.ISDN_MGCP:
                has_isdn = True
                has_mgcp = True

    # If ISDN is detected, PRI is the enterprise voice standard interface
    if has_isdn:
        has_pri = True

    # Build Evidence Checklist
    checklist: List[str] = []
    if has_isdn:
        checklist.append(f"✓ ISDN Q.931 detected ({proto_counts.get('ISDN', 0)} frames)")
    if has_pri:
        checklist.append("✓ PRI interface signaling detected")
    if has_mgcp:
        checklist.append(f"✓ MGCP packets detected ({proto_counts.get('MGCP', 0)} packets)")
    if has_cucm_sdl:
        checklist.append("✓ CUCM SDL events detected")
    if has_sip:
        checklist.append(f"✓ SIP signaling detected ({proto_counts.get('SIP', 0)} messages)")

    # ARCHITECTURE EVALUATION
    # Option 1: PSTN -> ISDN PRI -> Voice Gateway -> MGCP -> CUCM -> SIP -> Phone
    if (has_isdn and has_mgcp) or (has_mgcp and has_cucm_sdl and has_isdn):
        arch_name = "PSTN → ISDN PRI → Voice Gateway → MGCP → CUCM → SIP → Phone"
        flow_vert = (
            "PSTN\n"
            "↓\n"
            "ISDN PRI\n"
            "↓\n"
            "Voice Gateway\n"
            "↓\n"
            "MGCP\n"
            "↓\n"
            "CUCM\n"
            "↓\n"
            "SIP\n"
            "↓\n"
            "Phone"
        )
        flow_horiz = "PSTN  ──[ISDN PRI]──▶  Voice Gateway  ──[MGCP]──▶  CUCM  ──[SIP]──▶  Phone"

        # Evidence-based confidence scoring
        ev_score = 0.60
        if has_isdn:
            ev_score += 0.15
        if has_mgcp:
            ev_score += 0.15
        if has_sip:
            ev_score += 0.05
        if has_cucm_sdl:
            ev_score += 0.05

        conf_str = "High" if ev_score >= 0.85 else ("Medium" if ev_score >= 0.65 else "Low")

        return ArchitectureEvidence(
            architecture_name=arch_name,
            architecture_enum=CallArchitecture.ISDN_MGCP,
            flow_vertical=flow_vert,
            flow_horizontal=flow_horiz,
            evidence_checklist=checklist,
            confidence=conf_str,
            confidence_score=round(ev_score, 2),
            protocol_counts=proto_counts,
            has_isdn=has_isdn,
            has_pri_interface=has_pri,
            has_mgcp=has_mgcp,
            has_cucm_sdl=has_cucm_sdl,
            has_sip=has_sip,
        )

    # Option 2: PSTN -> ISDN PRI -> Voice Gateway -> SIP -> CUCM -> SIP -> Phone
    elif has_isdn and has_sip and not has_mgcp:
        arch_name = "PSTN → ISDN PRI → Voice Gateway → SIP → CUCM → SIP → Phone"
        flow_vert = (
            "PSTN\n"
            "↓\n"
            "ISDN PRI\n"
            "↓\n"
            "Voice Gateway\n"
            "↓\n"
            "SIP\n"
            "↓\n"
            "CUCM\n"
            "↓\n"
            "SIP\n"
            "↓\n"
            "Phone"
        )
        flow_horiz = "PSTN  ──[ISDN PRI]──▶  Voice Gateway  ──[SIP]──▶  CUCM  ──[SIP]──▶  Phone"

        ev_score = 0.50
        if has_isdn:
            ev_score += 0.20
        if has_sip:
            ev_score += 0.20
        if has_cucm_sdl:
            ev_score += 0.05

        conf_str = "High" if ev_score >= 0.85 else ("Medium" if ev_score >= 0.65 else "Low")

        return ArchitectureEvidence(
            architecture_name=arch_name,
            architecture_enum=CallArchitecture.ISDN_SIP,
            flow_vertical=flow_vert,
            flow_horizontal=flow_horiz,
            evidence_checklist=checklist,
            confidence=conf_str,
            confidence_score=round(ev_score, 2),
            protocol_counts=proto_counts,
            has_isdn=has_isdn,
            has_pri_interface=has_pri,
            has_mgcp=False,
            has_cucm_sdl=has_cucm_sdl,
            has_sip=has_sip,
        )

    # Option 3: SIP -> CUCM -> SIP Phone
    elif has_sip and not has_isdn and not has_mgcp:
        arch_name = "SIP → CUCM → SIP Phone"
        flow_vert = (
            "SIP\n"
            "↓\n"
            "CUCM\n"
            "↓\n"
            "SIP Phone"
        )
        flow_horiz = "SIP  ──[SIP]──▶  CUCM  ──[SIP]──▶  SIP Phone"

        ev_score = 0.85 if has_cucm_sdl else 0.70
        conf_str = "High" if ev_score >= 0.80 else "Medium"

        return ArchitectureEvidence(
            architecture_name=arch_name,
            architecture_enum=CallArchitecture.DIRECT_SIP,
            flow_vertical=flow_vert,
            flow_horizontal=flow_horiz,
            evidence_checklist=checklist,
            confidence=conf_str,
            confidence_score=round(ev_score, 2),
            protocol_counts=proto_counts,
            has_isdn=False,
            has_pri_interface=False,
            has_mgcp=False,
            has_cucm_sdl=has_cucm_sdl,
            has_sip=True,
        )

    # Fallback if only MGCP present
    elif has_mgcp and not has_isdn:
        arch_name = "PSTN → ISDN PRI → Voice Gateway → MGCP → CUCM → SIP → Phone"
        flow_vert = (
            "PSTN\n"
            "↓\n"
            "ISDN PRI\n"
            "↓\n"
            "Voice Gateway\n"
            "↓\n"
            "MGCP\n"
            "↓\n"
            "CUCM\n"
            "↓\n"
            "SIP\n"
            "↓\n"
            "Phone"
        )
        flow_horiz = "PSTN  ──[ISDN PRI]──▶  Voice Gateway  ──[MGCP]──▶  CUCM  ──[SIP]──▶  Phone"

        return ArchitectureEvidence(
            architecture_name=arch_name,
            architecture_enum=CallArchitecture.ISDN_MGCP,
            flow_vertical=flow_vert,
            flow_horizontal=flow_horiz,
            evidence_checklist=checklist,
            confidence="Medium",
            confidence_score=0.75,
            protocol_counts=proto_counts,
            has_isdn=False,
            has_pri_interface=False,
            has_mgcp=True,
            has_cucm_sdl=has_cucm_sdl,
            has_sip=has_sip,
        )

    return ArchitectureEvidence(
        architecture_name="UNKNOWN",
        architecture_enum=CallArchitecture.UNKNOWN,
        flow_vertical="UNKNOWN",
        flow_horizontal="UNKNOWN",
        evidence_checklist=checklist or ["Insufficient signaling protocols detected"],
        confidence="Low",
        confidence_score=0.20,
        protocol_counts=proto_counts,
    )
