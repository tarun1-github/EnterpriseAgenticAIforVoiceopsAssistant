"""Matching utilities and architecture inference for call correlation."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from app.models.call_session import CallArchitecture
from app.models.event import ProtocolEnum, VoiceEvent


def infer_call_architecture(events: List[VoiceEvent]) -> CallArchitecture:
    """Infer the call signaling architecture based on the protocols present in the session.

    Architectures:
    1. ISDN_MGCP: PSTN -> ISDN -> VG -> MGCP -> CUCM -> SIP -> Phone
    2. ISDN_SIP: PSTN -> ISDN -> VG -> SIP -> CUCM -> SIP -> Phone
    3. DIRECT_SIP: PSTN -> SIP -> CUCM -> SIP -> Phone
    4. UNKNOWN: Single protocol or unclassified combination
    """
    protocols: Set[ProtocolEnum] = {e.protocol for e in events}

    has_isdn = ProtocolEnum.ISDN in protocols
    has_mgcp = ProtocolEnum.MGCP in protocols
    has_sip = ProtocolEnum.SIP in protocols

    if has_isdn and has_mgcp:
        return CallArchitecture.ISDN_MGCP
    elif has_isdn and has_sip:
        return CallArchitecture.ISDN_SIP
    elif has_sip and not has_isdn and not has_mgcp:
        return CallArchitecture.DIRECT_SIP

    return CallArchitecture.UNKNOWN


def extract_session_identifiers(events: List[VoiceEvent]) -> Dict[str, Any]:
    """Extract and aggregate all addressing, identifiers, and bounds from events."""
    isdn_refs: Set[str] = set()
    mgcp_trans: Set[str] = set()
    mgcp_cids: Set[str] = set()
    mgcp_conns: Set[str] = set()
    sip_cids: Set[str] = set()
    devices: Set[str] = set()
    endpoints: Set[str] = set()

    calling_number: Optional[str] = None
    called_number: Optional[str] = None

    valid_timestamps: List[datetime] = []

    for e in events:
        if e.call_reference:
            isdn_refs.add(e.call_reference)
        if e.call_id:
            if e.protocol == ProtocolEnum.SIP:
                sip_cids.add(e.call_id)
            elif e.protocol == ProtocolEnum.MGCP:
                mgcp_cids.add(e.call_id)

        # MGCP metadata
        if e.protocol == ProtocolEnum.MGCP:
            if e.transaction_id:
                mgcp_trans.add(e.transaction_id)
            cid = e.metadata.get("call_id") or e.call_id
            if cid:
                mgcp_cids.add(cid)
            conn_id = e.metadata.get("connection_id")
            if conn_id:
                mgcp_conns.add(conn_id)

        if e.endpoint:
            endpoints.add(e.endpoint)
        if e.device:
            devices.add(e.device)

        if not calling_number and e.calling_number:
            calling_number = e.calling_number
        if not called_number and e.called_number:
            called_number = e.called_number

        if e.timestamp:
            valid_timestamps.append(e.timestamp)

    start_time = min(valid_timestamps) if valid_timestamps else None
    end_time = max(valid_timestamps) if valid_timestamps else None

    return {
        "isdn_call_references": sorted(list(isdn_refs)),
        "mgcp_transaction_ids": sorted(list(mgcp_trans)),
        "mgcp_call_ids": sorted(list(mgcp_cids)),
        "mgcp_connection_ids": sorted(list(mgcp_conns)),
        "sip_call_ids": sorted(list(sip_cids)),
        "devices": sorted(list(devices)),
        "endpoints": sorted(list(endpoints)),
        "calling_number": calling_number or "Unknown",
        "called_number": called_number or "Unknown",
        "start_time": start_time,
        "end_time": end_time,
    }


def is_call_seed_candidate(event: VoiceEvent) -> bool:
    """Determine whether an event is eligible to seed a new call session.

    A session must have at least one explicit signaling identifier:
    a calling/called number, a call_id, a call_reference, a transaction_id,
    or a call establishment primitive (INVITE, SETUP, CRCX, StationInit).
    Pure internal timer ticks, stats, and un-correlated logs without identifiers
    must not spawn standalone 1-event CallSessions.
    """
    if (event.calling_number and event.calling_number != "Unknown") or (
        event.called_number and event.called_number != "Unknown"
    ):
        return True

    if event.call_id or event.call_reference or event.transaction_id:
        return True

    if event.metadata.get("call_id") or event.metadata.get("connection_id") or event.metadata.get("call_id_ci"):
        return True

    msg = (event.message_type or "").upper()
    if event.protocol == ProtocolEnum.SIP and any(m in msg for m in ["INVITE", "180", "183", "200 OK", "BYE", "CANCEL"]):
        return True
    if event.protocol == ProtocolEnum.ISDN and any(m in msg for m in ["SETUP", "CALL_PROC", "ALERTING", "CONNECT", "DISCONNECT", "RELEASE"]):
        return True
    if event.protocol == ProtocolEnum.MGCP and any(m in msg for m in ["CRCX", "MDCX", "DLCX", "RQNT"]):
        return True
    if event.protocol == ProtocolEnum.CUCM and any(sig in msg for sig in ["StationInit", "StationD", "CcSetup", "DigitAnalysis", "CallState"]):
        return True

    return False
