"""Deep evidence extraction and SDL observation analysis for Cisco Voice traces."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models.event import VoiceEvent, ProtocolEnum


from app.core.timestamps import to_ist_display, ensure_utc


class SDLObservation(BaseModel):
    """Correlated CUCM SDL observation with exact forensic lineage."""

    timestamp: Optional[str] = Field(None, description="Event timestamp (e.g. 08:52:35.085)")
    timestamp_ist: Optional[str] = Field(None, description="Event timestamp formatted in Asia/Kolkata timezone")
    filename: str = Field(..., description="Source trace file name")
    event_name: str = Field(..., description="SDL message or signal name")
    signal: Optional[str] = Field(None, description="Specific SDL Signal name")
    process_name: Optional[str] = Field(None, description="CUCM process (e.g. MGCPHandler, SIPD, StationInit)")
    sending_process: Optional[str] = Field(None, description="SDL sending process")
    receiving_process: Optional[str] = Field(None, description="SDL receiving process")
    correlation_tag: Optional[str] = Field(None, description="Correlation tag (AppCorr, CI, ccbID)")
    trace_type: Optional[str] = Field(None, description="SDL trace type (SdlSig, AppInfo, etc.)")
    app_name: Optional[str] = Field(None, description="Application name (e.g. CCM)")
    device: Optional[str] = Field(None, description="Involved device name")
    peer_ip: Optional[str] = Field(None, description="Involved peer IP address")
    related_call_id: Optional[str] = Field(None, description="Related Call ID or Transaction ID")
    interpretation: str = Field(..., description="Engineering interpretation of the SDL signal")
    raw_evidence: str = Field(..., description="Raw trace line excerpt")

    def to_display_dict(self) -> Dict[str, Any]:
        """Convert observation to dictionary matching Requirement 10 for UI table."""
        return {
            "Timestamp": self.timestamp or "N/A",
            "IST Timestamp": self.timestamp_ist or "N/A",
            "Correlation Tag": self.correlation_tag or "N/A",
            "Sending Process": self.sending_process or self.process_name or "N/A",
            "Receiving Process": self.receiving_process or "N/A",
            "Signal": self.signal or self.event_name,
            "Trace Type": self.trace_type or "SdlSig",
            "Application Name": self.app_name or "CCM",
            "Device": self.device or "N/A",
            "IP": self.peer_ip or "N/A",
            "Raw SDL Line": self.raw_evidence,
        }


class TimingDelta(BaseModel):
    """Calculated inter-event signaling latency with empirical thresholds."""

    from_event: str = Field(..., description="Initial message (e.g. ISDN SETUP)")
    to_event: str = Field(..., description="Subsequent message (e.g. MGCP CRCX)")
    from_time_str: str = Field(...)
    to_time_str: str = Field(...)
    delta_ms: float = Field(..., description="Latency delta in milliseconds")
    is_suspicious: bool = Field(False, description="True if latency exceeds typical signaling SLA")
    threshold_ms: float = Field(2000.0, description="Warning threshold in milliseconds")
    note: Optional[str] = None


class DeepEvidenceExtract(BaseModel):
    """Structured deep evidence extracted from workspace for engineering agent reasoning."""

    isdn_messages_present: List[str] = Field(default_factory=list)
    sip_messages_present: List[str] = Field(default_factory=list)
    mgcp_messages_present: List[str] = Field(default_factory=list)
    sdl_observations: List[SDLObservation] = Field(default_factory=list)
    timing_deltas: List[TimingDelta] = Field(default_factory=list)


def extract_signaling_messages(events: List[VoiceEvent]) -> Dict[str, List[str]]:
    """Extract distinct messages present in the trace per protocol.

    Only returns messages that are ACTUALLY observed in trace logs.
    """
    isdn_msgs: List[str] = []
    sip_msgs: List[str] = []
    mgcp_msgs: List[str] = []

    for ev in events:
        msg = (ev.message_type or "").strip()
        if not msg:
            continue

        if ev.protocol == ProtocolEnum.ISDN:
            if msg not in isdn_msgs:
                isdn_msgs.append(msg)
        elif ev.protocol == ProtocolEnum.SIP:
            if msg not in sip_msgs:
                sip_msgs.append(msg)
        elif ev.protocol == ProtocolEnum.MGCP:
            if msg not in mgcp_msgs:
                mgcp_msgs.append(msg)

    return {
        "ISDN": isdn_msgs,
        "SIP": sip_msgs,
        "MGCP": mgcp_msgs,
    }


def extract_sdl_observations(
    events: List[VoiceEvent],
    default_filename: str = "cucm_sdl_trace.txt",
) -> List[SDLObservation]:
    """Inspect SDL events around correlated calls and extract precise evidence references.

    Looks for:
    - MGCP handler / manager events
    - SIP dialog handling (SIPD, INVITE, 200 OK)
    - Device state changes & station registration (StationInit, StationD)
    - Routing decisions, digit analysis, call setup / teardown
    - Timer expirations or error signals
    """
    observations: List[SDLObservation] = []
    seen_keys = set()

    for ev in events:
        raw = ev.raw or ""
        ts_str = ev.timestamp.strftime("%H:%M:%S.%f")[:-3] if ev.timestamp else (ev.timestamp_raw or "N/A")
        ts_ist = to_ist_display(ev.timestamp) if ev.timestamp else "N/A"
        fname = (ev.metadata.get("source_file") if ev.metadata else None) or default_filename
        meta = ev.metadata or {}
        corr_tag = meta.get("correlation_tag") or meta.get("call_id_ci") or meta.get("ccb_id")
        send_p = meta.get("sending_process") or meta.get("cucm_process")
        recv_p = meta.get("receiving_process")
        t_type = meta.get("trace_type") or "SdlSig"
        dev = ev.device
        pip = ev.source_ip or ev.destination_ip or meta.get("peer_ip")

        # Detect SDL patterns in raw event
        # Pattern 1: MGCPHandler / MGCPManager
        if "MGCPHandler" in raw or "MGCPNotify" in raw or "MGCPManager" in raw:
            match = re.search(r"\|\s*(MGCP\w+)\s*\|?\s*(\w+)?", raw)
            sig_name = match.group(1) if match else "MGCPHandler"
            interp = "CUCM MGCP process handling gateway signaling and endpoint event notification."
            if "received msg from" in raw:
                interp = f"CUCM received inbound MGCP signaling from gateway IP."
            elif "send msg SUCCESSFULLY" in raw:
                interp = f"CUCM acknowledged/sent outbound MGCP command to gateway."

            obs_key = (ts_str, sig_name, raw[:40])
            if obs_key not in seen_keys:
                seen_keys.add(obs_key)
                observations.append(
                    SDLObservation(
                        timestamp=ts_str,
                        timestamp_ist=ts_ist,
                        filename=fname,
                        event_name=sig_name,
                        signal=sig_name,
                        process_name="MGCPManager/MGCPHandler",
                        sending_process=send_p or "MGCPHandler",
                        receiving_process=recv_p or "MGCPManager",
                        correlation_tag=corr_tag,
                        trace_type=t_type,
                        app_name="CCM",
                        device=dev,
                        peer_ip=pip,
                        related_call_id=ev.call_id or ev.transaction_id,
                        interpretation=interp,
                        raw_evidence=raw.strip()[:300],
                    )
                )

        # Pattern 2: SIPD (SIP Dialog & Station processing)
        elif "SIPD" in raw or "SIPStationInit" in raw or "SIPNonceTimer" in raw:
            interp = "CUCM SIP stack managing SIP dialog session state and endpoint registration."
            sig_name = ev.message_type or "SIPDialogEvent"
            obs_key = (ts_str, "SIPD", raw[:40])
            if obs_key not in seen_keys:
                seen_keys.add(obs_key)
                observations.append(
                    SDLObservation(
                        timestamp=ts_str,
                        timestamp_ist=ts_ist,
                        filename=fname,
                        event_name=sig_name,
                        signal=sig_name,
                        process_name="SIPD",
                        sending_process=send_p or "SIPHandler",
                        receiving_process=recv_p or "SIPD",
                        correlation_tag=corr_tag,
                        trace_type=t_type,
                        app_name="CCM",
                        device=dev,
                        peer_ip=pip,
                        related_call_id=ev.call_id,
                        interpretation=interp,
                        raw_evidence=raw.strip()[:300],
                    )
                )

        # Pattern 3: StationInit / DeviceEventReceiptMonitoringTimer
        elif "StationInit" in raw or "DeviceEventReceipt" in raw:
            obs_key = (ts_str, "StationInit", raw[:40])
            if obs_key not in seen_keys:
                seen_keys.add(obs_key)
                observations.append(
                    SDLObservation(
                        timestamp=ts_str,
                        timestamp_ist=ts_ist,
                        filename=fname,
                        event_name="DeviceEventReceiptMonitoringTimer",
                        signal="DeviceEventReceiptMonitoringTimer",
                        process_name="StationInit",
                        sending_process=send_p or "StationInit",
                        receiving_process=recv_p or "SdlTimerService",
                        correlation_tag=corr_tag,
                        trace_type=t_type,
                        app_name="CCM",
                        device=dev,
                        peer_ip=pip,
                        related_call_id=None,
                        interpretation="CUCM monitoring endpoint keepalive and receipt of device events.",
                        raw_evidence=raw.strip()[:300],
                    )
                )

        # Pattern 4: Generic SdlSig
        elif "SdlSig" in raw or meta.get("trace_type") == "SdlSig":
            parts = [p.strip() for p in raw.split("|") if p.strip()]
            sig_name = parts[3] if len(parts) > 3 else (ev.message_type or "SdlSignal")
            state_name = parts[4] if len(parts) > 4 else ""
            proc_from = parts[5] if len(parts) > 5 else ""

            interp = f"CUCM internal SDL signal '{sig_name}' in state '{state_name}'."
            obs_key = (ts_str, sig_name, raw[:40])
            if obs_key not in seen_keys and len(observations) < 50:
                seen_keys.add(obs_key)
                observations.append(
                    SDLObservation(
                        timestamp=ts_str,
                        timestamp_ist=ts_ist,
                        filename=fname,
                        event_name=sig_name,
                        signal=sig_name,
                        process_name=proc_from or "SdlService",
                        sending_process=send_p or proc_from or "SdlService",
                        receiving_process=recv_p or "CCM",
                        correlation_tag=corr_tag,
                        trace_type=t_type,
                        app_name="CCM",
                        device=dev,
                        peer_ip=pip,
                        related_call_id=ev.call_id or meta.get("call_id_ci"),
                        interpretation=interp,
                        raw_evidence=raw.strip()[:300],
                    )
                )

    return observations


def calculate_timing_deltas(events: List[VoiceEvent]) -> List[TimingDelta]:
    """Calculate signaling deltas between consecutive call progression stages.

    Example progression:
    ISDN SETUP -> MGCP CRCX
    MGCP CRCX -> SIP INVITE
    SIP INVITE -> 180 Ringing / 200 OK
    """
    deltas: List[TimingDelta] = []
    timed_events = [e for e in events if e.timestamp and e.message_type]
    timed_events.sort(key=lambda e: ensure_utc(e.timestamp))

    if len(timed_events) < 2:
        return deltas

    # Look for key transitions
    setup_ev = next((e for e in timed_events if e.message_type.upper() in ("SETUP", "ISDN_SETUP")), None)
    crcx_ev = next((e for e in timed_events if "CRCX" in e.message_type.upper()), None)
    invite_ev = next((e for e in timed_events if "INVITE" in e.message_type.upper() and e.protocol == ProtocolEnum.SIP), None)
    ringing_ev = next((e for e in timed_events if "180" in e.message_type or "RINGING" in e.message_type.upper()), None)
    ok_ev = next((e for e in timed_events if "200" in e.message_type or "CONNECT" in e.message_type.upper()), None)

    # 1. SETUP -> CRCX
    if setup_ev and crcx_ev and ensure_utc(crcx_ev.timestamp) >= ensure_utc(setup_ev.timestamp):
        d_ms = round((ensure_utc(crcx_ev.timestamp) - ensure_utc(setup_ev.timestamp)).total_seconds() * 1000.0, 1)
        deltas.append(
            TimingDelta(
                from_event=f"ISDN {setup_ev.message_type}",
                to_event=f"MGCP {crcx_ev.message_type}",
                from_time_str=setup_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                to_time_str=crcx_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                delta_ms=d_ms,
                is_suspicious=d_ms > 2000.0,
                threshold_ms=2000.0,
                note="Inbound PSTN SETUP to Gateway MGCP Connection Creation (CRCX)",
            )
        )

    # 2. CRCX -> SIP INVITE
    if crcx_ev and invite_ev and ensure_utc(invite_ev.timestamp) >= ensure_utc(crcx_ev.timestamp):
        d_ms = round((ensure_utc(invite_ev.timestamp) - ensure_utc(crcx_ev.timestamp)).total_seconds() * 1000.0, 1)
        deltas.append(
            TimingDelta(
                from_event=f"MGCP {crcx_ev.message_type}",
                to_event=f"SIP {invite_ev.message_type}",
                from_time_str=invite_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                to_time_str=crcx_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                delta_ms=d_ms,
                is_suspicious=d_ms > 1500.0,
                threshold_ms=1500.0,
                note="Gateway MGCP Creation to CUCM SIP Egress INVITE",
            )
        )

    # 3. SIP INVITE -> 180 Ringing
    if invite_ev and ringing_ev and ensure_utc(ringing_ev.timestamp) >= ensure_utc(invite_ev.timestamp):
        d_ms = round((ensure_utc(ringing_ev.timestamp) - ensure_utc(invite_ev.timestamp)).total_seconds() * 1000.0, 1)
        deltas.append(
            TimingDelta(
                from_event=f"SIP {invite_ev.message_type}",
                to_event=f"SIP {ringing_ev.message_type}",
                from_time_str=invite_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                to_time_str=ringing_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                delta_ms=d_ms,
                is_suspicious=d_ms > 3000.0,
                threshold_ms=3000.0,
                note="SIP INVITE dispatched to destination endpoint 180 Ringing indication",
            )
        )

    # 4. SIP INVITE -> 200 OK / Connect
    if invite_ev and ok_ev and ensure_utc(ok_ev.timestamp) >= ensure_utc(invite_ev.timestamp):
        d_ms = round((ensure_utc(ok_ev.timestamp) - ensure_utc(invite_ev.timestamp)).total_seconds() * 1000.0, 1)
        deltas.append(
            TimingDelta(
                from_event=f"SIP {invite_ev.message_type}",
                to_event=f"SIP {ok_ev.message_type}",
                from_time_str=invite_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                to_time_str=ok_ev.timestamp.strftime("%H:%M:%S.%f")[:-3],
                delta_ms=d_ms,
                is_suspicious=d_ms > 30000.0,
                threshold_ms=30000.0,
                note="Call answer time (INVITE to 200 OK connect)",
            )
        )

    # Fallback: if specific call progression markers are not all present, calculate deltas between consecutive events
    if not deltas and len(timed_events) >= 2:
        for i in range(min(5, len(timed_events) - 1)):
            e1 = timed_events[i]
            e2 = timed_events[i + 1]
            d_ms = round((ensure_utc(e2.timestamp) - ensure_utc(e1.timestamp)).total_seconds() * 1000.0, 1)
            deltas.append(
                TimingDelta(
                    from_event=f"{e1.protocol.value} {e1.message_type}",
                    to_event=f"{e2.protocol.value} {e2.message_type}",
                    from_time_str=e1.timestamp.strftime("%H:%M:%S.%f")[:-3],
                    to_time_str=e2.timestamp.strftime("%H:%M:%S.%f")[:-3],
                    delta_ms=d_ms,
                    is_suspicious=d_ms > 5000.0,
                    threshold_ms=5000.0,
                    note="Consecutive signaling event progression delta",
                )
            )

    return deltas
