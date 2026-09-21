"""Normalized Call Flow Engine analyzing signal ordering, time gaps, and expected transitions."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.devices.cucm.sdl.models import Call, SDLEvent
from app.devices.cucm.sdl.state_machine import (
    CallState,
    StateTransition,
    get_state_machine_for_protocols,
)


class CallFlowNode(BaseModel):
    """Single step in a reconstructed call flow."""

    step_number: int
    timestamp: datetime
    state: CallState
    signal: str
    protocol: str
    direction: str
    source_process: Optional[str] = None
    dest_process: Optional[str] = None
    time_delta_ms: float = 0.0
    summary: str
    source_file: str
    source_line: int


class CallFlowReport(BaseModel):
    """Structured report of call flow execution, observed vs expected milestones, and gaps."""

    call_id: Optional[str] = None
    calling_number: Optional[str] = None
    called_number: Optional[str] = None
    nodes: List[CallFlowNode] = Field(default_factory=list)
    observed_events: List[str] = Field(default_factory=list)
    expected_events: List[str] = Field(default_factory=list)
    missing_events: List[str] = Field(default_factory=list)
    unexpected_events: List[str] = Field(default_factory=list)
    state_transitions: List[StateTransition] = Field(default_factory=list)
    ordering_issues: List[str] = Field(default_factory=list)
    large_time_gaps: List[Dict[str, Any]] = Field(default_factory=list)


class CallFlowEngine:
    """Reconstructs normalized call flows and analyzes milestones and timing anomalies."""

    def __init__(self, time_gap_threshold_ms: float = 4000.0):
        self.time_gap_threshold_ms = time_gap_threshold_ms

    def analyze(self, call: Call) -> CallFlowReport:
        """Analyze a Call session and return a comprehensive CallFlowReport."""
        sm = get_state_machine_for_protocols(call.protocols)
        sm.reset()

        nodes: List[CallFlowNode] = []
        observed_signals: List[str] = []
        unexpected_events: List[str] = []
        large_time_gaps: List[Dict[str, Any]] = []

        prev_time: Optional[datetime] = None

        for idx, ev in enumerate(call.events, start=1):
            delta_ms = 0.0
            if prev_time:
                delta_ms = max(0.0, (ev.timestamp - prev_time).total_seconds() * 1000.0)
                if delta_ms > self.time_gap_threshold_ms:
                    large_time_gaps.append({
                        "step": idx,
                        "prior_event": call.events[idx - 2].signal,
                        "current_event": ev.signal,
                        "gap_ms": round(delta_ms, 2),
                        "timestamp": ev.timestamp.isoformat(),
                    })
            prev_time = ev.timestamp

            trans = sm.step(ev)
            if not trans.is_valid and trans.reason:
                unexpected_events.append(f"Step {idx} ({ev.signal}): {trans.reason}")

            sig_name = ev.signal or ev.protocol or "UNKNOWN"
            observed_signals.append(sig_name)

            src_p = ev.attributes.get("sending_process") or ev.process
            dst_p = ev.attributes.get("receiving_process")

            summary = f"{ev.direction} {sig_name}"
            if ev.calling_number and ev.called_number:
                summary += f" ({ev.calling_number} -> {ev.called_number})"

            nodes.append(
                CallFlowNode(
                    step_number=idx,
                    timestamp=ev.timestamp,
                    state=sm.current_state,
                    signal=sig_name,
                    protocol=ev.protocol or "CUCM",
                    direction=ev.direction or "INTERNAL",
                    source_process=src_p,
                    dest_process=dst_p,
                    time_delta_ms=round(delta_ms, 2),
                    summary=summary,
                    source_file=ev.source_file,
                    source_line=ev.source_line,
                )
            )

        # Evaluate missing milestones based on protocol
        expected_signals, missing_signals, ordering_issues = self._evaluate_protocol_milestones(
            call.protocols, observed_signals
        )

        return CallFlowReport(
            call_id=call.call_id or call.ci or call.id,
            calling_number=call.calling_number,
            called_number=call.called_number,
            nodes=nodes,
            observed_events=observed_signals,
            expected_events=expected_signals,
            missing_events=missing_signals,
            unexpected_events=unexpected_events,
            state_transitions=sm.history,
            ordering_issues=ordering_issues,
            large_time_gaps=large_time_gaps,
        )

    def _evaluate_protocol_milestones(
        self, protocols: List[str], observed: List[str]
    ) -> tuple[List[str], List[str], List[str]]:
        """Identify missing milestones and sequence inversions."""
        protos = {p.upper() for p in protocols}
        obs_upper = [s.upper() for s in observed]

        expected: List[str] = []
        missing: List[str] = []
        ordering_issues: List[str] = []

        if "SIP" in protos:
            expected = ["INVITE", "100 TRYING", "180 RINGING", "200 OK", "ACK"]
            has_invite = any("INVITE" in s for s in obs_upper)
            has_alert = any("180" in s or "RINGING" in s for s in obs_upper)
            has_200 = any("200" in s or "OK" in s for s in obs_upper)
            has_ack = any("ACK" in s for s in obs_upper)
            has_bye = any("BYE" in s for s in obs_upper)

            if has_invite:
                if not has_alert and not has_200:
                    missing.append("180 Ringing (No ringback signal observed)")
                if has_alert and not has_200 and not has_bye:
                    missing.append("200 OK (Call alerted but never answered or terminated without 200 OK)")
                if has_200 and not has_ack:
                    missing.append("ACK (200 OK received without final SIP ACK)")

        elif "Q931" in protos or "ISDN" in protos:
            expected = ["SETUP", "CALL PROCEEDING", "ALERTING", "CONNECT", "DISCONNECT", "RELEASE", "RELEASE COMPLETE"]
            has_setup = any("SETUP" in s for s in obs_upper)
            has_alert = any("ALERT" in s for s in obs_upper)
            has_connect = any("CONNECT" in s for s in obs_upper)
            has_disc = any("DISCONNECT" in s for s in obs_upper)

            if has_setup:
                if not has_alert and not has_connect:
                    missing.append("ALERTING (Setup initiated but no alerting received)")
                if has_alert and not has_connect and not has_disc:
                    missing.append("CONNECT (Call alerting but no answer/connect received)")

        return expected, missing, ordering_issues
