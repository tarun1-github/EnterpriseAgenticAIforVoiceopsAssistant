"""EvidencePack builder synthesizing deterministic SDL analysis into a structured payload for AI reasoning."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.devices.cucm.sdl.anomaly_detector import SDLAnomaly, SDLAnomalyDetector
from app.devices.cucm.sdl.call_flow import CallFlowEngine, CallFlowReport
from app.devices.cucm.sdl.models import Call, SDLEvent


class EvidenceItem(BaseModel):
    """Specific line-level evidence entry."""

    source_file: str
    source_line: int
    timestamp_ist: str
    signal: str
    raw_text: str


class EvidencePack(BaseModel):
    """Self-contained, fact-grounded evidence pack bridging deterministic parsing to AI reasoning."""

    call: Dict[str, Any] = Field(..., description="High-level call metadata and endpoints")
    flow: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological call flow steps")
    states: List[Dict[str, Any]] = Field(default_factory=list, description="State machine transitions")
    anomalies: List[Dict[str, Any]] = Field(default_factory=list, description="Deterministic anomaly observations")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Curated raw trace lines")
    identifiers: Dict[str, Any] = Field(default_factory=dict, description="Correlated call identifiers")
    timing: Dict[str, Any] = Field(default_factory=dict, description="Timing and latency metrics")
    source_files: List[str] = Field(default_factory=list, description="All source files contributing evidence")
    source_line_range: Dict[str, int] = Field(default_factory=dict, description="Min and max line numbers observed")

    def to_prompt_context(self) -> str:
        """Render a clean, formatted Markdown representation of the evidence pack for the LLM."""
        lines = []
        lines.append("### CALL METADATA")
        lines.append(f"- Calling Party: {self.call.get('calling', 'Unknown')}")
        lines.append(f"- Called Party: {self.call.get('called', 'Unknown')}")
        lines.append(f"- Start Time (IST): {self.call.get('start_time_ist', 'N/A')}")
        lines.append(f"- End Time (IST): {self.call.get('end_time_ist', 'N/A')}")
        lines.append(f"- Duration: {self.call.get('duration_seconds', 0.0):.2f}s")
        lines.append(f"- CUCM Node(s): {', '.join(self.call.get('nodes', [])) or 'Unknown'}")
        lines.append(f"- Protocol(s): {', '.join(self.call.get('protocols', []))}")
        lines.append(f"- Device(s): {', '.join(self.call.get('devices', [])) or 'None'}")

        if self.identifiers:
            lines.append("\n### CORRELATED IDENTIFIERS")
            for k, v in self.identifiers.items():
                lines.append(f"- {k}: {v}")

        lines.append("\n### CHRONOLOGICAL CALL FLOW")
        for step in self.flow:
            delta = f"+{step.get('time_delta_ms', 0):.0f}ms" if step.get('step_number', 1) > 1 else "start"
            lines.append(
                f"Step {step.get('step_number')}: [{step.get('state')}] {step.get('signal')} "
                f"({step.get('direction', 'INT')}) ({delta}) - {step.get('source_file')}:{step.get('source_line')}"
            )

        if self.anomalies:
            lines.append("\n### DETERMINISTIC ANOMALIES OBSERVED")
            for anom in self.anomalies:
                lines.append(f"- [{anom.get('severity')}] {anom.get('type')}: {anom.get('description')}")
                if anom.get("evidence"):
                    for ev in anom["evidence"]:
                        lines.append(f"  Supporting fact: {ev}")
        else:
            lines.append("\n### DETERMINISTIC ANOMALIES OBSERVED\n- None detected.")

        if self.evidence:
            lines.append("\n### SUPPORTING RAW SDL EVIDENCE (EXACT TRACE LINES)")
            for item in self.evidence:
                lines.append(
                    f"[{item.get('source_file')}:{item.get('source_line')} @ {item.get('timestamp_ist')}] "
                    f"Signal: {item.get('signal')}\n```\n{item.get('raw_text')}\n```"
                )

        return "\n".join(lines)


def build_evidence_pack(
    call: Call,
    flow_report: Optional[CallFlowReport] = None,
    anomalies: Optional[List[SDLAnomaly]] = None,
) -> EvidencePack:
    """Synthesize a complete, self-contained EvidencePack for a Call session."""
    flow_engine = CallFlowEngine()
    anomaly_detector = SDLAnomalyDetector()

    report = flow_report or flow_engine.analyze(call)
    anom_list = anomalies if anomalies is not None else anomaly_detector.detect(call, report)

    # Call summary dict
    call_dict = {
        "call_id": call.call_id or call.id,
        "ci": call.ci,
        "cdcc": call.cdcc,
        "calling": call.calling_number or "Unknown",
        "called": call.called_number or "Unknown",
        "start_time": call.start_time.isoformat(),
        "end_time": call.end_time.isoformat(),
        "start_time_ist": call.start_time_ist_str,
        "end_time_ist": call.end_time_ist_str,
        "timezone": "Asia/Kolkata",
        "duration_seconds": call.duration_seconds,
        "event_count": call.event_count,
        "nodes": call.nodes,
        "devices": call.devices,
        "protocols": call.protocols,
        "correlation_reasons": call.correlation_reasons,
    }

    # Flow steps dict
    flow_steps = []
    for node in report.nodes:
        flow_steps.append({
            "step_number": node.step_number,
            "timestamp_ist": node.timestamp.strftime("%H:%M:%S.") + f"{node.timestamp.microsecond // 1000:03d}",
            "state": node.state.value,
            "signal": node.signal,
            "protocol": node.protocol,
            "direction": node.direction,
            "source_process": node.source_process,
            "dest_process": node.dest_process,
            "time_delta_ms": node.time_delta_ms,
            "summary": node.summary,
            "source_file": node.source_file,
            "source_line": node.source_line,
        })

    # State transitions
    states = []
    for st in report.state_transitions:
        states.append({
            "from_state": st.from_state.value,
            "to_state": st.to_state.value,
            "trigger_signal": st.trigger_signal,
            "timestamp": st.timestamp.isoformat(),
            "is_valid": st.is_valid,
            "reason": st.reason,
        })

    # Anomalies
    anom_dicts = [a.model_dump() for a in anom_list]

    # Curate important raw trace lines
    # We include key signaling milestones, errors, and any lines directly cited in anomalies
    evidence_items = []
    seen_lines = set()

    for ev in call.events:
        sig_up = (ev.signal or "").upper()
        # Include major signals
        is_key = any(
            k in sig_up
            for k in [
                "SETUP", "INVITE", "100 TRYING", "180 RINGING", "200 OK", "ACK", "BYE",
                "CANCEL", "DISCONNECT", "RELEASE", "MGCPNOTIFY", "CRCX", "MDCX", "DLCX",
                "404", "486", "503", "500"
            ]
        ) or any(
            k in ev.raw_text.upper() for k in ["SIP/2.0 4", "SIP/2.0 5", "SIP/2.0 6", "CAUSE="]
        )

        if is_key and (ev.source_file, ev.source_line) not in seen_lines:
            seen_lines.add((ev.source_file, ev.source_line))
            evidence_items.append({
                "source_file": ev.source_file,
                "source_line": ev.source_line,
                "timestamp_ist": ev.timestamp_ist_str,
                "signal": ev.signal or "EVENT",
                "raw_text": ev.raw_text,
            })

    # Identifiers
    identifiers_dict = {}
    if call.ci:
        identifiers_dict["CI"] = call.ci
    if call.cdcc:
        identifiers_dict["CDCC"] = call.cdcc
    if call.call_id:
        identifiers_dict["Call-ID"] = call.call_id
    for ident in call.call_identifiers:
        identifiers_dict[ident.key] = ident.value

    # Timing
    max_gap = max([g["gap_ms"] for g in report.large_time_gaps], default=0.0)
    timing_dict = {
        "duration_seconds": call.duration_seconds,
        "event_count": call.event_count,
        "max_gap_ms": max_gap,
    }

    # Sources
    src_files = sorted(list({e.source_file for e in call.events if e.source_file}))
    min_line = min([e.source_line for e in call.events], default=1)
    max_line = max([e.source_line for e in call.events], default=1)

    return EvidencePack(
        call=call_dict,
        flow=flow_steps,
        states=states,
        anomalies=anom_dicts,
        evidence=evidence_items,
        identifiers=identifiers_dict,
        timing=timing_dict,
        source_files=src_files,
        source_line_range={"min_line": min_line, "max_line": max_line},
    )
