"""Deterministic anomaly detector for CUCM SDL call flows."""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.devices.cucm.sdl.call_flow import CallFlowEngine, CallFlowReport
from app.devices.cucm.sdl.models import Call, SDLEvent
from app.devices.cucm.sdl.state_machine import CallState


class SDLAnomaly(BaseModel):
    """Structured deterministic observation of an abnormal signaling condition."""

    type: str = Field(..., description="Anomaly classification code")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: str = Field(..., description="Fact-based observation description")
    expected: Optional[str] = Field(default=None, description="Expected signal or state")
    after: Optional[str] = Field(default=None, description="Preceding signal or milestone")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Concrete supporting trace facts")


class SDLAnomalyDetector:
    """Deterministic anomaly detection engine operating on Call sessions and flow reports."""

    def __init__(self, excessive_delay_threshold_ms: float = 4000.0):
        self.excessive_delay_threshold_ms = excessive_delay_threshold_ms
        self.flow_engine = CallFlowEngine(time_gap_threshold_ms=excessive_delay_threshold_ms)

    def detect(self, call: Call, flow_report: Optional[CallFlowReport] = None) -> List[SDLAnomaly]:
        """Inspect a call session and return structured observations."""
        report = flow_report or self.flow_engine.analyze(call)
        anomalies: List[SDLAnomaly] = []

        # 1. Check for missing expected protocol milestones
        for missing in report.missing_events:
            parts = missing.split("(", 1)
            expected_sig = parts[0].strip()
            explanation = parts[1].rstrip(")") if len(parts) > 1 else ""

            # Find last observed event for evidence
            last_ev = call.events[-1] if call.events else None
            ev_list = []
            if last_ev:
                ev_list.append({
                    "signal": last_ev.signal,
                    "timestamp": last_ev.timestamp_ist_str,
                    "source_file": last_ev.source_file,
                    "source_line": last_ev.source_line,
                    "snippet": last_ev.raw_text[:120],
                })

            anomalies.append(
                SDLAnomaly(
                    type="MISSING_EXPECTED_EVENT",
                    severity="HIGH",
                    description=f"Expected milestone '{expected_sig}' was not observed. {explanation}".strip(),
                    expected=expected_sig,
                    after=report.observed_events[-1] if report.observed_events else None,
                    evidence=ev_list,
                )
            )

        # 2. Check for unexpected events / state machine violations
        for unexp in report.unexpected_events:
            anomalies.append(
                SDLAnomaly(
                    type="UNEXPECTED_SIGNAL",
                    severity="MEDIUM",
                    description=unexp,
                    evidence=[],
                )
            )

        # 3. Check for excessive time gaps between consecutive events
        for gap in report.large_time_gaps:
            anomalies.append(
                SDLAnomaly(
                    type="EXCESSIVE_DELAY",
                    severity="MEDIUM" if gap["gap_ms"] < 10000 else "HIGH",
                    description=(
                        f"Excessive delay of {gap['gap_ms']:.1f}ms observed between "
                        f"'{gap['prior_event']}' and '{gap['current_event']}'"
                    ),
                    evidence=[gap],
                )
            )

        # 4. Check for premature disconnect (disconnect immediately after setup or before connect)
        has_setup = any(
            s in (e.signal or "").upper() for e in call.events for s in ["INVITE", "SETUP", "CCSETUP"]
        )
        has_connect = any(
            s in (e.signal or "").upper() for e in call.events for s in ["200 OK", "CONNECT", "CCCONNECT"]
        )
        has_disc = any(
            s in (e.signal or "").upper() for e in call.events for s in ["BYE", "DISCONNECT", "CCDISCONNECT", "CANCEL"]
        )

        if has_setup and has_disc and not has_connect:
            disc_ev = next(
                (e for e in call.events if any(s in (e.signal or "").upper() for s in ["BYE", "DISCONNECT", "CANCEL"])),
                None
            )
            ev_list = []
            if disc_ev:
                ev_list.append({
                    "signal": disc_ev.signal,
                    "timestamp": disc_ev.timestamp_ist_str,
                    "source_file": disc_ev.source_file,
                    "source_line": disc_ev.source_line,
                    "snippet": disc_ev.raw_text[:120],
                })

            anomalies.append(
                SDLAnomaly(
                    type="PREMATURE_DISCONNECT",
                    severity="HIGH",
                    description="Call was disconnected/aborted before answering or reaching CONNECT state",
                    expected="200 OK / CONNECT",
                    after="SETUP / INVITE",
                    evidence=ev_list,
                )
            )

        # 5. Check for SIP error responses (4xx, 5xx, 6xx)
        for ev in call.events:
            raw = ev.raw_text
            m_sip_err = re.search(r"SIP/2\.0\s+([456]\d{2})\s+([^\r\n]+)", raw)
            if m_sip_err:
                code, reason_phrase = m_sip_err.group(1), m_sip_err.group(2).strip()
                anomalies.append(
                    SDLAnomaly(
                        type="REJECTED_RESPONSE",
                        severity="HIGH" if code.startswith("5") else "MEDIUM",
                        description=f"SIP failure response received: {code} {reason_phrase}",
                        evidence=[{
                            "signal": ev.signal,
                            "timestamp": ev.timestamp_ist_str,
                            "source_file": ev.source_file,
                            "source_line": ev.source_line,
                            "snippet": f"SIP/2.0 {code} {reason_phrase}",
                        }],
                    )
                )

        return anomalies
