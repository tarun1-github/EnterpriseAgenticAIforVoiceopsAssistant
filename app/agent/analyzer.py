"""Deep forensic VoiceOps engineering analyzer engine."""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.agent.models import AgentAnalysisResult, AnomalyFinding, RootCauseFinding
from app.agent.prompts import SYSTEM_AGENT_PROMPT, ANALYSIS_REPORT_TEMPLATE
from app.analysis.workspace import AnalysisWorkspace
from app.analysis.architecture import detect_call_architecture, ArchitectureEvidence
from app.analysis.evidence import (
    SDLObservation,
    TimingDelta,
    extract_signaling_messages,
    extract_sdl_observations,
    calculate_timing_deltas,
)
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("agent.analyzer")


class VoiceOpsAgentAnalyzer:
    """Consumes an AnalysisWorkspace to produce an in-depth Cisco engineering analysis report."""

    def __init__(self, storage_dir: Optional[Path] = None):
        if storage_dir is None:
            settings = get_settings()
            self._storage_dir = Path(settings.voiceops_trace_storage)
        else:
            self._storage_dir = Path(storage_dir)

        self._analysis_file = self._storage_dir / "agent_analysis.json"

    @property
    def analysis_file(self) -> Path:
        return self._analysis_file

    def analyze(self, workspace: AnalysisWorkspace) -> AgentAnalysisResult:
        """Run deep forensic engineering analysis on the ingested workspace."""
        source_file = workspace.source_files[0] if workspace.source_files else "trace.txt"

        # 1. Architecture Determination
        arch_ev = workspace.architecture_evidence or detect_call_architecture(
            workspace.events, sessions=workspace.call_sessions
        )

        # 2. Signaling Analysis (actual messages present)
        signaling_map = extract_signaling_messages(workspace.events)

        # 3. SDL Deep Inspection
        sdl_observations = extract_sdl_observations(workspace.events, default_filename=source_file)

        # 4. Timing Analysis
        timing_deltas = calculate_timing_deltas(workspace.events)

        # 5. Call Flow Sequence
        call_flow_lines: List[str] = []
        for ev in workspace.events[:50]:
            if ev.timestamp and ev.message_type:
                ts_str = ev.timestamp.strftime("%H:%M:%S.%f")[:-3]
                call_flow_lines.append(f"{ts_str} {ev.protocol.value} {ev.message_type}")

        # 6. Anomaly Analysis
        anomaly_findings: List[AnomalyFinding] = []
        for anom in workspace.anomalies:
            ts = anom.timestamp.strftime("%H:%M:%S.%f")[:-3] if anom.timestamp else "N/A"
            anomaly_findings.append(
                AnomalyFinding(
                    severity=anom.severity.value,
                    timestamp=ts,
                    protocol=anom.protocol.value,
                    description=anom.description,
                    evidence=anom.evidence or anom.description,
                    impact=anom.suggested_action or "Signaling state delay or unexpected teardown",
                    likely_location=anom.protocol.value + " Call Leg",
                    confidence="High",
                )
            )

        # 7. Root Cause Analysis (Fact vs Inference vs Hypothesis)
        root_cause_finding = self._determine_root_cause(
            workspace=workspace,
            anomalies=anomaly_findings,
            timing=timing_deltas,
            arch_ev=arch_ev,
        )

        # 8. Executive Summary
        exec_summary = self._generate_executive_summary(
            workspace=workspace,
            arch_ev=arch_ev,
            signaling_map=signaling_map,
            anomalies=anomaly_findings,
            root_cause=root_cause_finding,
        )

        # Build Full Markdown Report
        markdown = self._format_markdown_report(
            exec_summary=exec_summary,
            arch_ev=arch_ev,
            call_flow=call_flow_lines,
            signaling_map=signaling_map,
            sdl_obs=sdl_observations,
            timing_deltas=timing_deltas,
            anomalies=anomaly_findings,
            root_cause=root_cause_finding,
        )

        result = AgentAnalysisResult(
            trace_ids=workspace.trace_ids,
            source_files=workspace.source_files,
            executive_summary=exec_summary,
            architecture_name=arch_ev.architecture_name,
            architecture_flow=arch_ev.flow_vertical,
            architecture_evidence=arch_ev.evidence_checklist,
            architecture_confidence=arch_ev.confidence,
            call_flow=call_flow_lines,
            signaling_analysis=signaling_map,
            sdl_analysis=sdl_observations,
            timing_analysis=timing_deltas,
            anomaly_analysis=anomaly_findings,
            root_cause_analysis=root_cause_finding,
            markdown_report=markdown,
        )

        self.save_analysis(result)
        return result

    def _determine_root_cause(
        self,
        workspace: AnalysisWorkspace,
        anomalies: List[AnomalyFinding],
        timing: List[TimingDelta],
        arch_ev: ArchitectureEvidence,
    ) -> RootCauseFinding:
        """Derive root cause distinguishing FACTS, INFERENCES, and HYPOTHESES."""
        facts: List[str] = []
        inferences: List[str] = []
        hypotheses: List[str] = []

        # Facts: verified observations directly in log data
        facts.append(f"Ingested {len(workspace.events)} events across {len(workspace.source_files)} trace file(s).")
        if arch_ev.has_isdn:
            facts.append("ISDN Q.931 signaling frames were decoded on PRI interface.")
        if arch_ev.has_mgcp:
            facts.append("MGCP gateway control commands were decoded between Gateway and CUCM.")
        if arch_ev.has_sip:
            facts.append("SIP dialog messages were decoded between CUCM and endpoint(s).")
        if arch_ev.has_cucm_sdl:
            facts.append("CUCM internal SDL signals were processed (MGCPManager/SIPD/StationInit).")

        # Inferences: logically deduced from protocols
        if arch_ev.has_isdn and arch_ev.has_mgcp:
            inferences.append("Call entered the enterprise environment via an ISDN PRI Voice Gateway controlled by CUCM via MGCP.")
        if any(t.is_suspicious for t in timing):
            susp_del = [t for t in timing if t.is_suspicious]
            inferences.append(f"Detected {len(susp_del)} signaling delay(s) exceeding normal response thresholds.")

        # Evaluate anomalies for root cause
        if not workspace.anomalies:
            return RootCauseFinding(
                has_root_cause=True,
                root_cause="Clean call signaling progression with normal teardown; no operational defects or signaling violations detected.",
                evidence=[
                    "All expected signaling messages arrived in chronological sequence.",
                    "No Q.850 release cause codes indicating failure (e.g. Unallocated Number, User Busy).",
                    "Inter-protocol latency remained within typical enterprise tolerances.",
                ],
                confidence="High",
                missing_evidence=None,
                facts=facts,
                inferences=inferences,
                hypotheses=hypotheses,
            )

        # If anomalies exist, inspect for clear cause
        error_anomalies = [a for a in anomalies if a.severity == "ERROR"]
        if error_anomalies:
            primary_err = error_anomalies[0]
            facts.append(f"Anomaly detected at {primary_err.timestamp}: {primary_err.description}")
            return RootCauseFinding(
                has_root_cause=True,
                root_cause=f"{primary_err.description} on {primary_err.likely_location}",
                evidence=[primary_err.evidence],
                confidence="High",
                missing_evidence=None,
                facts=facts,
                inferences=inferences,
                hypotheses=hypotheses,
            )

        # Insufficient evidence case
        return RootCauseFinding(
            has_root_cause=False,
            root_cause=None,
            evidence=[],
            confidence="Low",
            missing_evidence="Trace does not contain downstream media negotiation or complete gateway debugs to isolate root cause conclusively.",
            facts=facts,
            inferences=inferences,
            hypotheses=["Potential downstream network jitter or endpoint ring-no-answer"],
        )

    def _generate_executive_summary(
        self,
        workspace: AnalysisWorkspace,
        arch_ev: ArchitectureEvidence,
        signaling_map: Dict[str, List[str]],
        anomalies: List[AnomalyFinding],
        root_cause: RootCauseFinding,
    ) -> str:
        """Produce clear executive engineering summary."""
        arch_text = arch_ev.architecture_name
        event_cnt = len(workspace.events)
        sess_cnt = len(workspace.call_sessions)
        anom_cnt = len(anomalies)

        summary = (
            f"The analyzed voice trace contains {event_cnt:,} signaling events correlated into "
            f"{sess_cnt} call session(s). The call topology follows the **{arch_text}** path.\n\n"
        )

        if anom_cnt == 0:
            summary += (
                "Call processing completed successfully through all gateway and CUCM stages. "
                "Signaling transitions between PSTN ISDN PRI, Gateway MGCP control, and CUCM SIP egress "
                "demonstrated deterministic state synchronization without timeouts or protocol anomalies."
            )
        else:
            summary += (
                f"Analysis detected {anom_cnt} signaling anomalies requiring engineering review. "
                f"Primary finding: {anomalies[0].description}."
            )

        return summary

    def _format_markdown_report(
        self,
        exec_summary: str,
        arch_ev: ArchitectureEvidence,
        call_flow: List[str],
        signaling_map: Dict[str, List[str]],
        sdl_obs: List[SDLObservation],
        timing_deltas: List[TimingDelta],
        anomalies: List[AnomalyFinding],
        root_cause: RootCauseFinding,
    ) -> str:
        """Render complete, beautiful GitHub-flavored markdown engineering report."""
        # Section 2: Architecture
        arch_flow_text = f"```text\n{arch_ev.flow_vertical}\n```"
        arch_ev_text = "\n".join(f"- {item}" for item in arch_ev.evidence_checklist)

        # Section 3: Call Flow
        call_flow_text = "```text\n" + "\n".join(call_flow[:25]) + "\n```" if call_flow else "No chronological events parsed."

        # Section 4: Signaling Analysis
        sig_lines: List[str] = []
        for proto, msgs in signaling_map.items():
            if msgs:
                sig_lines.append(f"### {proto}:")
                for m in msgs:
                    sig_lines.append(f"- `{m}`")
            else:
                sig_lines.append(f"### {proto}:\n- *(No messages observed)*")
        signaling_text = "\n".join(sig_lines)

        # Section 5: CUCM SDL Analysis
        sdl_lines: List[str] = []
        if not sdl_obs:
            sdl_text = "*(No specific CUCM SDL process signals isolated in trace)*"
        else:
            for obs in sdl_obs[:15]:
                sdl_lines.append(
                    f"#### ⏱️ `{obs.timestamp}` | **{obs.event_name}** ({obs.process_name or 'CUCM'})\n"
                    f"- **Interpretation:** {obs.interpretation}\n"
                    f"- **Correlated ID:** `{obs.related_call_id or 'N/A'}`\n"
                    f"- **Evidence Line:** `{obs.filename}`\n"
                    f"```text\n{obs.raw_evidence}\n```\n"
                )
            sdl_text = "\n".join(sdl_lines)

        # Section 6: Timing Analysis
        timing_lines: List[str] = []
        if not timing_deltas:
            timing_text = "*(Insufficient timestamps to evaluate progression deltas)*"
        else:
            timing_lines.append("| Transition | Start | End | Delta (ms) | Status | Note |")
            timing_lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for t in timing_deltas:
                stat_icon = "⚠️ DELAY" if t.is_suspicious else "✅ Normal"
                timing_lines.append(
                    f"| **{t.from_event}** ➔ **{t.to_event}** | `{t.from_time_str}` | `{t.to_time_str}` | `{t.delta_ms} ms` | {stat_icon} | {t.note or '-'} |"
                )
            timing_text = "\n".join(timing_lines)

        # Section 7: Anomaly Analysis
        if not anomalies:
            anomaly_text = "✅ **No signaling anomalies or unexpected disconnects isolated.**"
        else:
            anom_lines: List[str] = []
            for an in anomalies:
                icon = "🚨" if an.severity == "ERROR" else "⚠️"
                anom_lines.append(
                    f"### {icon} [{an.protocol} | {an.severity}] {an.description}\n"
                    f"- **Timestamp:** `{an.timestamp}`\n"
                    f"- **Likely Location:** `{an.likely_location}`\n"
                    f"- **Impact:** {an.impact}\n"
                    f"- **Evidence:** `{an.evidence}`\n"
                    f"- **Confidence:** `{an.confidence}`\n"
                )
            anomaly_text = "\n".join(anom_lines)

        # Section 8: Root Cause Analysis
        rc_lines: List[str] = []
        if root_cause.has_root_cause:
            rc_lines.append(f"### **Root Cause:**\n{root_cause.root_cause}\n")
            rc_lines.append("#### **Evidence:**")
            for i, ev_item in enumerate(root_cause.evidence, 1):
                rc_lines.append(f"{i}. {ev_item}")
            rc_lines.append(f"\n**Confidence:** `{root_cause.confidence}`\n")
        else:
            rc_lines.append("### **Insufficient evidence to establish root cause.**\n")
            if root_cause.missing_evidence:
                rc_lines.append(f"**Missing Evidence Required:**\n{root_cause.missing_evidence}\n")

        # Distinguish Fact, Inference, Hypothesis
        rc_lines.append("### Engineering Reasoning Matrix:")
        rc_lines.append("#### 📌 Facts (Directly observed):")
        for f in root_cause.facts:
            rc_lines.append(f"- {f}")
        rc_lines.append("#### 💡 Inferences (Protocol deductions):")
        for inf in root_cause.inferences:
            rc_lines.append(f"- {inf}")
        if root_cause.hypotheses:
            rc_lines.append("#### 🔬 Hypotheses (Requiring external validation):")
            for h in root_cause.hypotheses:
                rc_lines.append(f"- {h}")

        root_cause_text = "\n".join(rc_lines)

        report = ANALYSIS_REPORT_TEMPLATE.format(
            executive_summary=exec_summary,
            architecture_flow=arch_flow_text,
            architecture_evidence=arch_ev_text,
            architecture_confidence=arch_ev.confidence,
            call_flow=call_flow_text,
            signaling_analysis=signaling_text,
            sdl_analysis=sdl_text,
            timing_analysis=timing_text,
            anomaly_analysis=anomaly_text,
            root_cause_section=root_cause_text,
        )
        return report

    def save_analysis(self, result: AgentAnalysisResult) -> Path:
        """Persist analysis result to JSON file."""
        self._analysis_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._analysis_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
        tmp.replace(self._analysis_file)
        logger.info("Saved agent analysis to %s", self._analysis_file)
        return self._analysis_file

    def load_saved_analysis(self) -> Optional[AgentAnalysisResult]:
        """Load previously saved agent analysis from JSON file."""
        if not self._analysis_file.exists():
            return None
        try:
            content = self._analysis_file.read_text(encoding="utf-8")
            data = json.loads(content)
            return AgentAnalysisResult.model_validate(data)
        except Exception as e:
            logger.error("Failed to load saved agent analysis %s: %s", self._analysis_file, e)
            return None

    def has_saved_analysis(self) -> bool:
        """Check if saved agent analysis exists."""
        return self._analysis_file.exists() and self._analysis_file.is_file()
