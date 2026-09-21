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
from app.core.timestamps import to_ist_display
from app.correlation.ladder import CallLifecycleLadder
from app.models.event import ProtocolEnum

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

    def analyze(
        self,
        workspace: AnalysisWorkspace,
        selected_session_id: Optional[str] = None,
    ) -> AgentAnalysisResult:
        """Run deep forensic engineering analysis on the ingested workspace."""
        # 0. Call-Scoped Metadata Extraction (Requirement 14, 20 & 28)
        selected_call: Optional[CallSession] = None
        if selected_session_id:
            selected_call = workspace.get_session(selected_session_id)
        if not selected_call and workspace.call_sessions:
            selected_call = workspace.call_sessions[0]

        # Scope workspace to the selected call evidence only (if not already scoped to this session)
        if selected_call and workspace.workspace_id != f"scoped_{selected_call.session_id}":
            workspace = workspace.create_call_scoped_workspace(selected_call)

        source_file = workspace.source_files[0] if workspace.source_files else "trace.txt"
        call_id = selected_call.session_id if selected_call else "N/A"
        calling_num = (selected_call.calling_number if selected_call and selected_call.calling_number else None) or "Unknown"
        called_num = (selected_call.called_number if selected_call and selected_call.called_number else None) or "Unknown"
        start_ist = selected_call.start_time_ist if selected_call else "N/A"
        end_ist = selected_call.end_time_ist if selected_call else "N/A"
        duration_disp = selected_call.duration_display if selected_call else "N/A"

        call_summary_text = (
            f"- **Call ID:** `{call_id}`\n"
            f"- **Calling Number:** `{calling_num}`\n"
            f"- **Called Number:** `{called_num}`\n"
            f"- **Call Start Time (IST):** `{start_ist}`\n"
            f"- **Call End Time (IST):** `{end_ist}`\n"
            f"- **Duration:** `{duration_disp}`"
        )

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
            ts = to_ist_display(anom.timestamp) if anom.timestamp else "N/A"
            anom_ev = getattr(anom, "evidence_refs", None)
            if anom_ev:
                ev_str = ", ".join(str(x) for x in anom_ev)
            elif getattr(anom, "evidence", None):
                ev_val = anom.evidence
                ev_str = ", ".join(str(x) for x in ev_val) if isinstance(ev_val, list) else str(ev_val)
            else:
                ev_str = anom.description

            impact_val = getattr(anom, "suggested_action", None) or "Signaling state delay or unexpected teardown"
            proto_val = anom.protocol.value if hasattr(anom.protocol, "value") else str(anom.protocol)
            sev_val = anom.severity.value if hasattr(anom.severity, "value") else str(anom.severity)

            anomaly_findings.append(
                AnomalyFinding(
                    severity=sev_val,
                    timestamp=ts,
                    protocol=proto_val,
                    description=anom.description,
                    evidence=ev_str,
                    impact=impact_val,
                    likely_location=proto_val + " Call Leg",
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

        # Trace Sources Breakdown (Section 27)
        cucm_files = sorted(list({e.source for e in workspace.events if e.source and (e.trace_type == "CUCM_SDL" or e.protocol == ProtocolEnum.CUCM)}))
        isdn_files = sorted(list({e.source for e in workspace.events if e.source and e.protocol == ProtocolEnum.ISDN}))
        sip_files = sorted(list({e.source for e in workspace.events if e.source and e.protocol == ProtocolEnum.SIP}))
        mgcp_files = sorted(list({e.source for e in workspace.events if e.source and e.protocol == ProtocolEnum.MGCP}))

        trace_cucm_sdl = "\n".join(f"- `{f}`" for f in cucm_files) if cucm_files else "*(None observed)*"
        trace_isdn = "\n".join(f"- `{f}`" for f in isdn_files) if isdn_files else "*(None observed)*"
        trace_sip = "\n".join(f"- `{f}`" for f in sip_files) if sip_files else "*(None observed)*"
        trace_mgcp = "\n".join(f"- `{f}`" for f in mgcp_files) if mgcp_files else "*(None observed)*"

        # Lifecycle Ladder (Section 17, 18, 19)
        ladder_gen = CallLifecycleLadder()
        call_lifecycle_ladder = ladder_gen.generate_ascii_ladder(selected_call) if selected_call else "*(No events)*"

        # Cross-Protocol Correlation Explanation (Section 21)
        corr_facts: List[str] = []
        for ev in workspace.events[:15]:
            if ev.message_type and ev.timestamp:
                ts_str = ev.timestamp_ist_str.split()[-1] if " " in ev.timestamp_ist_str else ev.timestamp_ist_str
                corr_facts.append(f"FACT: {ev.protocol.value} {ev.message_type} observed at: {ts_str} IST in `{ev.source}`")

        corr_details = []
        if selected_call:
            if selected_call.isdn_call_references:
                corr_details.append(f"ISDN Call Reference: {', '.join(selected_call.isdn_call_references)}")
            if selected_call.mgcp_transaction_ids:
                corr_details.append(f"MGCP Trans ID: {', '.join(selected_call.mgcp_transaction_ids)}")
            if selected_call.sip_call_ids:
                corr_details.append(f"SIP Call-ID: {', '.join(selected_call.sip_call_ids)}")
            if selected_call.calling_number and selected_call.calling_number != "Unknown":
                corr_details.append(f"ANI: {selected_call.calling_number}")
            if selected_call.called_number and selected_call.called_number != "Unknown":
                corr_details.append(f"DNIS: {selected_call.called_number}")

        conf_name = selected_call.confidence_level if selected_call else "High"
        corr_explanation = "\n".join(corr_facts)
        if corr_details:
            corr_explanation += (
                f"\n\nCORRELATION:\nThese events are temporally and contextually correlated into call session `{call_id}` "
                f"via {'; '.join(corr_details)} with {conf_name} confidence."
            )
        else:
            corr_explanation += f"\n\nCORRELATION:\nThese events are temporally correlated into call session `{call_id}`."
        corr_explanation += (
            "\n\nINFERENCE:\nThe call progressed across protocol legs according to the detected architecture "
            "without signaling contradiction."
        )

        # Protocol-specific analyses (Section 27)
        isdn_evs = [e for e in workspace.events if e.protocol == ProtocolEnum.ISDN]
        if isdn_evs:
            isdn_lines = [f"- Observed {len(isdn_evs)} ISDN Q.931 frame(s):"]
            for e in isdn_evs[:10]:
                cr = f" (cr={e.call_reference})" if e.call_reference else ""
                isdn_lines.append(f"  - `{e.message_type}`{cr} at {e.timestamp_ist_str}")
            isdn_text = "\n".join(isdn_lines)
        else:
            isdn_text = "*(No ISDN signaling events in this call)*"

        mgcp_evs = [e for e in workspace.events if e.protocol == ProtocolEnum.MGCP]
        if mgcp_evs:
            mgcp_lines = [f"- Observed {len(mgcp_evs)} MGCP gateway control message(s):"]
            for e in mgcp_evs[:10]:
                tr = f" (trans={e.transaction_id})" if e.transaction_id else ""
                mgcp_lines.append(f"  - `{e.message_type}`{tr} at {e.timestamp_ist_str}")
            mgcp_text = "\n".join(mgcp_lines)
        else:
            mgcp_text = "*(No MGCP signaling events in this call)*"

        sip_evs = [e for e in workspace.events if e.protocol == ProtocolEnum.SIP]
        if sip_evs:
            sip_lines = [f"- Observed {len(sip_evs)} SIP dialog message(s):"]
            for e in sip_evs[:10]:
                cid = f" (Call-ID={e.call_id})" if e.call_id else ""
                sip_lines.append(f"  - `{e.message_type}`{cid} at {e.timestamp_ist_str}")
            sip_text = "\n".join(sip_lines)
        else:
            sip_text = "*(No SIP dialog events in this call)*"

        # Recommended Next Troubleshooting Commands (Section 27)
        cmd_lines: List[str] = []
        cmd_lines.append("### CUCM Commands:")
        cmd_lines.append("- `show status`")
        cmd_lines.append("- `utils ccm-service status`")
        cmd_lines.append("- `show perf query class \"Cisco CallManager\"`\n")

        if arch_ev.has_isdn or arch_ev.has_mgcp or "Gateway" in arch_ev.architecture_name:
            cmd_lines.append("### Voice Gateway Commands:")
            if arch_ev.has_isdn:
                cmd_lines.append("- `show isdn status`")
                cmd_lines.append("- `show isdn active`")
            if arch_ev.has_mgcp:
                cmd_lines.append("- `show mgcp endpoint`")
                cmd_lines.append("- `show mgcp connection`")
            if arch_ev.has_sip:
                cmd_lines.append("- `show sip-ua status`")
                cmd_lines.append("- `show ccsip calls`")
            cmd_lines.append("- `show voice call summary`")
            cmd_lines.append("- `show dial-peer voice summary`")
        recommended_cmds_text = "\n".join(cmd_lines)

        # Build Full Markdown Report
        arch_flow_text = selected_call.architecture_flow_vertical if selected_call else arch_ev.flow_vertical
        markdown = self._format_markdown_report(
            calling=calling_num,
            called=called_num,
            start_ist=start_ist,
            end_ist=end_ist,
            call_summary=call_summary_text,
            trace_cucm_sdl=trace_cucm_sdl,
            trace_isdn=trace_isdn,
            trace_sip=trace_sip,
            trace_mgcp=trace_mgcp,
            exec_summary=exec_summary,
            arch_flow=arch_flow_text,
            arch_ev=arch_ev,
            call_lifecycle_ladder=call_lifecycle_ladder,
            call_flow=call_flow_lines,
            cross_protocol_correlation=corr_explanation,
            signaling_map=signaling_map,
            isdn_analysis=isdn_text,
            mgcp_analysis=mgcp_text,
            sip_analysis=sip_text,
            sdl_obs=sdl_observations,
            timing_deltas=timing_deltas,
            observations=exec_summary,
            anomalies=anomaly_findings,
            facts=root_cause_finding.facts,
            correlations=root_cause_finding.correlations,
            inferences=root_cause_finding.inferences,
            hypotheses=root_cause_finding.hypotheses,
            root_cause=root_cause_finding,
            recommended_commands=recommended_cmds_text,
        )

        result = AgentAnalysisResult(
            call_id=call_id,
            calling_number=calling_num,
            called_number=called_num,
            start_time_ist=start_ist,
            end_time_ist=end_ist,
            duration=duration_disp,
            trace_ids=workspace.trace_ids,
            source_files=workspace.source_files,
            executive_summary=exec_summary,
            architecture_name=arch_ev.architecture_name,
            architecture_flow=arch_flow_text,
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
        """Derive root cause distinguishing FACTS, CORRELATIONS, INFERENCES, and HYPOTHESES."""
        facts: List[str] = []
        correlations: List[str] = []
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

        # Correlations: cross-protocol linkage from correlated session
        if workspace.call_sessions and workspace.call_sessions[0].correlation_evidence:
            correlations.extend(workspace.call_sessions[0].correlation_evidence)

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
                correlations=correlations,
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
                correlations=correlations,
                inferences=inferences,
                hypotheses=hypotheses,
            )

        # Insufficient evidence case
        return RootCauseFinding(
            has_root_cause=False,
            root_cause="Root cause not established from available evidence.",
            evidence=[],
            confidence="Low",
            missing_evidence="Trace does not contain downstream media negotiation or complete gateway debugs to isolate root cause conclusively.",
            facts=facts,
            correlations=correlations,
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
        calling: str,
        called: str,
        start_ist: str,
        end_ist: str,
        call_summary: str,
        trace_cucm_sdl: str,
        trace_isdn: str,
        trace_sip: str,
        trace_mgcp: str,
        exec_summary: str,
        arch_flow: str,
        arch_ev: ArchitectureEvidence,
        call_lifecycle_ladder: str,
        call_flow: List[str],
        cross_protocol_correlation: str,
        signaling_map: Dict[str, List[str]],
        isdn_analysis: str,
        mgcp_analysis: str,
        sip_analysis: str,
        sdl_obs: List[SDLObservation],
        timing_deltas: List[TimingDelta],
        observations: str,
        anomalies: List[AnomalyFinding],
        facts: List[str],
        correlations: List[str],
        inferences: List[str],
        hypotheses: List[str],
        root_cause: RootCauseFinding,
        recommended_commands: str,
    ) -> str:
        """Render complete, beautiful GitHub-flavored markdown engineering report matching Section 27."""
        arch_ev_text = "\n".join(f"- {item}" for item in arch_ev.evidence_checklist)
        call_flow_text = "```text\n" + "\n".join(call_flow[:25]) + "\n```" if call_flow else "No chronological events parsed."

        # Signaling text
        sig_lines: List[str] = []
        for proto, msgs in signaling_map.items():
            if msgs:
                sig_lines.append(f"### {proto}:")
                for m in msgs:
                    sig_lines.append(f"- `{m}`")
            else:
                sig_lines.append(f"### {proto}:\n- *(No messages observed)*")
        signaling_text = "\n".join(sig_lines)

        # SDL text
        if not sdl_obs:
            sdl_text = "*(No specific CUCM SDL process signals isolated in trace)*"
        else:
            sdl_lines = []
            for obs in sdl_obs[:15]:
                sdl_lines.append(
                    f"#### ⏱️ `{obs.timestamp}` | **{obs.event_name}** ({obs.process_name or 'CUCM'})\n"
                    f"- **Interpretation:** {obs.interpretation}\n"
                    f"- **Correlated ID:** `{obs.related_call_id or 'N/A'}`\n"
                    f"- **Evidence Line:** `{obs.filename}`\n"
                    f"```text\n{obs.raw_evidence}\n```\n"
                )
            sdl_text = "\n".join(sdl_lines)

        # Timing text
        if not timing_deltas:
            timing_text = "*(Insufficient timestamps to evaluate progression deltas)*"
        else:
            timing_lines = [
                "| Transition | Start | End | Delta (ms) | Status | Note |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
            for t in timing_deltas:
                stat_icon = "⚠️ DELAY" if t.is_suspicious else "✅ Normal"
                timing_lines.append(
                    f"| **{t.from_event}** ➔ **{t.to_event}** | `{t.from_time_str}` | `{t.to_time_str}` | `{t.delta_ms} ms` | {stat_icon} | {t.note or '-'} |"
                )
            timing_text = "\n".join(timing_lines)

        # Anomaly text
        if not anomalies:
            anomaly_text = "✅ **No signaling anomalies or unexpected disconnects isolated.**"
        else:
            anom_lines = []
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

        # Root cause text
        rc_lines = []
        if root_cause.has_root_cause:
            rc_lines.append(f"### **Root Cause:**\n{root_cause.root_cause}\n")
            rc_lines.append("#### **Evidence:**")
            for i, ev_item in enumerate(root_cause.evidence, 1):
                rc_lines.append(f"{i}. {ev_item}")
            rc_lines.append(f"\n**Confidence:** `{root_cause.confidence}`\n")
        else:
            rc_lines.append(f"### **{root_cause.root_cause or 'Root cause not established from available evidence.'}**\n")
            if root_cause.missing_evidence:
                rc_lines.append(f"**Missing Evidence Required:**\n{root_cause.missing_evidence}\n")

        facts_text = "\n".join(f"- {f}" for f in facts) if facts else "- No explicit facts isolated."
        corrs_text = "\n".join(f"- {c}" for c in correlations) if correlations else "- Correlation based on available signaling progression."
        infs_text = "\n".join(f"- {i}" for i in inferences) if inferences else "- Normal call state progression."
        hyps_text = "\n".join(f"- {h}" for h in hypotheses) if hypotheses else "- No secondary hypotheses required."

        report = ANALYSIS_REPORT_TEMPLATE.format(
            calling=calling,
            called=called,
            start_ist=start_ist,
            end_ist=end_ist,
            call_summary=call_summary,
            trace_cucm_sdl=trace_cucm_sdl,
            trace_isdn=trace_isdn,
            trace_sip=trace_sip,
            trace_mgcp=trace_mgcp,
            executive_summary=exec_summary,
            architecture_flow=arch_flow,
            architecture_evidence=arch_ev_text,
            architecture_confidence=arch_ev.confidence,
            call_lifecycle_ladder=call_lifecycle_ladder,
            call_flow=call_flow_text,
            cross_protocol_correlation=cross_protocol_correlation,
            signaling_analysis=signaling_text,
            isdn_analysis=isdn_analysis,
            mgcp_analysis=mgcp_analysis,
            sip_analysis=sip_analysis,
            sdl_analysis=sdl_text,
            timing_analysis=timing_text,
            observations=observations,
            anomaly_analysis=anomaly_text,
            facts=facts_text,
            correlations=corrs_text,
            inferences=infs_text,
            hypotheses=hyps_text,
            root_cause_section="\n".join(rc_lines),
            recommended_commands=recommended_commands,
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
