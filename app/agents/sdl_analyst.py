"""Evidence-driven CUCM SDL Analyst Agent producing grounded Root Cause Analysis."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from app.agents.models import RCAResult
from app.core.logging import get_logger
from app.devices.cucm.sdl.evidence import EvidencePack, build_evidence_pack
from app.devices.cucm.sdl.models import Call
from app.knowledge.retriever import BaseKnowledgeRetriever, InMemoryKnowledgeRetriever

logger = get_logger("agents.sdl_analyst")

IST_TZ = ZoneInfo("Asia/Kolkata")


class SDLAnalystAgent:
    """Forensic AI analyst reasoning strictly over structured EvidencePacks and verified domain knowledge."""

    def __init__(
        self,
        retriever: Optional[BaseKnowledgeRetriever] = None,
        llm_client: Optional[Any] = None,
    ):
        self.retriever = retriever or InMemoryKnowledgeRetriever()
        self.llm_client = llm_client
        self.agent_version = "1.0.0"
        self.parser_version = "1.0.0"
        self.knowledge_version = "1.0.0"

    def analyze_call(
        self,
        call: Call,
        user_request: str = "Perform root cause analysis on this call.",
    ) -> RCAResult:
        """Execute evidence-driven RCA workflow on a single Call session."""
        analysis_now = datetime.now(timezone.utc).astimezone(IST_TZ).strftime("%d-%b-%Y %H:%M:%S IST")

        # 1. Synthesize structured EvidencePack
        evidence_pack = build_evidence_pack(call)

        # 2. Retrieve relevant domain knowledge based on anomalies and signals
        retrieved_docs = []
        queries = []
        for anom in evidence_pack.anomalies:
            queries.append(f"{anom.get('type', '')} {anom.get('description', '')}")

        for step in evidence_pack.flow[:5]:
            queries.append(step.get("signal", ""))

        seen_doc_ids = set()
        for q in queries[:4]:
            results = self.retriever.search_knowledge(q, top_k=2)
            for doc in results:
                if doc.id not in seen_doc_ids:
                    seen_doc_ids.add(doc.id)
                    retrieved_docs.append(doc)

        # 3. Analyze Call Flow & State progression
        call_flow_lines = [
            f"Step {s['step_number']}: [{s['state']}] {s['signal']} ({s['direction']}) "
            f"[+{s.get('time_delta_ms', 0):.0f}ms] - {s['source_file']}:{s['source_line']}"
            for s in evidence_pack.flow
        ]

        observations = []
        for anom in evidence_pack.anomalies:
            observations.append(f"[{anom.get('severity')}] {anom.get('type')}: {anom.get('description')}")

        if not observations:
            observations.append("Normal call signaling observed with expected progression and milestones.")

        # 4. Determine Failure Point
        failure_point = None
        for step in reversed(evidence_pack.flow):
            sig_up = step.get("signal", "").upper()
            if any(k in sig_up for k in ["BYE", "CANCEL", "404", "486", "503", "500", "DISCONNECT", "RELEASE"]):
                failure_point = (
                    f"Step {step['step_number']} ({step['signal']}) at {step['timestamp_ist']} "
                    f"in {step['source_file']}:{step['source_line']}"
                )
                break

        if not failure_point and evidence_pack.anomalies:
            failure_point = f"Teardown at final event: {evidence_pack.flow[-1]['signal']} @ {evidence_pack.flow[-1]['timestamp_ist']}"

        # 5. Determine Possible Failure Domains
        failure_domains = []
        for doc in retrieved_docs:
            if doc.category == "signal":
                failure_domains.extend(doc.details.get("possible_failure_domains", []))
            elif doc.category == "failure":
                failure_domains.append(doc.title)

        if not failure_domains:
            if any("SIP" in p for p in call.protocols):
                failure_domains.append("SIP Trunk / Endpoint Signaling")
            if any("Q931" in p for p in call.protocols):
                failure_domains.append("ISDN PRI D-Channel Layer 3")
            if any("MGCP" in p for p in call.protocols):
                failure_domains.append("MGCP Gateway Communication")

        failure_domains = sorted(list(set(failure_domains)))

        # 6. Evaluate Root Cause Confirmation vs Insufficient Evidence
        # Rules:
        # - Never hallucinate a root cause.
        # - If evidence has an explicit reject code (SIP 503, 404, 486 or Q.850 cause), confirm cause.
        # - If evidence is incomplete or merely a premature hangup without failure code, report insufficient evidence.
        has_reject = any(a.get("type") == "REJECTED_RESPONSE" for a in evidence_pack.anomalies)
        has_premature = any(a.get("type") == "PREMATURE_DISCONNECT" for a in evidence_pack.anomalies)
        has_missing = any(a.get("type") == "MISSING_EXPECTED_EVENT" for a in evidence_pack.anomalies)

        additional_evidence: List[str] = []
        recommended_checks: List[str] = []

        if has_reject:
            rej_anom = next(a for a in evidence_pack.anomalies if a.get("type") == "REJECTED_RESPONSE")
            root_cause = f"Call failed due to explicit signaling rejection: {rej_anom.get('description')}."
            confidence = "High"
            confidence_explanation = "Concrete rejection response and reason code captured in verbatim trace records."
            recommended_checks.append("Verify destination endpoint routing and dial-peer configuration.")
            recommended_checks.append("Check remote SIP Trunk gateway status and CAC resource allocation.")

        elif has_premature:
            root_cause = (
                "Root cause cannot be confirmed from CUCM SDL evidence alone. "
                "Call terminated prematurely prior to answer (connect), but trace records indicate normal caller or far-end teardown."
            )
            confidence = "Medium"
            confidence_explanation = (
                "Trace facts demonstrate the disconnection point, but remote user behavior or external PBX signaling "
                "is outside the visibility of this node's SDL trace."
            )
            additional_evidence.append("Packet captures from border controller (CUBE/SBC) to verify teardown initiator.")
            additional_evidence.append("Endpoint client logs (Cisco Jabber / Webex / Phone console logs).")
            recommended_checks.append("Check user ring-no-answer timer configurations.")
            recommended_checks.append("Inspect calling and called party user activity at the time of call drop.")

        elif has_missing:
            root_cause = (
                "Root cause cannot be confirmed from CUCM SDL evidence alone. "
                "Expected signaling milestones were absent, but no fatal diagnostic error code was returned."
            )
            confidence = "Low"
            confidence_explanation = "Observations indicate an incomplete exchange without explicit reason headers."
            additional_evidence.append("Upstream and downstream gateway / trunk trace logs.")
            recommended_checks.append("Verify network connectivity and firewall state tables between CUCM and remote peer.")

        else:
            root_cause = "No failure observed. Signaling conforms to expected call establishment and release sequence."
            confidence = "High"
            confidence_explanation = "All expected milestones were observed in chronological order without state machine violations."
            recommended_checks.append("No action required.")

        # Pull recommended checks from retrieved knowledge
        for doc in retrieved_docs:
            checks = doc.details.get("recommended_checks", [])
            for c in checks:
                if c not in recommended_checks:
                    recommended_checks.append(c)

        # 7. Render exact Phase 13 required output structure
        report_text = self._format_rca_report(
            calling=call.calling_number or "Unknown",
            called=call.called_number or "Unknown",
            timestamp_ist=call.start_time_ist_str,
            nodes=", ".join(call.nodes) or "UCM15-HQ-PUB",
            call_flow=call_flow_lines,
            observations=observations,
            failure_point=failure_point or "None (Successful call completion)",
            evidence=evidence_pack.evidence,
            failure_domains=failure_domains,
            root_cause=root_cause,
            additional_evidence=additional_evidence,
            recommended_checks=recommended_checks,
            confidence=confidence,
            confidence_explanation=confidence_explanation,
        )

        return RCAResult(
            call_id=call.call_id or call.ci or call.id,
            calling_number=call.calling_number or "Unknown",
            called_number=call.called_number or "Unknown",
            timestamp_ist=call.start_time_ist_str,
            timezone="Asia/Kolkata",
            nodes=call.nodes,
            call_flow=call_flow_lines,
            observations=observations,
            failure_point=failure_point,
            evidence=evidence_pack.evidence,
            possible_failure_domains=failure_domains,
            root_cause=root_cause,
            additional_evidence_required=additional_evidence,
            recommended_checks=recommended_checks,
            confidence=confidence,
            confidence_explanation=confidence_explanation,
            analysis_timestamp=analysis_now,
            knowledge_version=self.knowledge_version,
            parser_version=self.parser_version,
            agent_version=self.agent_version,
            formatted_report=report_text,
        )

    def _format_rca_report(
        self,
        calling: str,
        called: str,
        timestamp_ist: str,
        nodes: str,
        call_flow: List[str],
        observations: List[str],
        failure_point: str,
        evidence: List[Dict[str, Any]],
        failure_domains: List[str],
        root_cause: str,
        additional_evidence: List[str],
        recommended_checks: List[str],
        confidence: str,
        confidence_explanation: str,
    ) -> str:
        """Format the report into the exact requested structure."""
        sections = []
        sections.append("### CUCM SDL TRACE ANALYSIS")
        sections.append(f"**Call**\n- **Calling:** `{calling}`\n- **Called:** `{called}`\n- **Timestamp:** `{timestamp_ist}`\n- **Timezone:** `Asia/Kolkata`\n- **CUCM Nodes:** `{nodes}`")

        sections.append("\n#### CALL FLOW")
        for line in call_flow:
            sections.append(f"- {line}")

        sections.append("\n#### OBSERVATIONS")
        for obs in observations:
            sections.append(f"- {obs}")

        sections.append(f"\n#### FAILURE POINT\n{failure_point}")

        sections.append("\n#### EVIDENCE")
        if evidence:
            for item in evidence[:6]:
                sections.append(
                    f"- **[{item.get('source_file')}:{item.get('source_line')} @ {item.get('timestamp_ist')}]** "
                    f"`{item.get('signal')}`\n  ```text\n  {item.get('raw_text')[:180]}\n  ```"
                )
        else:
            sections.append("- No abnormal raw trace lines isolated.")

        sections.append("\n#### POSSIBLE FAILURE DOMAINS")
        for dom in failure_domains:
            sections.append(f"- {dom}")

        sections.append(f"\n#### ROOT CAUSE\n{root_cause}")

        sections.append("\n#### ADDITIONAL EVIDENCE REQUIRED")
        if additional_evidence:
            for item in additional_evidence:
                sections.append(f"- {item}")
        else:
            sections.append("- None. Evidence in trace was sufficient.")

        sections.append("\n#### RECOMMENDED CHECKS")
        for check in recommended_checks:
            sections.append(f"- {check}")

        sections.append(f"\n#### CONFIDENCE\n**{confidence}**\n\n*Rationale:* {confidence_explanation}")

        return "\n".join(sections)
