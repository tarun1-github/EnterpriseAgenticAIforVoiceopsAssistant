"""Deterministic signaling anomaly detector for Cisco voice call sessions."""

from typing import Dict, List, Optional, Set
from uuid import uuid4
from app.models.anomaly import AnomalyCategory, AnomalySeverity, CallAnomaly
from app.models.call_session import CallSession
from app.models.event import ProtocolEnum, VoiceEvent

# Known normal cause codes
NORMAL_ISDN_CAUSES = {
    "0x8090",  # Normal call clearing (16)
    "0x8090 - Normal call clearing",
    "0x829F",  # Normal, unspecified (31)
    "0x829F - Normal, unspecified",
}


class AnomalyDetector:
    """Stateful, deterministic detector identifying anomalies in multi-protocol voice sessions."""

    def detect_anomalies(self, session: CallSession) -> List[CallAnomaly]:
        """Examine session events and return a list of detected anomalies.

        Note: Findings are strictly classified as 'Detected anomaly' rather than 'Root cause'.
        """
        anomalies: List[CallAnomaly] = []

        # Split events by protocol
        isdn_events = [e for e in session.events if e.protocol == ProtocolEnum.ISDN]
        sip_events = [e for e in session.events if e.protocol == ProtocolEnum.SIP]
        mgcp_events = [e for e in session.events if e.protocol == ProtocolEnum.MGCP]

        if isdn_events:
            anomalies.extend(self._check_isdn_anomalies(isdn_events))

        if sip_events:
            anomalies.extend(self._check_sip_anomalies(sip_events))

        if mgcp_events:
            anomalies.extend(self._check_mgcp_anomalies(mgcp_events))

        for an in anomalies:
            if not an.call_id:
                an.call_id = session.session_id

        return anomalies

    def _check_isdn_anomalies(self, events: List[VoiceEvent]) -> List[CallAnomaly]:
        """Evaluate deterministic Q.931 call state progression."""
        findings: List[CallAnomaly] = []
        msg_names = [e.message_type for e in events]
        msg_set = set(msg_names)

        has_setup = "SETUP" in msg_set
        has_call_proc = "CALL PROCEEDING" in msg_set or "CALL_PROC" in msg_set
        has_alerting = "ALERTING" in msg_set
        has_connect = "CONNECT" in msg_set
        has_disconnect = "DISCONNECT" in msg_set
        has_release = "RELEASE" in msg_set
        has_rel_comp = "RELEASE COMPLETE" in msg_set or "RELEASE_COMP" in msg_set

        # Rule 1: SETUP without any forward progression
        if has_setup and not (has_call_proc or has_alerting or has_connect or has_disconnect):
            setup_event = next(e for e in events if e.message_type == "SETUP")
            findings.append(
                CallAnomaly(
                    category=AnomalyCategory.MISSING_MESSAGE,
                    protocol=ProtocolEnum.ISDN,
                    severity=AnomalySeverity.ERROR,
                    description="Detected anomaly: ISDN SETUP initiated without subsequent progression (CALL PROCEEDING / ALERTING / CONNECT).",
                    timestamp=setup_event.timestamp,
                    evidence_event_ids=[setup_event.id],
                    expected_message="CALL PROCEEDING or ALERTING",
                    observed_messages=msg_names,
                )
            )

        # Rule 2: ALERTING without CONNECT or DISCONNECT
        if has_alerting and not (has_connect or has_disconnect):
            alert_event = next(e for e in events if e.message_type == "ALERTING")
            findings.append(
                CallAnomaly(
                    category=AnomalyCategory.MISSING_MESSAGE,
                    protocol=ProtocolEnum.ISDN,
                    severity=AnomalySeverity.WARNING,
                    description="Detected anomaly: ISDN ALERTING observed without subsequent call answer (CONNECT) or clearing.",
                    timestamp=alert_event.timestamp,
                    evidence_event_ids=[alert_event.id],
                    expected_message="CONNECT or DISCONNECT",
                    observed_messages=msg_names,
                )
            )

        # Rule 3: DISCONNECT without RELEASE or RELEASE COMPLETE
        if has_disconnect and not (has_release or has_rel_comp):
            disc_event = next(e for e in events if e.message_type == "DISCONNECT")
            findings.append(
                CallAnomaly(
                    category=AnomalyCategory.MISSING_MESSAGE,
                    protocol=ProtocolEnum.ISDN,
                    severity=AnomalySeverity.WARNING,
                    description="Detected anomaly: ISDN DISCONNECT observed without expected RELEASE or RELEASE COMPLETE clearing.",
                    timestamp=disc_event.timestamp,
                    evidence_event_ids=[disc_event.id],
                    expected_message="RELEASE or RELEASE COMPLETE",
                    observed_messages=msg_names,
                )
            )

        # Rule 4: ISDN Cause Code evaluation
        for ev in events:
            if ev.cause_code:
                is_normal = any(normal in ev.cause_code for normal in ["0x8090", "Normal call clearing", "0x829F", "Normal, unspecified"])
                if not is_normal:
                    findings.append(
                        CallAnomaly(
                            category=AnomalyCategory.CAUSE_CODE,
                            protocol=ProtocolEnum.ISDN,
                            severity=AnomalySeverity.ERROR,
                            description=f"Detected anomaly: ISDN call cleared with non-normal cause code '{ev.cause_code}'.",
                            timestamp=ev.timestamp,
                            evidence_event_ids=[ev.id],
                            observed_messages=[ev.message_type],
                        )
                    )

        return findings

    def _check_sip_anomalies(self, events: List[VoiceEvent]) -> List[CallAnomaly]:
        """Evaluate deterministic SIP dialog and transaction progression."""
        findings: List[CallAnomaly] = []
        msg_names = [e.message_type for e in events]

        has_invite = any("INVITE" in e.message_type.upper() and not e.message_type.startswith("SIP/2.0") and not e.message_type.isdigit() for e in events)
        has_provisional = any(e.message_type.startswith("1") and len(e.message_type) >= 3 for e in events)
        has_200_ok = any("200 OK" in e.message_type for e in events)
        has_ack = any(e.message_type == "ACK" for e in events)
        has_bye = any(e.message_type == "BYE" for e in events)

        # Rule 1: INVITE without provisional response
        if has_invite and not has_provisional and not has_200_ok:
            invite_event = next(e for e in events if "INVITE" in e.message_type)
            findings.append(
                CallAnomaly(
                    category=AnomalyCategory.MISSING_MESSAGE,
                    protocol=ProtocolEnum.SIP,
                    severity=AnomalySeverity.WARNING,
                    description="Detected anomaly: SIP INVITE transmitted without provisional response (100 Trying / 180 Ringing).",
                    timestamp=invite_event.timestamp,
                    evidence_event_ids=[invite_event.id],
                    expected_message="100 Trying or 180 Ringing",
                    observed_messages=msg_names,
                )
            )

        # Rule 2: 200 OK (INVITE answer) without ACK
        # If there is a 200 OK and INVITE, but no ACK
        if has_invite and has_200_ok and not has_ack:
            ok_event = next(e for e in events if "200 OK" in e.message_type)
            findings.append(
                CallAnomaly(
                    category=AnomalyCategory.SEQUENCE_ERROR,
                    protocol=ProtocolEnum.SIP,
                    severity=AnomalySeverity.ERROR,
                    description="Detected anomaly: SIP 200 OK call answer received without subsequent ACK acknowledgement.",
                    timestamp=ok_event.timestamp,
                    evidence_event_ids=[ok_event.id],
                    expected_message="ACK",
                    observed_messages=msg_names,
                )
            )

        # Rule 3: BYE without 200 OK
        if has_bye:
            bye_idx = next(i for i, e in enumerate(events) if e.message_type == "BYE")
            has_bye_ok = any("200 OK" in e.message_type for e in events[bye_idx + 1:])
            if not has_bye_ok:
                bye_event = events[bye_idx]
                findings.append(
                    CallAnomaly(
                        category=AnomalyCategory.MISSING_MESSAGE,
                        protocol=ProtocolEnum.SIP,
                        severity=AnomalySeverity.WARNING,
                        description="Detected anomaly: SIP BYE request terminated without 200 OK confirmation.",
                        timestamp=bye_event.timestamp,
                        evidence_event_ids=[bye_event.id],
                        expected_message="200 OK",
                        observed_messages=msg_names,
                    )
                )

        # Rule 4: SIP 4xx / 5xx / 6xx error responses
        for ev in events:
            # Check for error status codes
            code_str = ev.message_type.split()[0] if ev.message_type else ""
            if code_str.isdigit() and int(code_str) >= 400:
                findings.append(
                    CallAnomaly(
                        category=AnomalyCategory.CAUSE_CODE,
                        protocol=ProtocolEnum.SIP,
                        severity=AnomalySeverity.ERROR,
                        description=f"Detected anomaly: SIP signaling failure response '{ev.message_type}'.",
                        timestamp=ev.timestamp,
                        evidence_event_ids=[ev.id],
                        observed_messages=[ev.message_type],
                    )
                )

        return findings

    def _check_mgcp_anomalies(self, events: List[VoiceEvent]) -> List[CallAnomaly]:
        """Evaluate deterministic MGCP request/response transactions."""
        findings: List[CallAnomaly] = []

        # Group events by transaction_id
        transactions: Dict[str, List[VoiceEvent]] = {}
        for ev in events:
            if ev.transaction_id:
                transactions.setdefault(ev.transaction_id, []).append(ev)

        for trans_id, trans_events in transactions.items():
            has_request = any(e.metadata.get("command") in ["CRCX", "MDCX", "DLCX", "RQNT", "RSIP", "AUEP"] or e.message_type in ["CRCX", "MDCX", "DLCX", "RQNT", "RSIP", "AUEP"] for e in trans_events)
            has_response = any(e.metadata.get("response_code") or (e.message_type.split()[0].isdigit() and len(e.message_type.split()[0]) == 3) for e in trans_events)

            if has_request and not has_response:
                req_event = trans_events[0]
                findings.append(
                    CallAnomaly(
                        category=AnomalyCategory.RESPONSE_TIMEOUT,
                        protocol=ProtocolEnum.MGCP,
                        severity=AnomalySeverity.ERROR,
                        description=f"Detected anomaly: MGCP transaction {trans_id} ({req_event.message_type}) sent without receiving response.",
                        timestamp=req_event.timestamp,
                        evidence_event_ids=[req_event.id],
                        expected_message=f"200/250 OK for {req_event.message_type}",
                        observed_messages=[e.message_type for e in trans_events],
                    )
                )

            # Check for error response codes >= 400
            for ev in trans_events:
                resp_code = ev.metadata.get("response_code")
                if resp_code and resp_code >= 400:
                    findings.append(
                        CallAnomaly(
                            category=AnomalyCategory.CAUSE_CODE,
                            protocol=ProtocolEnum.MGCP,
                            severity=AnomalySeverity.ERROR,
                            description=f"Detected anomaly: MGCP transaction {trans_id} failed with error response '{ev.message_type}'.",
                            timestamp=ev.timestamp,
                            evidence_event_ids=[ev.id],
                            observed_messages=[ev.message_type],
                        )
                    )

        return findings
