"""Evidence pack generator structuring correlated session evidence for diagnosis."""

from typing import Any, Dict, List
from app.models.call_session import CallSession
from app.models.evidence import EvidencePack


def build_evidence_pack(session: CallSession) -> EvidencePack:
    """Transform a correlated CallSession into a JSON-serializable EvidencePack.

    Args:
        session: Correlated multi-protocol CallSession.

    Returns:
        Structured EvidencePack instance.
    """
    # Build timeline summary
    timeline: List[Dict[str, Any]] = [ev.to_summary_dict() for ev in session.events]

    # Protocol summaries
    protocol_counts: Dict[str, int] = {}
    for ev in session.events:
        protocol_counts[ev.protocol.value] = protocol_counts.get(ev.protocol.value, 0) + 1

    # Missing expected messages from anomalies
    missing_msgs: List[str] = [
        anom.expected_message for anom in session.anomalies if anom.expected_message
    ]

    important_ids: Dict[str, Any] = {
        "calling_party": session.calling_number,
        "called_party": session.called_number,
        "isdn_call_references": session.isdn_call_references,
        "sip_call_ids": session.sip_call_ids,
        "mgcp_call_ids": session.mgcp_call_ids,
        "mgcp_transaction_ids": session.mgcp_transaction_ids,
        "mgcp_connection_ids": session.mgcp_connection_ids,
        "endpoints": session.endpoints,
        "devices": session.devices,
    }

    return EvidencePack(
        call_session=session,
        architecture=session.architecture,
        timeline=timeline,
        protocol_summaries=protocol_counts,
        correlation_evidence=session.correlation_evidence,
        anomalies=session.anomalies,
        missing_expected_messages=missing_msgs,
        important_identifiers=important_ids,
    )
