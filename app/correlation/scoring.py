"""Scoring parameters and weights for multi-signal call correlation."""

from dataclasses import dataclass
from typing import List, Optional, Tuple
from app.models.event import ProtocolEnum, VoiceEvent


@dataclass
class CorrelationConfig:
    """Configurable thresholds and signal weights for the correlation engine."""

    merge_threshold: float = 0.65
    weak_threshold: float = 0.50
    max_time_gap_seconds: float = 45.0

    # Signal Weights (additive evidence)
    weight_direct_call_id: float = 0.65
    weight_call_reference: float = 0.60
    weight_mgcp_transaction: float = 0.60
    weight_mgcp_call_id: float = 0.55
    weight_mgcp_conn_id: float = 0.45
    weight_full_addressing: float = 0.55  # Both calling (ANI) and called (DNIS) match
    weight_partial_addressing: float = 0.25  # Only one matches
    weight_temporal_proximity: float = 0.15
    weight_endpoint_match: float = 0.15
    weight_ip_match: float = 0.10

    # Negative penalties
    penalty_address_conflict: float = 0.60  # Conflicting phone numbers
    penalty_time_exceeded: float = 0.50


def normalize_isdn_callref(ref: Optional[str]) -> Optional[str]:
    """Normalize Q.931 call reference by masking out the direction flag bit (0x80 / 0x8000)."""
    if not ref:
        return None
    try:
        val = int(ref, 16) if ref.lower().startswith("0x") else int(ref)
        hex_clean = ref.lower().replace("0x", "")
        # If 3 or 4 hex chars (e.g. 0082, 8082), it is a 2-octet call reference; mask 0x7FFF
        if len(hex_clean) > 2 or val > 0xFF:
            norm = val & 0x7FFF
            return f"0x{norm:04x}"
        else:
            # 1-octet call reference; mask 0x7F
            norm = val & 0x7F
            return f"0x{norm:02x}"
    except ValueError:
        return ref.lower()


def evaluate_signal_score(
    event: VoiceEvent,
    session_events: List[VoiceEvent],
    config: CorrelationConfig,
) -> Tuple[float, List[str]]:
    """Compute affinity score between a candidate VoiceEvent and an existing set of session events.

    Returns:
        Tuple of (confidence_score, list_of_matching_evidence_reasons).
    """
    if not session_events:
        return 1.0, ["Session initial event"]

    score = 0.0
    evidence: List[str] = []

    # Aggregate session attributes for comparison
    session_sip_cids = {e.call_id for e in session_events if e.call_id}
    session_isdn_refs = {normalize_isdn_callref(e.call_reference) for e in session_events if e.call_reference}
    session_mgcp_trans = {
        e.transaction_id for e in session_events if e.protocol == ProtocolEnum.MGCP and e.transaction_id
    }
    session_mgcp_cids = {
        e.metadata.get("call_id") or e.call_id
        for e in session_events
        if (e.metadata.get("call_id") or e.call_id)
    }
    session_mgcp_conns = {
        e.metadata.get("connection_id") for e in session_events if e.metadata.get("connection_id")
    }
    session_calling = {e.calling_number for e in session_events if e.calling_number}
    session_called = {e.called_number for e in session_events if e.called_number}
    session_endpoints = {e.endpoint for e in session_events if e.endpoint}
    session_ips = {
        ip for e in session_events for ip in [e.source_ip, e.destination_ip] if ip
    }

    # 1. Direct Identifier Matches
    # SIP Call-ID
    if event.call_id and event.call_id in session_sip_cids:
        score += config.weight_direct_call_id
        evidence.append(f"Matched SIP Call-ID: {event.call_id}")

    # ISDN Call Reference (with Q.931 direction flag masked)
    norm_isdn_ref = normalize_isdn_callref(event.call_reference)
    if norm_isdn_ref and norm_isdn_ref in session_isdn_refs:
        score += config.weight_call_reference
        evidence.append(f"Matched ISDN Call Reference: {event.call_reference}")

    # MGCP Transaction ID
    if event.protocol == ProtocolEnum.MGCP and event.transaction_id and event.transaction_id in session_mgcp_trans:
        score += config.weight_mgcp_transaction
        evidence.append(f"Matched MGCP Transaction ID: {event.transaction_id}")

    # MGCP Call-ID
    mgcp_cid = event.metadata.get("call_id") or event.call_id
    if mgcp_cid and mgcp_cid in session_mgcp_cids:
        score += config.weight_mgcp_call_id
        evidence.append(f"Matched MGCP Call-ID: {mgcp_cid}")

    # MGCP Connection-ID
    conn_id = event.metadata.get("connection_id")
    if conn_id and conn_id in session_mgcp_conns:
        score += config.weight_mgcp_conn_id
        evidence.append(f"Matched MGCP Connection-ID: {conn_id}")

    # 2. Addressing Matches (ANI / DNIS)
    calling_match = event.calling_number and event.calling_number in session_calling
    called_match = event.called_number and event.called_number in session_called

    # Check for addressing conflict (completely different numbers present on both sides)
    if event.calling_number and session_calling and event.calling_number not in session_calling:
        score -= config.penalty_address_conflict
    elif event.called_number and session_called and event.called_number not in session_called:
        score -= config.penalty_address_conflict
    else:
        if calling_match and called_match:
            score += config.weight_full_addressing
            evidence.append(f"Matched ANI ({event.calling_number}) and DNIS ({event.called_number})")
        elif calling_match or called_match:
            score += config.weight_partial_addressing
            matched_val = event.calling_number if calling_match else event.called_number
            evidence.append(f"Matched Party Number: {matched_val}")

    # 3. Temporal Proximity
    if event.timestamp:
        session_timestamps = [e.timestamp for e in session_events if e.timestamp]
        if session_timestamps:
            min_delta = min(abs((event.timestamp - ts).total_seconds()) for ts in session_timestamps)
            if min_delta <= config.max_time_gap_seconds:
                score += config.weight_temporal_proximity * (1.0 - (min_delta / config.max_time_gap_seconds))
                evidence.append(f"Temporal proximity within {min_delta:.2f}s")
            else:
                score -= config.penalty_time_exceeded

    # 4. Endpoint & Device Matching
    if event.endpoint and event.endpoint in session_endpoints:
        score += config.weight_endpoint_match
        evidence.append(f"Matched Endpoint: {event.endpoint}")

    # Hardware B-Channel to MGCP Endpoint matching
    # Example: B-channel '1' matches endpoint 'S0/SU0/DS1-0/1@vg224.cisco.com'
    session_b_channels = {
        str(e.metadata.get("b_channel")) for e in session_events if e.metadata.get("b_channel")
    }
    if event.endpoint and session_b_channels:
        ep_name = event.endpoint.split("@")[0]
        for b_ch in session_b_channels:
            if b_ch and (ep_name.endswith(f"/{b_ch}") or ep_name.endswith(f":{b_ch}")):
                score += config.weight_call_reference
                evidence.append(f"Matched ISDN B-channel {b_ch} to MGCP endpoint {event.endpoint}")
                break

    if event.metadata.get("b_channel") and session_endpoints:
        b_ch = str(event.metadata.get("b_channel"))
        for ep in session_endpoints:
            ep_name = ep.split("@")[0]
            if ep_name.endswith(f"/{b_ch}") or ep_name.endswith(f":{b_ch}"):
                score += config.weight_call_reference
                evidence.append(f"Matched ISDN B-channel {b_ch} to MGCP endpoint {ep}")
                break

    # 5. IP Addressing
    event_ips = {ip for ip in [event.source_ip, event.destination_ip, event.metadata.get("rtp_ip")] if ip}
    session_all_ips = session_ips.union({
        e.metadata.get("rtp_ip") for e in session_events if e.metadata.get("rtp_ip")
    })
    common_ips = event_ips.intersection(session_all_ips)
    if common_ips:
        score += config.weight_ip_match * min(2, len(common_ips))
        evidence.append(f"Common Network IP: {', '.join(common_ips)}")

    # Clamp confidence score between 0.0 and 1.0
    normalized_score = max(0.0, min(1.0, score))
    return normalized_score, evidence
