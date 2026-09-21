"""Multi-factor Call Correlation Engine for CUCM SDL traces."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from app.core.logging import get_logger
from app.devices.cucm.sdl.models import Call, CallIdentifier, SDLEvent

logger = get_logger("devices.cucm.sdl.correlator")

# Signals indicating call control / signaling activity (not background periodic timers)
VOICE_SIGNAL_KEYWORDS = {
    "setup", "invite", "bye", "ack", "ringing", "trying", "alert", "connect",
    "disconnect", "release", "notify", "stationinit", "crcx", "mdcx", "dlcx",
    "digit", "routetrans", "callstate", "linestate", "ccb"
}


class SDLCallCorrelator:
    """Correlates disconnected SDL trace events across CI, CDCC, Call-ID, TCP handle, and numbers."""

    def __init__(self, time_proximity_seconds: float = 30.0):
        self.time_proximity_seconds = time_proximity_seconds

    def correlate(self, events: Iterable[SDLEvent]) -> List[Call]:
        """Group a stream or list of SDLEvents into logical Call sessions with correlation rationales."""
        event_list = list(events)
        if not event_list:
            return []

        # Sort events chronologically
        event_list.sort(key=lambda e: e.timestamp)

        # Disjoint-Set / Union-Find structure
        parent: Dict[int, int] = {}

        def find(i: int) -> int:
            if parent[i] == i:
                return i
            parent[i] = find(parent[i])
            return parent[i]

        def union(i: int, j: int) -> None:
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_j] = root_i

        for idx in range(len(event_list)):
            parent[idx] = idx

        # Index events by identifiers for union
        id_map: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        correl_reasons: Dict[int, List[str]] = defaultdict(list)

        for idx, ev in enumerate(event_list):
            keys = self._get_event_keys(ev)
            for k_type, k_val in keys:
                pair = (k_type, k_val)
                if pair in id_map:
                    first_idx = id_map[pair][0]
                    union(first_idx, idx)
                    correl_reasons[idx].append(f"Linked via {k_type}={k_val}")
                id_map[pair].append(idx)

        # Proximity linking: for events with identical calling & called numbers within small time window
        # but missing explicit CI/Call-ID
        num_sessions: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        for idx, ev in enumerate(event_list):
            if ev.calling_number and ev.called_number:
                pair = (ev.calling_number.strip(), ev.called_number.strip())
                for prev_idx in num_sessions[pair]:
                    prev_ev = event_list[prev_idx]
                    gap = (ev.timestamp - prev_ev.timestamp).total_seconds()
                    if 0 <= gap <= self.time_proximity_seconds:
                        union(prev_idx, idx)
                        correl_reasons[idx].append(
                            f"Linked via number pair {pair[0]}->{pair[1]} (gap {gap:.2f}s)"
                        )
                num_sessions[pair].append(idx)

        # Group events by cluster root
        clusters: Dict[int, List[int]] = defaultdict(list)
        for idx in range(len(event_list)):
            root = find(idx)
            clusters[root].append(idx)

        # Build Call objects from meaningful clusters
        calls: List[Call] = []
        for root, indices in clusters.items():
            cluster_events = [event_list[i] for i in indices]

            # Filter out pure background timer noise
            if not self._is_call_related(cluster_events):
                continue

            call = self._create_call_from_cluster(cluster_events, correl_reasons)
            calls.append(call)

        calls.sort(key=lambda c: c.start_time)
        logger.info("Correlated %d events into %d logical calls", len(event_list), len(calls))
        return calls

    def _get_event_keys(self, ev: SDLEvent) -> List[Tuple[str, str]]:
        """Extract all candidate correlation key pairs (type, val) from an SDLEvent."""
        keys = []
        if ev.ci:
            keys.append(("CI", ev.ci.strip()))
        if ev.cdcc:
            keys.append(("CDCC", ev.cdcc.strip()))
        if ev.call_id:
            keys.append(("Call-ID", ev.call_id.strip()))

        ccb_id = ev.attributes.get("ccb_id")
        if ccb_id:
            keys.append(("ccbID", str(ccb_id).strip()))

        tcp_handle = ev.attributes.get("tcp_handle")
        if tcp_handle:
            keys.append(("tcpHandle", str(tcp_handle).strip()))

        app_corr = ev.attributes.get("app_corr")
        if app_corr and str(app_corr) != "0":
            keys.append(("AppCorr", str(app_corr).strip()))

        return keys

    def _is_call_related(self, events: List[SDLEvent]) -> bool:
        """Determine if an event group represents a voice call rather than background polling."""
        for ev in events:
            if ev.calling_number or ev.called_number or ev.ci or ev.call_id:
                return True
            sig_low = (ev.signal or "").lower()
            if any(k in sig_low for k in VOICE_SIGNAL_KEYWORDS):
                return True
            if ev.protocol in ("SIP", "Q931", "MGCP", "SCCP"):
                return True
        return False

    def _create_call_from_cluster(
        self,
        events: List[SDLEvent],
        correl_reasons: Dict[int, List[str]],
    ) -> Call:
        """Synthesize a unified Call object from an event cluster."""
        events.sort(key=lambda e: e.timestamp)
        start_time = events[0].timestamp
        end_time = events[-1].timestamp

        nodes = sorted(list({e.node for e in events if e.node}))
        devices = sorted(list({e.device for e in events if e.device}))
        protocols = sorted(list({e.protocol for e in events if e.protocol}))

        # Determine primary identifiers
        ci = next((e.ci for e in events if e.ci), None)
        cdcc = next((e.cdcc for e in events if e.cdcc), None)
        call_id = next((e.call_id for e in events if e.call_id), None)
        calling_number = next((e.calling_number for e in events if e.calling_number), None)
        called_number = next((e.called_number for e in events if e.called_number), None)

        reasons: Set[str] = set()
        for ev in events:
            # Look up correlation reasons recorded for this event
            reasons.update(ev.attributes.get("correlation_reasons", []))

        # Collect unique CallIdentifiers
        identifiers: List[CallIdentifier] = []
        seen_idents = set()

        if ci and ("CI", ci) not in seen_idents:
            identifiers.append(CallIdentifier(key="CI", value=ci))
            seen_idents.add(("CI", ci))
        if cdcc and ("CDCC", cdcc) not in seen_idents:
            identifiers.append(CallIdentifier(key="CDCC", value=cdcc))
            seen_idents.add(("CDCC", cdcc))
        if call_id and ("Call-ID", call_id) not in seen_idents:
            identifiers.append(CallIdentifier(key="Call-ID", value=call_id))
            seen_idents.add(("Call-ID", call_id))

        for ev in events:
            ccb = ev.attributes.get("ccb_id")
            if ccb and ("ccbID", str(ccb)) not in seen_idents:
                identifiers.append(CallIdentifier(key="ccbID", value=str(ccb)))
                seen_idents.add(("ccbID", str(ccb)))

        if not reasons:
            if ci:
                reasons.add(f"Correlated by CUCM Call Identification CI={ci}")
            elif call_id:
                reasons.add(f"Correlated by SIP Call-ID={call_id}")
            elif calling_number and called_number:
                reasons.add(f"Correlated by party numbers {calling_number} -> {called_number}")
            else:
                reasons.add("Correlated by signaling continuity")

        return Call(
            call_id=call_id,
            ci=ci,
            cdcc=cdcc,
            calling_number=calling_number,
            called_number=called_number,
            start_time=start_time,
            end_time=end_time,
            nodes=nodes,
            devices=devices,
            protocols=protocols,
            events=events,
            correlation_reasons=sorted(list(reasons)),
            call_identifiers=identifiers,
        )
