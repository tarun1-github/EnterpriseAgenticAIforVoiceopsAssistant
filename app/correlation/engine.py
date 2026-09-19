"""Deterministic multi-signal correlation engine for Cisco voice environments."""

from typing import Any, List, Optional
from uuid import uuid4
from app.core.logging import get_logger
from app.correlation.matchers import extract_session_identifiers, infer_call_architecture
from app.correlation.scoring import CorrelationConfig, evaluate_signal_score
from app.models.call_session import CallSession
from app.models.event import VoiceEvent

logger = get_logger("correlation.engine")


class CorrelationEngine:
    """Multi-signal correlation engine linking ISDN, MGCP, SIP, and CUCM events into CallSessions."""

    def __init__(
        self,
        config: Optional[CorrelationConfig] = None,
        anomaly_detector: Optional[Any] = None,
    ) -> None:
        """Initialize engine with configurable thresholds and optional anomaly detector."""
        self.config = config or CorrelationConfig()
        self.anomaly_detector = anomaly_detector

    def correlate(self, events: List[VoiceEvent]) -> List[CallSession]:
        """Group and correlate a list of VoiceEvents into distinct CallSessions.

        Args:
            events: List of raw parsed VoiceEvents.

        Returns:
            List of correlated CallSession instances.
        """
        if not events:
            return []

        # Sort events chronologically where timestamps exist, preserving file order for un-timestamped
        sorted_events = sorted(
            events,
            key=lambda e: (e.timestamp is None, e.timestamp)
        )

        clusters: List[List[VoiceEvent]] = []
        cluster_evidence: List[List[str]] = []
        cluster_scores: List[List[float]] = []

        for event in sorted_events:
            best_idx = -1
            best_score = -1.0
            best_evidence: List[str] = []

            for idx, cluster in enumerate(clusters):
                score, ev_list = evaluate_signal_score(event, cluster, self.config)
                if score > best_score:
                    best_score = score
                    best_idx = idx
                    best_evidence = ev_list

            if best_idx != -1 and best_score >= self.config.merge_threshold:
                clusters[best_idx].append(event)
                cluster_evidence[best_idx].extend(best_evidence)
                cluster_scores[best_idx].append(best_score)
            else:
                # Seed a new session cluster
                clusters.append([event])
                cluster_evidence.append(["Initial call seed event"])
                cluster_scores.append([1.0])

        # Second Pass: Merge clusters that share high-confidence cross-protocol bridges
        merged_clusters, merged_evidence, merged_scores = self._merge_interdependent_clusters(
            clusters, cluster_evidence, cluster_scores
        )

        # Build final CallSession objects
        sessions: List[CallSession] = []
        for cl_events, cl_ev, cl_sc in zip(merged_clusters, merged_evidence, merged_scores):
            identifiers = extract_session_identifiers(cl_events)
            architecture = infer_call_architecture(cl_events)

            # Deduplicate evidence notes
            unique_evidence = list(dict.fromkeys(cl_ev))

            # Overall confidence is the mean affinity of correlated links
            avg_score = sum(cl_sc) / len(cl_sc) if cl_sc else 1.0

            session = CallSession(
                session_id=f"call_{uuid4().hex[:8]}",
                architecture=architecture,
                calling_number=identifiers["calling_number"],
                called_number=identifiers["called_number"],
                start_time=identifiers["start_time"],
                end_time=identifiers["end_time"],
                events=cl_events,
                isdn_call_references=identifiers["isdn_call_references"],
                mgcp_transaction_ids=identifiers["mgcp_transaction_ids"],
                mgcp_call_ids=identifiers["mgcp_call_ids"],
                mgcp_connection_ids=identifiers["mgcp_connection_ids"],
                sip_call_ids=identifiers["sip_call_ids"],
                devices=identifiers["devices"],
                endpoints=identifiers["endpoints"],
                correlation_confidence=round(avg_score, 2),
                correlation_evidence=unique_evidence,
                anomalies=[],
            )

            # Run deterministic anomaly detection if registered
            if self.anomaly_detector:
                try:
                    session.anomalies = self.anomaly_detector.detect_anomalies(session)
                except Exception as exc:
                    logger.error("Anomaly detector error on session %s: %s", session.session_id, exc)

            sessions.append(session)

        logger.info("Correlated %d events into %d CallSession(s)", len(events), len(sessions))
        return sessions

    def _merge_interdependent_clusters(
        self,
        clusters: List[List[VoiceEvent]],
        cluster_evidence: List[List[str]],
        cluster_scores: List[List[float]],
    ) -> tuple[List[List[VoiceEvent]], List[List[str]], List[List[float]]]:
        """Merge clusters that exhibit strong cross-protocol correlation signals."""
        if len(clusters) <= 1:
            return clusters, cluster_evidence, cluster_scores

        merged_clusters: List[List[VoiceEvent]] = []
        merged_evidence: List[List[str]] = []
        merged_scores: List[List[float]] = []

        visited = [False] * len(clusters)

        for i in range(len(clusters)):
            if visited[i]:
                continue

            current_events = list(clusters[i])
            current_ev = list(cluster_evidence[i])
            current_sc = list(cluster_scores[i])
            visited[i] = True

            for j in range(i + 1, len(clusters)):
                if visited[j]:
                    continue

                # Check maximum bridge score between any event in candidate cluster and current cluster
                candidate_cluster = clusters[j]
                max_bridge_score = 0.0
                best_bridge_ev: List[str] = []

                for cand_ev in candidate_cluster:
                    sc, ev_l = evaluate_signal_score(cand_ev, current_events, self.config)
                    if sc > max_bridge_score:
                        max_bridge_score = sc
                        best_bridge_ev = ev_l

                if max_bridge_score >= self.config.merge_threshold:
                    current_events.extend(candidate_cluster)
                    current_ev.extend(cluster_evidence[j])
                    current_ev.extend(best_bridge_ev)
                    current_sc.extend(cluster_scores[j])
                    current_sc.append(max_bridge_score)
                    visited[j] = True

            merged_clusters.append(current_events)
            merged_evidence.append(current_ev)
            merged_scores.append(current_sc)

        return merged_clusters, merged_evidence, merged_scores
