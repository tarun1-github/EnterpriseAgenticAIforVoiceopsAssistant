"""Unified CallSession model representing correlated multi-protocol call legs."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field
from app.models.anomaly import CallAnomaly
from app.models.event import VoiceEvent


class CallArchitecture(str, Enum):
    """Identified call routing and signaling architecture."""

    ISDN_MGCP = "ISDN_MGCP"
    ISDN_SIP = "ISDN_SIP"
    DIRECT_SIP = "DIRECT_SIP"
    UNKNOWN = "UNKNOWN"


class CallSession(BaseModel):
    """Correlated session combining ISDN, MGCP, SIP, and CUCM events for a single call."""

    session_id: str = Field(default_factory=lambda: f"call_{uuid4().hex[:8]}", description="Unique session identifier")
    architecture: CallArchitecture = Field(default=CallArchitecture.UNKNOWN, description="Inferred call architecture")

    # Addressing
    calling_number: Optional[str] = Field(default=None, description="Calling party (ANI)")
    called_number: Optional[str] = Field(default=None, description="Called party (DNIS)")

    # Temporal bounds
    start_time: Optional[datetime] = Field(default=None, description="Earliest event timestamp")
    end_time: Optional[datetime] = Field(default=None, description="Latest event timestamp")

    # Correlated Events
    events: List[VoiceEvent] = Field(default_factory=list, description="All signaling events linked to this call")

    # Multi-protocol Correlation Identifiers
    isdn_call_references: List[str] = Field(default_factory=list, description="ISDN Q.931 call references")
    mgcp_transaction_ids: List[str] = Field(default_factory=list, description="MGCP transaction IDs")
    mgcp_call_ids: List[str] = Field(default_factory=list, description="MGCP Call Identifiers")
    mgcp_connection_ids: List[str] = Field(default_factory=list, description="MGCP Connection Identifiers")
    sip_call_ids: List[str] = Field(default_factory=list, description="SIP Call-IDs")

    # Entities
    devices: List[str] = Field(default_factory=list, description="Involved CUCM devices or gateways")
    endpoints: List[str] = Field(default_factory=list, description="Involved MGCP endpoints")
    trace_sources: List[str] = Field(default_factory=list, description="Contributing trace filenames")

    # Correlation Diagnostics
    correlation_confidence: float = Field(default=1.0, description="Overall correlation confidence score (0.0 - 1.0)")
    confidence_level: str = Field(default="High", description="High, Medium, or Low correlation confidence")
    correlation_evidence: List[str] = Field(default_factory=list, description="Human-readable justification of signals matched")
    ambiguity_notes: List[str] = Field(default_factory=list, description="Notes on any potentially ambiguous cross-file correlations")

    # Anomaly findings
    anomalies: List[CallAnomaly] = Field(default_factory=list, description="Deterministic signaling anomalies identified")

    @property
    def start_time_ist(self) -> str:
        """Formatted start time in Asia/Kolkata timezone."""
        from app.core.timestamps import to_ist_display
        return to_ist_display(self.start_time)

    @property
    def end_time_ist(self) -> str:
        """Formatted end time in Asia/Kolkata timezone."""
        from app.core.timestamps import to_ist_display
        return to_ist_display(self.end_time)

    @property
    def duration_seconds(self) -> float:
        """Duration of call in seconds."""
        if self.start_time and self.end_time:
            from app.core.timestamps import ensure_utc
            delta = (ensure_utc(self.end_time) - ensure_utc(self.start_time)).total_seconds()
            return max(0.0, round(delta, 3))
        return 0.0

    @property
    def duration_display(self) -> str:
        """Human-readable call duration."""
        if not self.start_time or not self.end_time:
            return "N/A"
        sec = self.duration_seconds
        if sec < 1.0:
            return f"{int(sec * 1000)}ms"
        return f"{sec:.2f}s"

    @property
    def protocol_counts(self) -> Dict[str, int]:
        """Count of events per protocol for this call session."""
        counts = {"ISDN": 0, "MGCP": 0, "SIP": 0, "CUCM": 0}
        for ev in self.events:
            p_name = ev.protocol.value if hasattr(ev.protocol, "value") else str(ev.protocol)
            counts[p_name] = counts.get(p_name, 0) + 1
        return counts

    @property
    def architecture_flow_vertical(self) -> str:
        """Render vertical call architecture path reflecting protocol legs."""
        if self.architecture == CallArchitecture.ISDN_MGCP:
            return "PSTN\n↓\nISDN PRI\n↓\nVoice Gateway\n↓\nMGCP\n↓\nCUCM\n↓\nSIP\n↓\nPhone"
        elif self.architecture == CallArchitecture.ISDN_SIP:
            return "PSTN\n↓\nISDN PRI\n↓\nVoice Gateway\n↓\nSIP\n↓\nCUCM\n↓\nSIP\n↓\nPhone"
        elif self.architecture == CallArchitecture.DIRECT_SIP:
            return "PSTN / CUBE\n↓\nSIP Trunk\n↓\nCUCM\n↓\nSIP\n↓\nPhone"
        else:
            return "PSTN\n↓\nVoice Gateway\n↓\nCUCM\n↓\nPhone"

    @property
    def status(self) -> str:
        """Status string for UI tables."""
        return "Anomalous" if self.anomalies else "Normal"

    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert session to summary dictionary for UI tables and logs."""
        proto_map = self.protocol_counts
        protocols = sorted({ev.protocol.value for ev in self.events})

        return {
            "session_id": self.session_id,
            "call_id": self.session_id,
            "architecture": self.architecture.value,
            "calling": self.calling_number or "Unknown",
            "calling_number": self.calling_number or "Unknown",
            "called": self.called_number or "Unknown",
            "called_number": self.called_number or "Unknown",
            "start": self.start_time_ist,
            "start_time_ist": self.start_time_ist,
            "end": self.end_time_ist,
            "end_time_ist": self.end_time_ist,
            "duration": self.duration_display,
            "duration_seconds": self.duration_seconds,
            "protocols": ", ".join(protocols),
            "trace_sources": ", ".join(self.trace_sources) if self.trace_sources else "N/A",
            "confidence_level": self.confidence_level,
            "isdn": proto_map.get("ISDN", 0),
            "mgcp": proto_map.get("MGCP", 0),
            "sip": proto_map.get("SIP", 0),
            "cucm": proto_map.get("CUCM", 0),
            "event_count": len(self.events),
            "confidence": f"{int(self.correlation_confidence * 100)}%",
            "anomalies": len(self.anomalies),
            "status": self.status,
            "ambiguities": len(self.ambiguity_notes),
        }
