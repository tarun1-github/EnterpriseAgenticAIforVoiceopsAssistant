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

    # Correlation Diagnostics
    correlation_confidence: float = Field(default=1.0, description="Overall correlation confidence score (0.0 - 1.0)")
    correlation_evidence: List[str] = Field(default_factory=list, description="Human-readable justification of signals matched")

    # Anomaly findings
    anomalies: List[CallAnomaly] = Field(default_factory=list, description="Deterministic signaling anomalies identified")

    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert session to summary dictionary for UI tables and logs."""
        fmt_start = self.start_time.strftime("%H:%M:%S.%f")[:-3] if self.start_time else "N/A"
        fmt_end = self.end_time.strftime("%H:%M:%S.%f")[:-3] if self.end_time else "N/A"

        protocols = sorted({ev.protocol.value for ev in self.events})

        return {
            "session_id": self.session_id,
            "architecture": self.architecture.value,
            "calling": self.calling_number or "-",
            "called": self.called_number or "-",
            "start": fmt_start,
            "end": fmt_end,
            "protocols": ", ".join(protocols),
            "event_count": len(self.events),
            "confidence": f"{int(self.correlation_confidence * 100)}%",
            "anomalies": len(self.anomalies),
        }
