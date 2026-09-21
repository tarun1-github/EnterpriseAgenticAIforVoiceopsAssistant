"""Call anomaly model for deterministic signaling failure detection."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field
from app.models.event import ProtocolEnum


class AnomalyCategory(str, Enum):
    """Categories of signaling anomalies."""

    MISSING_MESSAGE = "MISSING_MESSAGE"
    UNEXPECTED_MESSAGE = "UNEXPECTED_MESSAGE"
    SEQUENCE_ERROR = "SEQUENCE_ERROR"
    RESPONSE_TIMEOUT = "RESPONSE_TIMEOUT"
    CAUSE_CODE = "CAUSE_CODE"
    CORRELATION_GAP = "CORRELATION_GAP"
    PROTOCOL_MISMATCH = "PROTOCOL_MISMATCH"


class AnomalySeverity(str, Enum):
    """Severity levels for detected signaling anomalies."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class CallAnomaly(BaseModel):
    """Structured anomaly finding for deterministic signaling failure detection."""

    anomaly_id: str = Field(default_factory=lambda: f"anom_{uuid4().hex[:8]}", description="Unique anomaly ID")
    call_id: Optional[str] = Field(default=None, description="Associated call identifier")
    category: AnomalyCategory = Field(..., description="Anomaly classification")
    protocol: ProtocolEnum = Field(..., description="Protocol domain where anomaly occurred")
    severity: AnomalySeverity = Field(default=AnomalySeverity.WARNING, description="Severity of finding")
    description: str = Field(..., description="Deterministic factual description of the anomaly")
    timestamp: Optional[datetime] = Field(default=None, description="Timestamp where anomaly was isolated")
    evidence_refs: List[str] = Field(default_factory=list, description="References or IDs of supporting evidence")
    related_event_ids: List[str] = Field(default_factory=list, description="IDs of VoiceEvents supporting this finding")
    evidence_event_ids: List[str] = Field(default_factory=list, description="Backwards-compatible alias for related_event_ids")
    expected_message: Optional[str] = Field(default=None, description="Expected signaling message (e.g. 200 OK, CONNECT)")
    observed_messages: List[str] = Field(default_factory=list, description="Actually observed messages leading up to anomaly")
    confidence: float = Field(default=1.0, description="Confidence of the anomaly rule evaluation (0.0 - 1.0)")

    def __init__(self, **data):
        super().__init__(**data)
        if self.evidence_event_ids and not self.related_event_ids:
            self.related_event_ids = list(self.evidence_event_ids)
        elif self.related_event_ids and not self.evidence_event_ids:
            self.evidence_event_ids = list(self.related_event_ids)
        if not self.evidence_refs and self.related_event_ids:
            self.evidence_refs = list(self.related_event_ids)

    @property
    def evidence(self) -> List[str]:
        """Backwards-compatible evidence accessor returning evidence_refs or [description]."""
        return self.evidence_refs if self.evidence_refs else [self.description]
