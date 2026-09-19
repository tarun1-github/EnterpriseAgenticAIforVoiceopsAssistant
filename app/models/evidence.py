"""Structured EvidencePack model prepared for subsequent agent reasoning."""

import json
from typing import Any, Dict, List
from pydantic import BaseModel, Field
from app.models.anomaly import CallAnomaly
from app.models.call_session import CallArchitecture, CallSession


class EvidencePack(BaseModel):
    """Deterministic evidence container structured for evidence-driven troubleshooting."""

    call_session: CallSession = Field(..., description="Correlated call session")
    architecture: CallArchitecture = Field(..., description="Identified call architecture")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Ordered chronological signaling events")
    protocol_summaries: Dict[str, Any] = Field(default_factory=dict, description="Per-protocol message breakdown and counts")
    correlation_evidence: List[str] = Field(default_factory=list, description="Documented signals linking the call legs")
    anomalies: List[CallAnomaly] = Field(default_factory=list, description="Deterministic anomaly findings")
    missing_expected_messages: List[str] = Field(default_factory=list, description="Expected messages missing from call flow")
    important_identifiers: Dict[str, Any] = Field(default_factory=dict, description="Extracted Call-IDs, refs, endpoints, IPs")

    def to_json(self, indent: int = 2) -> str:
        """Serialize evidence pack to clean JSON string."""
        return json.dumps(self.model_dump(mode="json"), indent=indent)
