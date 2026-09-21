"""Metadata model representing an ingested or collected Cisco voice trace artifact."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


class TraceArtifact(BaseModel):
    """Normalized metadata describing an ingested trace artifact file."""

    trace_id: str = Field(default_factory=lambda: f"trace_{uuid4().hex[:8]}", description="Unique trace ID")
    filename: str = Field(..., description="Canonical stored filename")
    original_filename: str = Field(..., description="Original upload filename")
    trace_type: str = Field("UNKNOWN", description="CUCM_SDL, ISDN_Q931, SIP, MGCP, CCAPI, MIXED, UNKNOWN")
    device_type: str = Field("UNKNOWN", description="CUCM, VOICE_GATEWAY, CUBE, IOS_ROUTER, SIP_ENDPOINT, OTHER")
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    protocol: Optional[str] = None
    timezone: str = "Asia/Kolkata"
    earliest_timestamp: Optional[datetime] = None
    latest_timestamp: Optional[datetime] = None
    file_size: int = 0
    sha256: Optional[str] = None
    classification_confidence: float = 0.0
    classification_evidence: List[str] = Field(default_factory=list)
    source: str = "upload"

    def to_inventory_dict(self) -> Dict[str, Any]:
        """Summary dict formatted for Trace Inventory UI display."""
        return {
            "File": self.original_filename or self.filename,
            "Detected Type": self.trace_type,
            "Device": self.device_type,
            "IP": self.device_ip or "-",
            "Confidence": f"{int(self.classification_confidence * 100)}%",
            "Status": "Parsed & Correlated",
        }
