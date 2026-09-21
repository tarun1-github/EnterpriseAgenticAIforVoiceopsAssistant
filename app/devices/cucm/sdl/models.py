"""Data models for CUCM SDL trace events and correlated calls."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from zoneinfo import ZoneInfo
from pydantic import BaseModel, Field

IST_TZ = ZoneInfo("Asia/Kolkata")


class SDLEvent(BaseModel):
    """Structured event extracted from a CUCM SDL trace record."""

    id: str = Field(default_factory=lambda: uuid4().hex, description="Globally unique SDL event ID")
    timestamp: datetime = Field(..., description="Timezone-aware datetime of event occurrence")
    node: Optional[str] = Field(default=None, description="CUCM node/hostname where trace was generated")
    process: Optional[str] = Field(default=None, description="CUCM process name (e.g. SIPHandler, Cdcc, StationInit)")
    signal: Optional[str] = Field(default=None, description="SDL Signal name or message type (e.g. CcSetupReq, MGCPNotify)")
    direction: Optional[str] = Field(default="INTERNAL", description="Signaling direction: INBOUND, OUTBOUND, INTERNAL, UNKNOWN")
    call_id: Optional[str] = Field(default=None, description="Call-ID (SIP or MGCP)")
    ci: Optional[str] = Field(default=None, description="CUCM Call Identification (CI)")
    cdcc: Optional[str] = Field(default=None, description="Call Deflection / Control Block identifier (CDCC)")
    calling_number: Optional[str] = Field(default=None, description="Calling party number (ANI)")
    called_number: Optional[str] = Field(default=None, description="Called party number (DNIS)")
    device: Optional[str] = Field(default=None, description="Associated device name (e.g. SEP..., VGR...)")
    ip_address: Optional[str] = Field(default=None, description="Remote or local IP address")
    protocol: Optional[str] = Field(default="CUCM", description="Signaling protocol: SIP, Q931, MGCP, SCCP, CUCM")
    raw_text: str = Field(..., description="Verbatim raw text line(s) from SDL trace")
    source_file: str = Field(..., description="Source trace filename or path")
    source_line: int = Field(..., description="1-based starting line number in source file")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Additional parsed metadata fields")

    @property
    def timestamp_ist(self) -> datetime:
        """Return event timestamp converted to Asia/Kolkata (IST)."""
        if self.timestamp.tzinfo is None:
            # Explicitly assume UTC if naive was encountered to prevent silent misinterpretation
            dt_utc = self.timestamp.replace(tzinfo=timezone.utc)
        else:
            dt_utc = self.timestamp.astimezone(timezone.utc)
        return dt_utc.astimezone(IST_TZ)

    @property
    def timestamp_ist_str(self) -> str:
        """Format timestamp in IST: DD-Mon-YYYY HH:MM:SS.mmm IST."""
        ist_dt = self.timestamp_ist
        return ist_dt.strftime("%d-%b-%Y %H:%M:%S.") + f"{ist_dt.microsecond // 1000:03d} IST"


class CallIdentifier(BaseModel):
    """Correlation identifier key-value pair."""

    key: str = Field(..., description="Identifier name, e.g. CI, CDCC, Call-ID, TCP_HANDLE")
    value: str = Field(..., description="Identifier value")


class Call(BaseModel):
    """Logical call session reconstructed from correlated SDL events."""

    id: str = Field(default_factory=lambda: uuid4().hex, description="Globally unique call ID")
    call_id: Optional[str] = Field(default=None, description="Primary SIP Call-ID if available")
    ci: Optional[str] = Field(default=None, description="Primary CUCM CI (Call Identification)")
    cdcc: Optional[str] = Field(default=None, description="Primary CDCC identifier")
    calling_number: Optional[str] = Field(default=None, description="Calling party number")
    called_number: Optional[str] = Field(default=None, description="Called party number")
    start_time: datetime = Field(..., description="Timezone-aware start timestamp of call")
    end_time: datetime = Field(..., description="Timezone-aware end timestamp of call")
    nodes: List[str] = Field(default_factory=list, description="CUCM nodes involved in this call")
    devices: List[str] = Field(default_factory=list, description="Devices involved (e.g. phones, gateways, trunks)")
    protocols: List[str] = Field(default_factory=list, description="Protocols observed (e.g. SIP, Q931, MGCP)")
    events: List[SDLEvent] = Field(default_factory=list, description="Chronologically ordered SDL events")
    correlation_reasons: List[str] = Field(default_factory=list, description="Explanations of how events were correlated")
    call_identifiers: List[CallIdentifier] = Field(default_factory=list, description="All identifiers linked to this call")

    @property
    def duration_seconds(self) -> float:
        """Call duration in seconds."""
        return max(0.0, (self.end_time - self.start_time).total_seconds())

    @property
    def event_count(self) -> int:
        """Total number of SDL events in this call session."""
        return len(self.events)

    @property
    def start_time_ist(self) -> datetime:
        """Return call start time converted to Asia/Kolkata (IST)."""
        if self.start_time.tzinfo is None:
            dt_utc = self.start_time.replace(tzinfo=timezone.utc)
        else:
            dt_utc = self.start_time.astimezone(timezone.utc)
        return dt_utc.astimezone(IST_TZ)

    @property
    def end_time_ist(self) -> datetime:
        """Return call end time converted to Asia/Kolkata (IST)."""
        if self.end_time.tzinfo is None:
            dt_utc = self.end_time.replace(tzinfo=timezone.utc)
        else:
            dt_utc = self.end_time.astimezone(timezone.utc)
        return dt_utc.astimezone(IST_TZ)

    @property
    def start_time_ist_str(self) -> str:
        """Formatted start time in Asia/Kolkata IST."""
        ist_dt = self.start_time_ist
        return ist_dt.strftime("%d-%b-%Y %H:%M:%S.") + f"{ist_dt.microsecond // 1000:03d} IST"

    @property
    def end_time_ist_str(self) -> str:
        """Formatted end time in Asia/Kolkata IST."""
        ist_dt = self.end_time_ist
        return ist_dt.strftime("%d-%b-%Y %H:%M:%S.") + f"{ist_dt.microsecond // 1000:03d} IST"
