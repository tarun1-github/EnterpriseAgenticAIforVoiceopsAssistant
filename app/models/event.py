"""Common Event Model (VoiceEvent) for multi-protocol call correlation."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4
from pydantic import BaseModel, Field, model_validator
from app.core.timestamps import parse_cisco_timestamp, ensure_utc


class ProtocolEnum(str, Enum):
    """Supported signaling and trace protocols."""

    ISDN = "ISDN"
    SIP = "SIP"
    MGCP = "MGCP"
    CUCM = "CUCM"
    UNKNOWN = "UNKNOWN"


class DirectionEnum(str, Enum):
    """Signaling message direction."""

    INBOUND = "RX"
    OUTBOUND = "TX"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class VoiceEvent(BaseModel):
    """Normalized, protocol-agnostic event model representing a single signaling unit."""

    id: str = Field(default_factory=lambda: uuid4().hex, description="Globally unique event ID")
    timestamp: Optional[datetime] = Field(default=None, description="Normalized datetime if date is available")
    timestamp_raw: Optional[str] = Field(default=None, description="Original verbatim timestamp string")
    protocol: ProtocolEnum = Field(default=ProtocolEnum.UNKNOWN, description="Signaling protocol")
    direction: DirectionEnum = Field(default=DirectionEnum.UNKNOWN, description="RX / TX / INTERNAL / UNKNOWN")
    source: Optional[str] = Field(default=None, description="Source trace file, node, or device")
    interface: Optional[str] = Field(default=None, description="Signaling interface (e.g. Se0/2/0:23)")
    message_type: str = Field(..., description="Message name/verb (e.g. SETUP, INVITE, 200 OK, CRCX)")

    # Correlation Identifiers
    call_reference: Optional[str] = Field(default=None, description="ISDN Q.931 call reference (e.g. 0x0082)")
    transaction_id: Optional[str] = Field(default=None, description="MGCP transaction ID or SIP CSeq number")
    call_id: Optional[str] = Field(default=None, description="SIP Call-ID or MGCP Call Identifier")

    # Addressing
    calling_number: Optional[str] = Field(default=None, description="Calling party number (ANI)")
    called_number: Optional[str] = Field(default=None, description="Called party number (DNIS)")

    # Network Transport
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    source_port: Optional[int] = Field(default=None, description="Source UDP/TCP port")
    destination_port: Optional[int] = Field(default=None, description="Destination UDP/TCP port")

    # Hardware & Call Processing Entities
    endpoint: Optional[str] = Field(default=None, description="MGCP endpoint or device name")
    device: Optional[str] = Field(default=None, description="CUCM device name or gateway name")

    # Classification & Provenance
    trace_type: Optional[str] = Field(default=None, description="CUCM_SDL, ISDN_Q931, SIP, MGCP, CCAPI")
    device_type: Optional[str] = Field(default=None, description="CUCM, VOICE_GATEWAY, CUBE, IOS_ROUTER, SIP_ENDPOINT")
    device_name: Optional[str] = Field(default=None, description="Device hostname or prompt")
    device_ip: Optional[str] = Field(default=None, description="Device IP address")
    destination: Optional[str] = Field(default=None, description="Destination device, host, or endpoint")
    correlation_ids: Dict[str, Any] = Field(default_factory=dict, description="Extracted correlation key-values")
    trace_id: Optional[str] = Field(default=None, description="Parent trace artifact identifier")
    timestamp_timezone: Optional[str] = Field(default=None, description="Original timestamp timezone string")

    # Status & Disposition
    cause_code: Optional[str] = Field(default=None, description="ISDN Q.850 cause code or SIP response reason")

    # Trace Text and Extensibility
    raw: str = Field(..., description="Exact raw log block for this event")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extensible protocol-specific metadata")

    @property
    def event_id(self) -> str:
        return self.id

    @property
    def timestamp_original(self) -> Optional[str]:
        return self.timestamp_raw

    @property
    def raw_text(self) -> str:
        return self.raw

    @property
    def parsed_fields(self) -> Dict[str, Any]:
        return self.metadata

    @property
    def timestamp_utc(self) -> Optional[datetime]:
        """Canonical UTC datetime."""
        from datetime import timezone
        if self.timestamp is None:
            return None
        if self.timestamp.tzinfo is None:
            return self.timestamp.replace(tzinfo=timezone.utc)
        return self.timestamp.astimezone(timezone.utc)

    @property
    def timestamp_ist(self) -> Optional[datetime]:
        """Canonical Asia/Kolkata (IST) datetime."""
        from app.core.timestamps import IST_TZ
        utc_dt = self.timestamp_utc
        if utc_dt is None:
            return None
        return utc_dt.astimezone(IST_TZ)

    @property
    def timestamp_ist_str(self) -> str:
        """Formatted string in Asia/Kolkata IST."""
        ist_dt = self.timestamp_ist
        if ist_dt is None:
            return self.timestamp_raw or "N/A"
        return ist_dt.strftime("%d-%b-%Y %H:%M:%S.") + f"{ist_dt.microsecond // 1000:03d} IST"


    @model_validator(mode="before")
    @classmethod
    def normalize_timestamps(cls, data: Any) -> Any:
        """Handle string or datetime timestamps gracefully before Pydantic validation."""
        if isinstance(data, dict):
            raw_ts = data.get("timestamp_raw") or data.get("timestamp")
            if isinstance(data.get("timestamp"), str):
                dt, clean_str = parse_cisco_timestamp(data["timestamp"])
                data["timestamp"] = ensure_utc(dt) if dt else None
                if not data.get("timestamp_raw"):
                    data["timestamp_raw"] = clean_str
            elif isinstance(data.get("timestamp"), datetime):
                data["timestamp"] = ensure_utc(data["timestamp"])
                if not data.get("timestamp_raw"):
                    data["timestamp_raw"] = data["timestamp"].isoformat()
            elif raw_ts and isinstance(raw_ts, str):
                dt, clean_str = parse_cisco_timestamp(raw_ts)
                data["timestamp"] = ensure_utc(dt) if dt else None
                if not data.get("timestamp_raw"):
                    data["timestamp_raw"] = clean_str
        return data

    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert event to a concise flat dictionary suitable for UI tables and logs."""
        formatted_ts = "N/A"
        if self.timestamp:
            formatted_ts = self.timestamp.strftime("%b %d %H:%M:%S.%f")[:-3]
        elif self.timestamp_raw:
            formatted_ts = self.timestamp_raw

        return {
            "id": self.id[:8],
            "timestamp": formatted_ts,
            "protocol": self.protocol.value,
            "direction": self.direction.value,
            "message": self.message_type,
            "calling": self.calling_number or "-",
            "called": self.called_number or "-",
            "call_ref": self.call_reference or "-",
            "call_id": self.call_id or "-",
            "cause": self.cause_code or "-",
        }
