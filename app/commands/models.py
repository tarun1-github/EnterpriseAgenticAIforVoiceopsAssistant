"""Data models for Device Command Center operations."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4
from pydantic import BaseModel, Field


class DeviceTypeEnum(str, Enum):
    """Supported target device types."""

    CUCM = "CUCM"
    IOS = "IOS"


class CommandRequest(BaseModel):
    """Request to execute a command on a voice device."""

    device_type: DeviceTypeEnum
    host: str
    command: str
    timeout: int = 30


class CommandResponse(BaseModel):
    """Result of command execution on a voice device."""

    command: str
    device_type: DeviceTypeEnum
    host: str
    output: str
    execution_time_seconds: float
    success: bool
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    prompt: Optional[str] = None


class CommandHistoryEntry(BaseModel):
    """Historical ledger record of a device command execution."""

    entry_id: str = Field(default_factory=lambda: f"cmd_{uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%H:%M:%S"))
    device_type: str
    host: str
    command: str
    output: str
    execution_time_seconds: float
    status: str  # SUCCESS, FAILED, BLOCKED
    error: Optional[str] = None
