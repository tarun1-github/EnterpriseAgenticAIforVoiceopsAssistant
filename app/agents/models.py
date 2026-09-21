"""Data models for SDL Analyst Agent findings and RCA reports."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RCAResult(BaseModel):
    """Structured, reproducible evidence-based Root Cause Analysis result."""

    call_id: str
    calling_number: str
    called_number: str
    timestamp_ist: str
    timezone: str = "Asia/Kolkata"
    nodes: List[str] = Field(default_factory=list)
    call_flow: List[str] = Field(default_factory=list)
    observations: List[str] = Field(default_factory=list)
    failure_point: Optional[str] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    possible_failure_domains: List[str] = Field(default_factory=list)
    root_cause: str
    additional_evidence_required: List[str] = Field(default_factory=list)
    recommended_checks: List[str] = Field(default_factory=list)
    confidence: str = Field(..., description="High, Medium, or Low")
    confidence_explanation: str
    analysis_timestamp: str
    knowledge_version: str = "1.0.0"
    parser_version: str = "1.0.0"
    agent_version: str = "1.0.0"
    formatted_report: str = ""
