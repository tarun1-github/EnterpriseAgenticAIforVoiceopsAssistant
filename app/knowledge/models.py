"""Data models for structured CUCM domain knowledge items."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class KnowledgeItem(BaseModel):
    """Normalized domain knowledge item covering signals, processes, patterns, or failure signatures."""

    id: str = Field(..., description="Unique knowledge item identifier")
    category: str = Field(..., description="Category: signal, process, identifier, trace_type, callflow, failure")
    title: str = Field(..., description="Human-readable title or signal name")
    description: str = Field(..., description="Technical explanation or definition")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured attributes (e.g. causes, steps)")
    confidence: str = Field(default="high", description="Documentation confidence: high, medium, low")
    source_reference: Optional[str] = Field(default=None, description="Cisco doc reference or RFC citation")
    tags: List[str] = Field(default_factory=list, description="Searchable keyword tags")
