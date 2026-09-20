"""Artifact models representing trace manifests and metadata."""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any


@dataclass
class TraceManifest:
    """Persistent metadata manifest for a collected trace file."""

    request_id: str
    node: str
    original_filename: str
    normalized_filename: str
    cucm_timestamp: Optional[str] = None
    trace_type: str = "SDL"
    original_extension: str = ".gzo"
    raw_path: str = ""
    extracted_path: str = ""
    raw_size: int = 0
    extracted_size: int = 0
    raw_sha256: Optional[str] = None
    extracted_sha256: Optional[str] = None
    collection_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    transfer_method: str = "sftp_file_get"
    extraction_method: str = "normalized_text"
    validation_status: str = "Validated"

    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceManifest":
        """Reconstitute manifest from dictionary."""
        return cls(
            request_id=data.get("request_id", ""),
            node=data.get("node", "unknown"),
            original_filename=data.get("original_filename", ""),
            normalized_filename=data.get("normalized_filename", ""),
            cucm_timestamp=data.get("cucm_timestamp"),
            trace_type=data.get("trace_type", "SDL"),
            original_extension=data.get("original_extension", ""),
            raw_path=data.get("raw_path", ""),
            extracted_path=data.get("extracted_path", ""),
            raw_size=int(data.get("raw_size", 0)),
            extracted_size=int(data.get("extracted_size", 0)),
            raw_sha256=data.get("raw_sha256"),
            extracted_sha256=data.get("extracted_sha256"),
            collection_timestamp=data.get("collection_timestamp", ""),
            transfer_method=data.get("transfer_method", "sftp_file_get"),
            extraction_method=data.get("extraction_method", "normalized_text"),
            validation_status=data.get("validation_status", "Validated"),
        )
