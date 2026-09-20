"""Manifest serializer and validator for persistent trace metadata."""

import json
from pathlib import Path
from typing import Optional
from app.artifacts.models import TraceManifest
from app.core.logging import get_logger

logger = get_logger("artifacts.manifest")


def save_manifest_to_file(manifest: TraceManifest, filepath: Path) -> None:
    """Save a TraceManifest to a JSON file atomically.

    Args:
        manifest: TraceManifest instance.
        filepath: Destination Path.
    """
    filepath.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = filepath.with_suffix(".tmp")
    data = manifest.to_dict()
    tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp_path.replace(filepath)
    logger.debug("Saved trace manifest: %s", filepath)


def load_manifest_from_file(filepath: Path) -> Optional[TraceManifest]:
    """Load a TraceManifest from a JSON file.

    Args:
        filepath: Path to manifest JSON.

    Returns:
        TraceManifest if successfully parsed, None otherwise.
    """
    if not filepath.exists() or not filepath.is_file():
        return None
    try:
        content = filepath.read_text(encoding="utf-8")
        data = json.loads(content)
        return TraceManifest.from_dict(data)
    except Exception as e:
        logger.error("Failed to parse manifest %s: %s", filepath, e)
        return None
