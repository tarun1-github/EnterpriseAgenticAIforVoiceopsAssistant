"""Persistent repository for managing trace artifacts and metadata manifests."""

import gzip
import hashlib
import shutil
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone

from app.artifacts.models import TraceManifest
from app.artifacts.manifest import save_manifest_to_file, load_manifest_from_file
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("artifacts.repository")


class TraceArtifactRepository:
    """Manages the persistent VoiceOps trace workspace and inventory."""

    def __init__(self, storage_dir: Optional[Path] = None):
        if storage_dir is None:
            settings = get_settings()
            self._storage_dir = Path(settings.voiceops_trace_storage)
        else:
            self._storage_dir = Path(storage_dir)

        self._raw_dir = self._storage_dir / "raw"
        self._extracted_dir = self._storage_dir / "extracted"
        self._manifests_dir = self._storage_dir / "manifests"

        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Ensure all required storage directories exist."""
        self._raw_dir.mkdir(parents=True, exist_ok=True)
        self._extracted_dir.mkdir(parents=True, exist_ok=True)
        self._manifests_dir.mkdir(parents=True, exist_ok=True)

    @property
    def storage_dir(self) -> Path:
        return self._storage_dir

    @property
    def raw_dir(self) -> Path:
        return self._raw_dir

    @property
    def extracted_dir(self) -> Path:
        return self._extracted_dir

    @property
    def manifests_dir(self) -> Path:
        return self._manifests_dir

    def get_manifest_path(self, request_id: str) -> Path:
        """Get the manifest JSON path for a given request_id."""
        return self._manifests_dir / f"{request_id}.json"

    def save_manifest(self, manifest: TraceManifest) -> Path:
        """Save a TraceManifest to the manifests directory."""
        path = self.get_manifest_path(manifest.request_id)
        save_manifest_to_file(manifest, path)
        return path

    def load_manifest(self, request_id: str) -> Optional[TraceManifest]:
        """Load a TraceManifest by request_id."""
        path = self.get_manifest_path(request_id)
        return load_manifest_from_file(path)

    def list_manifests(self) -> List[TraceManifest]:
        """List all trace manifests in the repository sorted by collection timestamp descending."""
        manifests: List[TraceManifest] = []
        if not self._manifests_dir.exists():
            return manifests

        for p in self._manifests_dir.glob("*.json"):
            if p.name == "analysis_manifest.json":
                continue  # skip analysis manifest
            m = load_manifest_from_file(p)
            if m:
                manifests.append(m)

        # Sort newest first
        manifests.sort(key=lambda x: x.collection_timestamp, reverse=True)
        return manifests

    def delete_trace(self, request_id: str) -> bool:
        """Delete all artifacts (raw, extracted, manifest) associated with a request_id."""
        manifest = self.load_manifest(request_id)
        deleted = False

        if manifest:
            # Remove raw file/dir
            if manifest.raw_path:
                raw_p = Path(manifest.raw_path)
                if raw_p.exists():
                    try:
                        raw_p.unlink()
                        # Also remove parent request_id directory if empty
                        if raw_p.parent.exists() and not any(raw_p.parent.iterdir()):
                            raw_p.parent.rmdir()
                        deleted = True
                    except Exception as e:
                        logger.warning("Error deleting raw file %s: %s", raw_p, e)

            # Remove extracted file/dir
            if manifest.extracted_path:
                ext_p = Path(manifest.extracted_path)
                if ext_p.exists():
                    try:
                        ext_p.unlink()
                        # Also remove parent request_id directory if empty
                        if ext_p.parent.exists() and not any(ext_p.parent.iterdir()):
                            ext_p.parent.rmdir()
                        deleted = True
                    except Exception as e:
                        logger.warning("Error deleting extracted file %s: %s", ext_p, e)

        # Remove manifest file
        m_path = self.get_manifest_path(request_id)
        if m_path.exists():
            try:
                m_path.unlink()
                deleted = True
            except Exception as e:
                logger.warning("Error deleting manifest file %s: %s", m_path, e)

        return deleted

    def get_raw_bytes(self, manifest: TraceManifest) -> bytes:
        """Read raw trace artifact bytes."""
        p = Path(manifest.raw_path)
        if not p.is_absolute():
            p = self._storage_dir.parent / p
        return p.read_bytes()

    def get_extracted_text(self, manifest: TraceManifest) -> str:
        """Read extracted trace normalized text."""
        p = Path(manifest.extracted_path)
        if not p.is_absolute():
            p = self._storage_dir.parent / p
        return p.read_text(encoding="utf-8", errors="replace")

    def generate_trace_export_text(
        self,
        manifest: TraceManifest,
        download_timestamp: Optional[str] = None,
    ) -> str:
        """Generate a downloadable evidence package with metadata header without altering canonical artifact."""
        raw_trace = self.get_extracted_text(manifest)
        if not download_timestamp:
            download_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        node_ip = manifest.node.replace("_", ".")
        header = (
            "==================================================\n"
            "VoiceOps AI - CUCM Trace Evidence\n"
            "=================================\n\n"
            f"Device IP   : {node_ip}\n"
            f"Node        : {node_ip}\n"
            f"CUCM File   : {manifest.original_filename}\n"
            f"Normalized  : {manifest.normalized_filename}\n"
            f"CUCM Time   : {manifest.cucm_timestamp or 'N/A'}\n"
            f"Downloaded  : {download_timestamp}\n"
            f"SHA256      : {manifest.extracted_sha256}\n\n"
            "==================================================\n"
            "TRACE\n"
            "=====\n\n"
            f"{raw_trace}"
        )
        return header

    def process_and_store_artifact(
        self,
        request_id: str,
        node: str,
        filename: str,
        raw_bytes: bytes,
        cucm_timestamp: Optional[str] = None,
        trace_type: str = "SDL",
        transfer_method: str = "sftp_file_get",
    ) -> TraceManifest:
        """Store raw trace bytes, extract normalized text based on extension, and save manifest.

        Rules:
        .gzo -> preserve raw .gzo -> create normalized .txt -> DO NOT gunzip .gzo
        .gz  -> preserve raw .gz  -> gzip decompress -> normalized .txt
        .txt -> preserve raw .txt -> normalized .txt
        .index -> rejected
        """
        if filename.endswith(".index"):
            raise ValueError(f"Cannot store .index metadata file as trace artifact: {filename}")

        # Determine extensions and normalized filename
        original_extension = ""
        normalized_filename = filename
        if filename.endswith(".txt.gzo"):
            original_extension = ".gzo"
            normalized_filename = filename[:-4]  # removes .gzo -> ends in .txt
        elif filename.endswith(".gzo"):
            original_extension = ".gzo"
            normalized_filename = filename[:-4] + ".txt"
        elif filename.endswith(".txt.gz"):
            original_extension = ".gz"
            normalized_filename = filename[:-3]  # removes .gz -> ends in .txt
        elif filename.endswith(".gz"):
            original_extension = ".gz"
            normalized_filename = filename[:-3] + ".txt"
        elif filename.endswith(".txt"):
            original_extension = ".txt"
            normalized_filename = filename
        else:
            original_extension = Path(filename).suffix
            normalized_filename = f"{Path(filename).stem}.txt"

        # Directory layout:
        # raw/<node>/<request_id>/<filename>
        # extracted/<node>/<request_id>/<normalized_filename>
        safe_node = node.replace(".", "_").replace(":", "_")
        node_raw_dir = self._raw_dir / safe_node / request_id
        node_raw_dir.mkdir(parents=True, exist_ok=True)
        raw_file_path = node_raw_dir / filename

        node_ext_dir = self._extracted_dir / safe_node / request_id
        node_ext_dir.mkdir(parents=True, exist_ok=True)
        ext_file_path = node_ext_dir / normalized_filename

        # Write raw
        raw_file_path.write_bytes(raw_bytes)
        raw_size = len(raw_bytes)
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Extract normalized .txt
        if filename.endswith(".gz") and not filename.endswith(".gzo"):
            # Gzip decompress
            decompressed = gzip.decompress(raw_bytes)
            ext_file_path.write_bytes(decompressed)
            extraction_method = "gzip_decompress"
        elif filename.endswith(".gzo"):
            # Plain text copy (DO NOT gunzip .gzo)
            ext_file_path.write_bytes(raw_bytes)
            extraction_method = "plain_copy_no_gunzip"
        else:
            # Plain text copy
            ext_file_path.write_bytes(raw_bytes)
            extraction_method = "plain_copy"

        extracted_bytes = ext_file_path.read_bytes()
        extracted_size = len(extracted_bytes)
        extracted_sha256 = hashlib.sha256(extracted_bytes).hexdigest()

        manifest = TraceManifest(
            request_id=request_id,
            node=node,
            original_filename=filename,
            normalized_filename=normalized_filename,
            cucm_timestamp=cucm_timestamp,
            trace_type=trace_type,
            original_extension=original_extension,
            raw_path=str(raw_file_path.resolve()),
            extracted_path=str(ext_file_path.resolve()),
            raw_size=raw_size,
            extracted_size=extracted_size,
            raw_sha256=raw_sha256,
            extracted_sha256=extracted_sha256,
            collection_timestamp=datetime.now(timezone.utc).isoformat(),
            transfer_method=transfer_method,
            extraction_method=extraction_method,
            validation_status="Validated",
        )

        self.save_manifest(manifest)
        logger.info(
            "Persisted trace artifact: request_id=%s file=%s ext=%s raw_size=%d ext_size=%d",
            request_id, filename, normalized_filename, raw_size, extracted_size
        )
        return manifest
