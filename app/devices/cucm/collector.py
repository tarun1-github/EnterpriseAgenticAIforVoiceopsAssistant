"""CUCM SDL trace file collector with SFTP-based file-get workflow."""

import hashlib
import gzip
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from app.core.logging import get_logger
from app.core.config import get_settings
from app.devices.cucm.client import CUCMClient
from app.devices.cucm.models import CUCMTraceFile
from app.devices.cucm.selection import (
    TraceSelectionService,
    SelectionMode,
    RelativeTimeOption,
    SelectionRequest,
    SelectionResult,
    create_selection_request,
)
from app.devices.cucm.exceptions import CUCMTraceCollectionError, CUCMConnectionError
from app.devices.cucm.transport import CUCMTransport

logger = get_logger("devices.cucm.collector")


@dataclass
class CollectionResult:
    """Result of trace file collection."""

    filename: str
    local_path: Optional[Path] = None
    size_bytes: int = 0
    success: bool = False
    error: Optional[str] = None
    method: str = "unknown"
    raw_path: Optional[Path] = None
    extracted_path: Optional[Path] = None
    remote_size_bytes: int = 0
    raw_size_bytes: int = 0
    extracted_size_bytes: int = 0
    raw_sha256: Optional[str] = None
    extracted_sha256: Optional[str] = None
    transfer_success: bool = False
    extraction_success: bool = False


@dataclass
class CollectorConfig:
    """Configuration for trace collection."""

    local_storage: Optional[Path] = None
    sftp_host: Optional[str] = None
    sftp_port: int = 22
    sftp_username: Optional[str] = None
    sftp_password: Optional[str] = None
    sftp_remote_base_dir: str = "/tmp/voiceops_mount/voiceops_sftp/cucm"


class CUCMTraceCollector:
    """Collects SDL trace files from CUCM using SFTP-based file-get workflow.

    All trace files (.gz, .gzo, .txt) use the CUCM 'file get' -> SFTP -> local
    workflow. The 'file view' method is retained only for diagnostic purposes.

    Time-based selection:
    - Latest: newest trace file
    - Relative: last N minutes/hours
    - Custom: specific start/end datetime
    """

    def __init__(
        self,
        client: Optional[CUCMClient] = None,
        config: Optional[CollectorConfig] = None,
    ):
        self._client = client or CUCMClient()
        self._config = config or CollectorConfig()

        # Load SFTP settings from central config if not provided
        if self._config.sftp_host is None:
            settings = get_settings()
            self._config.sftp_host = settings.sftp_host
            self._config.sftp_port = settings.sftp_port
            self._config.sftp_username = settings.sftp_username
            self._config.sftp_password = (
                settings.sftp_password.get_secret_value() if settings.sftp_password else None
            )
            self._config.sftp_remote_base_dir = settings.sftp_remote_base_dir

        self._local_storage = (
            self._config.local_storage
            or Path(tempfile.gettempdir()) / "voiceops_traces"
        )
        self._local_storage.mkdir(parents=True, exist_ok=True)
        self._selection_service = TraceSelectionService()

    def find_traces(
        self,
        mode: str = "latest",
        relative: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> SelectionResult:
        """Discover and select trace files matching time criteria.

        This performs discovery and candidate selection ONLY - no files are downloaded.

        Args:
            mode: "latest", "relative", or "custom"
            relative: For relative mode, one of:
                "5 minutes", "10 minutes", "15 minutes", "30 minutes",
                "1 hour", "2 hours", "4 hours", "8 hours", "12 hours", "24 hours"
            start: For custom mode, ISO format start datetime (e.g., "2026-09-19T11:00:00")
            end: For custom mode, ISO format end datetime (e.g., "2026-09-19T11:15:00")
            remote_path: CUCM directory to search.

        Returns:
            SelectionResult with candidate files and metadata.

        Raises:
            CUCMConnectionError: If not connected.
            ValueError: If parameters are invalid.
        """
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        request = create_selection_request(mode, relative, start, end)

        # Discover all SDL files
        all_files = self._client.list_sdl_files(remote_path)
        logger.info("Discovered %d total SDL files", len(all_files))

        # Select candidates based on time criteria
        result = self._selection_service.select_traces(all_files, request)

        logger.info(
            "Time-based selection: mode=%s, window=%s to %s, candidates=%d, est_size=%.2f MB",
            mode, result.start_time, result.end_time,
            result.total_candidates, result.estimated_size_bytes / (1024 * 1024)
        )

        return result

    def collect_selected_traces(
        self,
        selection: SelectionResult,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
        progress_callback: Optional[Callable[[CollectionResult], None]] = None,
    ) -> List[CollectionResult]:
        """Download the previously selected trace files via SFTP.

        Args:
            selection: SelectionResult from find_traces().
            remote_path: CUCM directory.
            progress_callback: Optional callback for progress updates.

        Returns:
            List of CollectionResult for each downloaded file.
        """
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        # Filter to trace payloads only (exclude .index)
        trace_files = [f for f in selection.candidate_files if f.trace_type == "SDL_TRACE"]
        if not trace_files:
            logger.warning("No trace payload files in selection")
            return []

        logger.info("Starting SFTP collection for %d trace files", len(trace_files))
        results = []

        for trace_file in trace_files:
            result = self.collect_file(trace_file.filename, remote_path)
            results.append(result)
            if progress_callback:
                progress_callback(result)

        return results

    def _validate_sftp_config(self) -> None:
        """Validate SFTP configuration is present."""
        if not self._config.sftp_host:
            raise CUCMTraceCollectionError(
                "SFTP host not configured (set SFTP_HOST in .env)",
                filename="",
                stage="config",
            )
        if not self._config.sftp_username:
            raise CUCMTraceCollectionError(
                "SFTP username not configured (set SFTP_USERNAME in .env)",
                filename="",
                stage="config",
            )
        if not self._config.sftp_password:
            raise CUCMTraceCollectionError(
                "SFTP password not configured (set SFTP_PASSWORD in .env)",
                filename="",
                stage="config",
            )

    def _get_node_name(self) -> str:
        """Get safe node name from CUCM host."""
        settings = get_settings()
        host = settings.cucm_host or "unknown"
        # Sanitize for filesystem
        return host.replace(".", "_").replace(":", "_")

    def _create_remote_sftp_dir(self, request_id: str) -> str:
        """Create unique remote SFTP directory for this collection request.

        Args:
            request_id: Unique identifier for this collection.

        Returns:
            Full remote directory path.
        """
        import paramiko

        node = self._get_node_name()
        remote_dir = f"{self._config.sftp_remote_base_dir}/{node}/{request_id}"

        # Connect via SFTP and create directory
        transport = paramiko.Transport((self._config.sftp_host, self._config.sftp_port))
        transport.connect(username=self._config.sftp_username, password=self._config.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        try:
            # Create directory recursively
            parts = remote_dir.strip("/").split("/")
            current = ""
            for part in parts:
                current = f"{current}/{part}" if current else f"/{part}"
                try:
                    sftp.stat(current)
                except FileNotFoundError:
                    sftp.mkdir(current)
                    logger.debug("Created remote SFTP dir: %s", current)

            logger.info("Created remote SFTP directory: %s", remote_dir)
        finally:
            sftp.close()
            transport.close()

        return remote_dir

    def _verify_remote_file(self, remote_dir: str, filename: str) -> tuple[int, str]:
        """Verify file exists on SFTP server and get its size and SHA-256.

        Args:
            remote_dir: Remote directory path.
            filename: Expected filename.

        Returns:
            Tuple of (size_bytes, sha256_hash).

        Raises:
            CUCMTraceCollectionError: If file not found or verification fails.
        """
        import paramiko

        remote_path = f"{remote_dir}/{filename}"

        transport = paramiko.Transport((self._config.sftp_host, self._config.sftp_port))
        transport.connect(username=self._config.sftp_username, password=self._config.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        try:
            try:
                stat = sftp.stat(remote_path)
                size = stat.st_size
            except FileNotFoundError:
                raise CUCMTraceCollectionError(
                    f"File not found on SFTP server: {remote_path}",
                    filename=filename,
                    stage="verification",
                )

            # Calculate SHA-256
            sha256 = hashlib.sha256()
            with sftp.open(remote_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)

            logger.info("SFTP artifact verified: filename=%s remote_size=%d", filename, size)
            return size, sha256.hexdigest()

        finally:
            sftp.close()
            transport.close()

    def _download_from_sftp(self, remote_dir: str, filename: str, local_path: Path) -> int:
        """Download file from SFTP server to local path.

        Args:
            remote_dir: Remote directory path.
            filename: Filename to download.
            local_path: Local destination path.

        Returns:
            Number of bytes downloaded.
        """
        import paramiko

        remote_path = f"{remote_dir}/{filename}"

        transport = paramiko.Transport((self._config.sftp_host, self._config.sftp_port))
        transport.connect(username=self._config.sftp_username, password=self._config.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote_path, str(local_path))
            size = local_path.stat().st_size
            logger.info("Downloaded from SFTP: filename=%s local_size=%d", filename, size)
            return size
        finally:
            sftp.close()
            transport.close()

    def _cleanup_remote(self, remote_dir: str, filename: str) -> None:
        """Remove temporary file from SFTP server after successful local verification.

        Args:
            remote_dir: Remote directory path.
            filename: Filename to remove.
        """
        import paramiko

        remote_path = f"{remote_dir}/{filename}"

        transport = paramiko.Transport((self._config.sftp_host, self._config.sftp_port))
        transport.connect(username=self._config.sftp_username, password=self._config.sftp_password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        try:
            sftp.remove(remote_path)
            logger.debug("Removed temporary SFTP file: %s", remote_path)

            # Try to remove directory if empty
            try:
                sftp.rmdir(remote_dir)
            except OSError:
                pass  # Directory not empty or doesn't exist
        except Exception as e:
            logger.warning("Failed to cleanup SFTP file %s: %s", remote_path, e)
        finally:
            sftp.close()
            transport.close()

    def _extract_file(self, raw_path: Path, filename: str) -> tuple[Path, int, str]:
        """Extract/process file based on extension.

        Args:
            raw_path: Path to raw downloaded file.
            filename: Original filename (for extension detection).

        Returns:
            Tuple of (extracted_path, extracted_size, extracted_sha256).
        """
        extracted_dir = self._local_storage / "extracted" / self._get_node_name()
        extracted_dir.mkdir(parents=True, exist_ok=True)
        extracted_path = extracted_dir / filename.replace(".gz", "").replace(".gzo", ".txt")

        if filename.endswith(".gz"):
            # Gzip decompress
            logger.debug("Decompressing .gz file: %s", filename)
            with gzip.open(raw_path, "rb") as f_in:
                content = f_in.read()
            extracted_path.write_bytes(content)

        elif filename.endswith(".gzo"):
            # .gzo is plain text, just copy
            logger.debug("Copying .gzo as plain text: %s", filename)
            content = raw_path.read_bytes()
            extracted_path.write_bytes(content)

        elif filename.endswith(".txt"):
            # Plain text, just copy
            logger.debug("Copying .txt file: %s", filename)
            content = raw_path.read_bytes()
            extracted_path.write_bytes(content)

        else:
            raise CUCMTraceCollectionError(
                f"Unknown file extension for extraction: {filename}",
                filename=filename,
                stage="extraction",
            )

        extracted_size = extracted_path.stat().st_size
        sha256 = hashlib.sha256(extracted_path.read_bytes()).hexdigest()
        logger.info("SDL evidence extracted: filename=%s extracted_path=%s", filename, extracted_path)
        return extracted_path, extracted_size, sha256

    def collect_file(
        self,
        filename: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> CollectionResult:
        """Collect a single SDL trace file via SFTP file-get workflow.

        Args:
            filename: Name of the trace file.
            remote_path: Remote directory on CUCM.

        Returns:
            CollectionResult with all metadata.
        """
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        # Validate filename
        try:
            local_raw_path = self._validate_filename(filename)
        except CUCMTraceCollectionError as e:
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=str(e),
                method="validation",
            )

        # Reject .index files
        if filename.endswith(".index"):
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error="Cannot collect .index metadata files",
                method="validation",
            )

        # Validate SFTP config
        try:
            self._validate_sftp_config()
        except CUCMTraceCollectionError as e:
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=str(e),
                method="config",
            )

        request_id = uuid.uuid4().hex[:8]
        node = self._get_node_name()

        # Set up local paths
        raw_dir = self._local_storage / "raw" / node
        raw_dir.mkdir(parents=True, exist_ok=True)
        local_raw_path = raw_dir / filename

        extracted_dir = self._local_storage / "extracted" / node
        extracted_dir.mkdir(parents=True, exist_ok=True)
        local_extracted_path = extracted_dir / filename.replace(".gz", "").replace(".gzo", ".txt")

        logger.info("Starting CUCM SFTP collection: filename=%s node=%s", filename, node)

        try:
            # Step 1: Create unique remote SFTP directory
            remote_dir = self._create_remote_sftp_dir(request_id)

            # Step 2: Execute CUCM file-get to push to SFTP
            self._client.execute_file_get(
                filename=filename,
                sftp_host=self._config.sftp_host,
                sftp_username=self._config.sftp_username,
                sftp_password=self._config.sftp_password,
                sftp_remote_dir=remote_dir,
                remote_path=remote_path,
            )

            # Step 3: Verify file on SFTP server
            remote_size, raw_sha256 = self._verify_remote_file(remote_dir, filename)

            # Step 4: Download from SFTP to local raw storage
            raw_size = self._download_from_sftp(remote_dir, filename, local_raw_path)

            # Verify local size matches remote
            if raw_size != remote_size:
                logger.warning("Size mismatch: local=%d remote=%d", raw_size, remote_size)

            # Step 5: Extract/process file
            extracted_path, extracted_size, extracted_sha256 = self._extract_file(local_raw_path, filename)

            # Step 6: Cleanup remote (optional, after verification)
            self._cleanup_remote(remote_dir, filename)

            result = CollectionResult(
                filename=filename,
                local_path=extracted_path,  # For backward compatibility
                size_bytes=extracted_size,  # For backward compatibility
                success=True,
                error=None,
                method="sftp_file_get",
                raw_path=local_raw_path,
                extracted_path=extracted_path,
                remote_size_bytes=remote_size,
                raw_size_bytes=raw_size,
                extracted_size_bytes=extracted_size,
                raw_sha256=raw_sha256,
                extracted_sha256=extracted_sha256,
                transfer_success=True,
                extraction_success=True,
            )

            logger.info("CUCM SFTP collection successful: filename=%s", filename)
            return result

        except CUCMTraceCollectionError as e:
            logger.error("CUCM SFTP collection failed: filename=%s reason=%s", filename, e)
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=str(e),
                method="sftp_file_get",
                transfer_success=False,
                extraction_success=False,
            )
        except Exception as e:
            logger.error("CUCM SFTP collection failed: filename=%s error=%s", filename, e)
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=f"Collection failed: {e}",
                method="sftp_file_get",
                transfer_success=False,
                extraction_success=False,
            )

    def _validate_filename(self, filename: str) -> Path:
        """Validate filename and return safe local path.

        Prevents path traversal attacks by ensuring the resolved path
        stays within the local storage directory.

        Args:
            filename: The filename to validate.

        Returns:
            Safe local Path within storage directory.

        Raises:
            CUCMTraceCollectionError: If filename is unsafe.
        """
        # Reject empty or None filenames
        if not filename or not filename.strip():
            raise CUCMTraceCollectionError(
                "Filename cannot be empty",
                filename=filename,
                stage="validation",
            )

        # Reject absolute paths (Windows and Unix-style)
        if Path(filename).is_absolute() or filename.startswith("/"):
            raise CUCMTraceCollectionError(
                "Absolute paths are not allowed",
                filename=filename,
                stage="validation",
            )

        # Reject path traversal attempts (..)
        if ".." in filename:
            raise CUCMTraceCollectionError(
                "Path traversal detected in filename",
                filename=filename,
                stage="validation",
            )

        # Resolve the local path and ensure it's within storage directory
        local_path = (self._local_storage / filename).resolve()
        storage_resolved = self._local_storage.resolve()

        try:
            local_path.relative_to(storage_resolved)
        except ValueError:
            raise CUCMTraceCollectionError(
                "Filename resolves outside storage directory",
                filename=filename,
                stage="validation",
            )

        return local_path

    def collect_multiple(
        self,
        filenames: List[str],
        remote_path: str = "activelog /cm/trace/ccm/sdl",
        progress_callback: Optional[Callable[[CollectionResult], None]] = None,
    ) -> List[CollectionResult]:
        """Collect multiple SDL trace files."""
        results = []
        for filename in filenames:
            result = self.collect_file(filename, remote_path)
            results.append(result)
            if progress_callback:
                progress_callback(result)
        return results

    def collect_all_sdl(
        self,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
        max_files: Optional[int] = None,
        progress_callback: Optional[Callable[[CollectionResult], None]] = None,
    ) -> List[CollectionResult]:
        """Discover and collect all SDL trace files."""
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        files = self._client.list_sdl_files(remote_path)
        if max_files:
            files = files[:max_files]

        filenames = [f.filename for f in files if f.trace_type == "SDL_TRACE"]
        return self.collect_multiple(filenames, remote_path, progress_callback=progress_callback)

    def get_local_storage_path(self) -> Path:
        """Get the local storage directory path."""
        return self._local_storage

    def clear_local_storage(self) -> None:
        """Clear all collected trace files."""
        if self._local_storage.exists():
            shutil.rmtree(self._local_storage)
            self._local_storage.mkdir(parents=True, exist_ok=True)
            logger.info("Cleared local trace storage")