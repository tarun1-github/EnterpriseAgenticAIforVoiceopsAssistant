"""CUCM SDL trace file collector with multiple retrieval strategies."""

import tempfile
import shutil
from pathlib import Path
from typing import List, Optional, Callable
from dataclasses import dataclass, field

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

logger = get_logger("devices.cucm.collector")


@dataclass
class CollectionResult:
    """Result of trace file collection."""
    filename: str
    local_path: Optional[Path]
    size_bytes: int
    success: bool
    error: Optional[str] = None
    method: str = "unknown"


@dataclass
class CollectorConfig:
    """Configuration for trace collection."""
    large_file_threshold_mb: int = 10
    local_storage: Optional[Path] = None


class CUCMTraceCollector:
    """Collects SDL trace files from CUCM using available mechanisms.

    Supported methods:
    1. file view (CLI) - for small files, no external dependencies
    2. file get (SFTP) - for large files, requires SFTP server (NOT YET IMPLEMENTED)

    Note: SFTP-based file get is a separate milestone. This collector only supports
    'file view' for now. Attempting 'get' will return a clear failure result.

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
        method: str = "auto",
        progress_callback: Optional[Callable[[CollectionResult], None]] = None,
    ) -> List[CollectionResult]:
        """Download the previously selected trace files.

        Args:
            selection: SelectionResult from find_traces().
            remote_path: CUCM directory.
            method: "auto", "view", or "get"
            progress_callback: Optional callback for progress updates.

        Returns:
            List of CollectionResult for each downloaded file.
        """
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        filenames = [f.filename for f in selection.candidate_files]
        if not filenames:
            logger.warning("No candidate files to download")
            return []

        return self.collect_multiple(filenames, remote_path, method, progress_callback)

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

    def collect_file(
        self,
        filename: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
        method: str = "auto",
    ) -> CollectionResult:
        """Collect a single SDL trace file.

        Args:
            filename: Name of the trace file.
            remote_path: Remote directory on CUCM.
            method: "auto", "view", or "get"

        Returns:
            CollectionResult with local file path or error.
        """
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        # Validate filename early
        try:
            local_path = self._validate_filename(filename)
        except CUCMTraceCollectionError as e:
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=str(e),
                method="validation",
            )

        if method == "auto":
            # Determine best method based on file size AND file type
            files = self._client.list_sdl_files(remote_path)
            target = next((f for f in files if f.filename == filename), None)

            # .gz files MUST use 'get' (SFTP) - file view cannot read compressed files
            if target and filename.endswith(".gz"):
                method = "get"
            # Large files also need 'get'
            elif target and target.size_bytes > self._config.large_file_threshold_mb * 1024 * 1024:
                method = "get"
            else:
                method = "view"

        if method == "view":
            return self._collect_via_view(filename, remote_path, local_path)
        elif method == "get":
            return self._collect_via_get(filename, remote_path, local_path)
        else:
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=f"Unknown collection method: {method}",
                method=method,
            )

    def _collect_via_view(
        self,
        filename: str,
        remote_path: str,
        local_path: Path,
    ) -> CollectionResult:
        """Collect file using 'file view' CLI command.

        Limitation: Only works for reasonably sized UNCOMPRESSED files.
        For .txt.gz files, use 'file get' with SFTP (not yet implemented).
        Large files may be truncated or timeout.
        """
        # Do NOT use file view for compressed .gz files
        if filename.endswith(".gz"):
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=(
                    "Cannot use 'file view' for compressed .gz files. "
                    "Use method='get' with SFTP (not yet implemented) for .gz files."
                ),
                method="view",
            )

        try:
            logger.info("Collecting %s via 'file view'", filename)
            content = self._client.get_sdl_file_content(filename, remote_path)

            local_path.write_text(content, encoding="utf-8", errors="replace")

            size = local_path.stat().st_size
            logger.info("Collected %s (%d bytes) via view", filename, size)

            return CollectionResult(
                filename=filename,
                local_path=local_path,
                size_bytes=size,
                success=True,
                method="view",
            )
        except Exception as e:
            logger.error("Failed to collect %s via view: %s", filename, e)
            return CollectionResult(
                filename=filename,
                local_path=None,
                size_bytes=0,
                success=False,
                error=str(e),
                method="view",
            )

    def _collect_via_get(
        self,
        filename: str,
        remote_path: str,
        local_path: Path,
    ) -> CollectionResult:
        """Collect file using 'file get' with SFTP.

        NOT YET IMPLEMENTED - requires:
        1. An SFTP server accessible from CUCM
        2. CUCM configured to allow file get to that server
        3. Application to retrieve from the SFTP server

        Returns a clear failure result instead of silently falling back.
        """
        logger.warning("File get (SFTP) requested but not yet implemented")
        return CollectionResult(
            filename=filename,
            local_path=None,
            size_bytes=0,
            success=False,
            error=(
                "SFTP-based file get is not yet configured. "
                "Use method='view' for small files or configure SFTP server."
            ),
            method="get",
        )

    def collect_multiple(
        self,
        filenames: List[str],
        remote_path: str = "activelog /cm/trace/ccm/sdl",
        method: str = "auto",
        progress_callback: Optional[Callable[[CollectionResult], None]] = None,
    ) -> List[CollectionResult]:
        """Collect multiple SDL trace files."""
        results = []
        for filename in filenames:
            result = self.collect_file(filename, remote_path, method)
            results.append(result)
            if progress_callback:
                progress_callback(result)
        return results

    def collect_all_sdl(
        self,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
        max_files: Optional[int] = None,
        method: str = "auto",
        progress_callback: Optional[Callable[[CollectionResult], None]] = None,
    ) -> List[CollectionResult]:
        """Discover and collect all SDL trace files."""
        if not self._client.is_connected():
            raise CUCMConnectionError("CUCM client not connected")

        files = self._client.list_sdl_files(remote_path)
        if max_files:
            files = files[:max_files]

        filenames = [f.filename for f in files]
        return self.collect_multiple(filenames, remote_path, method, progress_callback=progress_callback)

    def get_local_storage_path(self) -> Path:
        """Get the local storage directory path."""
        return self._local_storage

    def clear_local_storage(self) -> None:
        """Clear all collected trace files."""
        if self._local_storage.exists():
            shutil.rmtree(self._local_storage)
            self._local_storage.mkdir(parents=True, exist_ok=True)
            logger.info("Cleared local trace storage")