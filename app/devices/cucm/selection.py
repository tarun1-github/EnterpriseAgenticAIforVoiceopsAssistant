"""Time-based SDL trace file selection service."""

from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass

from app.devices.cucm.models import CUCMTraceFile
from app.core.logging import get_logger

logger = get_logger("devices.cucm.selection")


class SelectionMode(Enum):
    """Trace file selection modes."""
    LATEST = "latest"
    RELATIVE = "relative"
    CUSTOM = "custom"


class RelativeTimeOption(Enum):
    """Predefined relative time options."""
    MINUTES_5 = timedelta(minutes=5)
    MINUTES_10 = timedelta(minutes=10)
    MINUTES_15 = timedelta(minutes=15)
    MINUTES_30 = timedelta(minutes=30)
    HOURS_1 = timedelta(hours=1)
    HOURS_2 = timedelta(hours=2)
    HOURS_4 = timedelta(hours=4)
    HOURS_8 = timedelta(hours=8)
    HOURS_12 = timedelta(hours=12)
    HOURS_24 = timedelta(hours=24)

    @classmethod
    def from_string(cls, value: str) -> "RelativeTimeOption":
        """Parse relative time string like '15 minutes'."""
        value = value.lower().strip()
        mapping = {
            "5 minutes": cls.MINUTES_5,
            "10 minutes": cls.MINUTES_10,
            "15 minutes": cls.MINUTES_15,
            "30 minutes": cls.MINUTES_30,
            "1 hour": cls.HOURS_1,
            "2 hours": cls.HOURS_2,
            "4 hours": cls.HOURS_4,
            "8 hours": cls.HOURS_8,
            "12 hours": cls.HOURS_12,
            "24 hours": cls.HOURS_24,
        }
        if value not in mapping:
            raise ValueError(f"Unknown relative time option: {value}. Valid: {list(mapping.keys())}")
        return mapping[value]

    def to_display_string(self) -> str:
        """Return human-readable string."""
        td = self.value
        if td == timedelta(minutes=5):
            return "5 minutes"
        elif td == timedelta(minutes=10):
            return "10 minutes"
        elif td == timedelta(minutes=15):
            return "15 minutes"
        elif td == timedelta(minutes=30):
            return "30 minutes"
        elif td == timedelta(hours=1):
            return "1 hour"
        elif td == timedelta(hours=2):
            return "2 hours"
        elif td == timedelta(hours=4):
            return "4 hours"
        elif td == timedelta(hours=8):
            return "8 hours"
        elif td == timedelta(hours=12):
            return "12 hours"
        elif td == timedelta(hours=24):
            return "24 hours"
        return str(td)


@dataclass
class SelectionRequest:
    """Request parameters for trace selection."""
    mode: SelectionMode
    relative_option: Optional[RelativeTimeOption] = None
    custom_start: Optional[datetime] = None
    custom_end: Optional[datetime] = None
    reference_time: Optional[datetime] = None  # For testing; defaults to now

    def __post_init__(self):
        if self.reference_time is None:
            self.reference_time = datetime.now()

    def validate(self) -> None:
        """Validate the selection request."""
        if self.mode == SelectionMode.RELATIVE:
            if self.relative_option is None:
                raise ValueError("Relative mode requires relative_option")
        elif self.mode == SelectionMode.CUSTOM:
            if self.custom_start is None or self.custom_end is None:
                raise ValueError("Custom mode requires custom_start and custom_end")
            if self.custom_start >= self.custom_end:
                raise ValueError("custom_start must be before custom_end")
            if self.custom_end > self.reference_time:
                raise ValueError("custom_end cannot be in the future")


@dataclass
class SelectionResult:
    """Result of trace file selection."""
    request: SelectionRequest
    candidate_files: List[CUCMTraceFile]
    start_time: datetime
    end_time: datetime
    total_candidates: int
    estimated_size_bytes: int

    @property
    def estimated_size_mb(self) -> float:
        """Estimated size in megabytes."""
        return round(self.estimated_size_bytes / (1024 * 1024), 2)

    def to_dict(self) -> dict:
        return {
            "mode": self.request.mode.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "candidate_files": [
                {
                    "filename": f.filename,
                    "size_bytes": f.size_bytes,
                    "size_mb": round(f.size_bytes / (1024 * 1024), 2),
                    "modified": f.modified.isoformat() if f.modified else None,
                    "trace_type": f.trace_type,
                }
                for f in self.candidate_files
            ],
            "total_candidates": self.total_candidates,
            "estimated_size_bytes": self.estimated_size_bytes,
            "estimated_size_mb": round(self.estimated_size_bytes / (1024 * 1024), 2),
        }


class TraceSelectionService:
    """Service for selecting SDL trace files based on time criteria."""

    def __init__(self):
        pass

    def select_traces(
        self,
        all_files: List[CUCMTraceFile],
        request: SelectionRequest,
    ) -> SelectionResult:
        """Select trace files matching the time criteria.

        Args:
            all_files: All discovered SDL trace files from CUCM.
            request: Selection criteria.

        Returns:
            SelectionResult with candidate files.
        """
        request.validate()

        # Filter to trace payloads only (exclude .index)
        trace_files = [f for f in all_files if f.trace_type == "SDL_TRACE"]
        logger.info("Total trace payload files available: %d", len(trace_files))

        # Determine time window
        end_time = request.reference_time
        if request.mode == SelectionMode.LATEST:
            start_time = end_time - timedelta(days=365)  # Very wide window for latest
        elif request.mode == SelectionMode.RELATIVE:
            delta = request.relative_option.value
            start_time = end_time - delta
        elif request.mode == SelectionMode.CUSTOM:
            start_time = request.custom_start
            end_time = request.custom_end
        else:
            raise ValueError(f"Unknown selection mode: {request.mode}")

        logger.info("Selection window: %s to %s", start_time, end_time)

        # Select candidate files that could overlap with the time window
        # A file is a candidate if its modified time is within or near the window
        # We use a generous buffer to account for file rotation boundaries
        candidates = self._select_candidate_files(trace_files, start_time, end_time)

        # Sort by modification time (newest first)
        candidates.sort(key=lambda f: f.modified, reverse=True)

        estimated_size = sum(f.size_bytes for f in candidates)

        logger.info("Selected %d candidate files (%.2f MB)",
                    len(candidates), estimated_size / (1024 * 1024))

        return SelectionResult(
            request=request,
            candidate_files=candidates,
            start_time=start_time,
            end_time=end_time,
            total_candidates=len(candidates),
            estimated_size_bytes=estimated_size,
        )

    def _select_candidate_files(
        self,
        trace_files: List[CUCMTraceFile],
        start_time: datetime,
        end_time: datetime,
    ) -> List[CUCMTraceFile]:
        """Select files that could contain traces in the requested time window.

        A file is a candidate if:
        - Its modified time falls within the window, OR
        - It's the file immediately before the window start and the next file
          is within the window (boundary crossing - the file's end overlaps
          with the window start).

        Files are sorted by actual parsed CUCM timestamp (NOT filename sequence).
        Sequence numbers wrap and must NOT be used for ordering.
        """
        if not trace_files:
            return []

        # Sort by modified time (chronological order using parsed timestamps)
        sorted_files = sorted(trace_files, key=lambda f: f.modified)

        candidates = []

        for i, file in enumerate(sorted_files):
            file_time = file.modified

            # File falls within window
            if start_time <= file_time <= end_time:
                candidates.append(file)
            # File is just before window - check for boundary crossing
            elif file_time < start_time:
                # Check if this is the last file before the window
                next_idx = i + 1
                if next_idx < len(sorted_files):
                    next_file_time = sorted_files[next_idx].modified
                    # Boundary crossing: next file is in window, so this file
                    # may contain records that extend into the window
                    if next_file_time >= start_time:
                        candidates.append(file)

        # NO fallback to "closest before" - if no files overlap the window,
        # return empty list. The caller should handle zero candidates.

        return candidates

    def select_latest(self, all_files: List[CUCMTraceFile]) -> Optional[CUCMTraceFile]:
        """Select the single newest trace file."""
        trace_files = [f for f in all_files if f.trace_type == "SDL_TRACE"]
        if not trace_files:
            return None
        return max(trace_files, key=lambda f: f.modified)


def create_selection_request(
    mode: str,
    relative: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> SelectionRequest:
    """Factory function to create SelectionRequest from UI inputs."""
    sel_mode = SelectionMode(mode.lower())

    if sel_mode == SelectionMode.RELATIVE:
        if not relative:
            raise ValueError("Relative mode requires 'relative' parameter")
        rel_option = RelativeTimeOption.from_string(relative)
        return SelectionRequest(mode=sel_mode, relative_option=rel_option)

    elif sel_mode == SelectionMode.CUSTOM:
        if not start or not end:
            raise ValueError("Custom mode requires 'start' and 'end' parameters")
        custom_start = datetime.fromisoformat(start)
        custom_end = datetime.fromisoformat(end)
        return SelectionRequest(
            mode=sel_mode,
            custom_start=custom_start,
            custom_end=custom_end,
        )

    elif sel_mode == SelectionMode.LATEST:
        return SelectionRequest(mode=sel_mode)

    else:
        raise ValueError(f"Unknown mode: {mode}")