"""CUCM data models for version info and trace files."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class CUCMVersion:
    """Structured CUCM version information."""

    version: str
    full_version: str
    build: Optional[str] = None
    edition: Optional[str] = None
    install_date: Optional[str] = None
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "full_version": self.full_version,
            "build": self.build,
            "edition": self.edition,
            "install_date": self.install_date,
            "raw_output": self.raw_output,
        }

    @classmethod
    def from_cli_output(cls, output: str) -> "CUCMVersion":
        """Parse 'show version active' CLI output."""
        import re

        version = "unknown"
        full_version = "unknown"
        build = None
        edition = None
        install_date = None

        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            if line.startswith("Active Master Version:"):
                full_version = line.split(":", 1)[1].strip()
            elif line.startswith("Active Version:"):
                version = line.split(":", 1)[1].strip()
            elif "Version:" in line and version == "unknown":
                version = line.split(":", 1)[1].strip()
            elif line.startswith("Build:"):
                build = line.split(":", 1)[1].strip()
            elif line.startswith("Edition:") or "Edition" in line and "install" not in line.lower():
                edition = line.split(":", 1)[1].strip() if ":" in line else line.strip()
            elif line.startswith("Install Date:") or "Install Date" in line:
                install_date = line.split(":", 1)[1].strip() if ":" in line else line.strip()

        if version == "unknown" and full_version != "unknown":
            version = full_version

        return cls(
            version=version,
            full_version=full_version,
            build=build,
            edition=edition,
            install_date=install_date,
            raw_output=output,
        )


@dataclass
class CUCMTraceFile:
    """Structured CUCM SDL trace file information."""

    filename: str
    path: str
    size_bytes: int
    modified: datetime
    trace_type: str = "SDL"
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "size_mb": round(self.size_bytes / (1024 * 1024), 2),
            "modified": self.modified.isoformat() if self.modified else None,
            "trace_type": self.trace_type,
            "raw_metadata": self.raw_metadata,
        }

    @classmethod
    def from_file_list_output(cls, line: str, base_path: str = "activelog/cm/trace/ccm/sdl") -> Optional["CUCMTraceFile"]:
        """Parse a single line from 'file list ... detail' output.

        Real CUCM output format:
        19 Sep,2026 05:28:31           34  SDL001_100.index
        03 Sep,2026 23:59:59      385,759  SDL001_100_000001.txt.gz
        """
        import re

        line = line.strip()
        if not line or line.startswith("====") or "total" in line.lower():
            return None

        # Pattern for real CUCM output:
        # DD Mon,YYYY HH:MM:SS   SIZE(filename may contain dots)
        # Examples:
        # 19 Sep,2026 05:28:31           34  SDL001_100.index
        # 03 Sep,2026 23:59:59      385,759  SDL001_100_000001.txt.gz
        pattern = re.compile(
            r"(?P<day>\d{1,2})\s+"
            r"(?P<month>\w{3}),"
            r"(?P<year>\d{4})\s+"
            r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
            r"(?P<size>[\d,]+)\s+"
            r"(?P<name>.+)"
        )

        match = pattern.match(line)
        if not match:
            return None

        # Parse size (handle comma-separated numbers)
        size_str = match.group("size").replace(",", "")
        try:
            size = int(size_str)
        except ValueError:
            return None

        name = match.group("name").strip()
        day = int(match.group("day"))
        month_str = match.group("month")
        year = int(match.group("year"))
        time_str = match.group("time")

        month_map = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
        }
        month = month_map.get(month_str, 1)

        try:
            hour, minute, second = map(int, time_str.split(":"))
            modified = datetime(year, month, day, hour, minute, second)
        except ValueError:
            modified = datetime.now()

        full_path = f"{base_path}/{name}"

        # Determine trace type
        trace_type = "SDL"
        if name.endswith(".index"):
            trace_type = "SDL_INDEX"
        elif name.endswith(".txt.gzo") or name.endswith(".txt.gz") or name.endswith(".txt"):
            trace_type = "SDL_TRACE"

        return cls(
            filename=name,
            path=full_path,
            size_bytes=size,
            modified=modified,
            trace_type=trace_type,
            raw_metadata={
                "permissions": "file",
            },
        )