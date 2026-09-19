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
        """Parse a single line from 'file list ... detail' output."""
        import re

        line = line.strip()
        if not line or line.startswith("====") or "total" in line.lower():
            return None

        pattern = re.compile(
            r"(?P<perms>\S+)\s+"
            r"(?P<links>\d+)\s+"
            r"(?P<owner>\S+)\s+"
            r"(?P<group>\S+)\s+"
            r"(?P<size>\d+)\s+"
            r"(?P<month>\w{3})\s+"
            r"(?P<day>\d{1,2})\s+"
            r"(?P<time>\d{2}:\d{2}|\d{4})\s+"
            r"(?P<name>.+)"
        )

        match = pattern.match(line)
        if not match:
            return None

        size = int(match.group("size"))
        name = match.group("name").strip()
        month_str = match.group("month")
        day = int(match.group("day"))
        time_str = match.group("time")

        month_map = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
        }
        month = month_map.get(month_str, 1)

        current_year = datetime.now().year
        try:
            if ":" in time_str:
                hour, minute = map(int, time_str.split(":"))
                modified = datetime(current_year, month, day, hour, minute)
            else:
                year = int(time_str)
                modified = datetime(year, month, day)
        except ValueError:
            modified = datetime.now()

        full_path = f"{base_path}/{name}"

        return cls(
            filename=name,
            path=full_path,
            size_bytes=size,
            modified=modified,
            trace_type="SDL",
            raw_metadata={
                "permissions": match.group("perms"),
                "owner": match.group("owner"),
                "group": match.group("group"),
            },
        )