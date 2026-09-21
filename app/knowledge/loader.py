"""Knowledge loader reading versioned structured YAML knowledge into KnowledgeItem models."""

from pathlib import Path
from typing import Dict, List, Optional
import yaml

from app.core.logging import get_logger
from app.knowledge.models import KnowledgeItem

logger = get_logger("knowledge.loader")


class KnowledgeLoader:
    """Discovers and parses structured YAML knowledge files into memory."""

    def __init__(self, base_path: Optional[Path] = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            # Default to <repo_root>/knowledge/sdl
            self.base_path = Path(__file__).resolve().parent.parent.parent / "knowledge" / "sdl"

        self._items: Dict[str, KnowledgeItem] = {}
        self.version: str = "1.0.0"

    def load_all(self, force_reload: bool = False) -> List[KnowledgeItem]:
        """Load and cache all knowledge items from disk."""
        if self._items and not force_reload:
            return list(self._items.values())

        self._items.clear()
        if not self.base_path.exists():
            logger.warning("Knowledge base path does not exist: %s", self.base_path)
            return []

        # Recursively discover all .yaml and .yml files
        yaml_files = list(self.base_path.rglob("*.yaml")) + list(self.base_path.rglob("*.yml"))
        for yfile in yaml_files:
            self._load_file(yfile)

        logger.info("Loaded %d knowledge items from %s", len(self._items), self.base_path)
        return list(self._items.values())

    def _load_file(self, file_path: Path) -> None:
        """Parse a single YAML file and ingest its knowledge elements."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return

            # Read signals
            if "signals" in data and isinstance(data["signals"], list):
                for sig in data["signals"]:
                    item = KnowledgeItem(
                        id=f"signal_{sig.get('name')}",
                        category="signal",
                        title=sig.get("name", "Unknown Signal"),
                        description=sig.get("description", ""),
                        details={
                            "related_processes": sig.get("related_processes", []),
                            "expected_context": sig.get("expected_context", ""),
                            "possible_failure_domains": sig.get("possible_failure_domains", []),
                        },
                        confidence=sig.get("confidence", "high"),
                        source_reference=sig.get("source_reference"),
                        tags=[sig.get("name", "").lower(), "signal", sig.get("category", "").lower()],
                    )
                    self._items[item.id] = item

            # Read processes
            if "processes" in data and isinstance(data["processes"], list):
                for proc in data["processes"]:
                    item = KnowledgeItem(
                        id=f"proc_{proc.get('name')}",
                        category="process",
                        title=f"{proc.get('name')} ({proc.get('full_name', '')})",
                        description=proc.get("description", ""),
                        details={
                            "instance_pattern": proc.get("instance_pattern", ""),
                            "primary_functions": proc.get("primary_functions", []),
                        },
                        confidence=proc.get("confidence", "high"),
                        source_reference=proc.get("source_reference"),
                        tags=[proc.get("name", "").lower(), "process"],
                    )
                    self._items[item.id] = item

            # Read identifiers
            if "identifiers" in data and isinstance(data["identifiers"], list):
                for ident in data["identifiers"]:
                    item = KnowledgeItem(
                        id=f"ident_{ident.get('name')}",
                        category="identifier",
                        title=f"{ident.get('name')} ({ident.get('full_name', '')})",
                        description=ident.get("description", ""),
                        details={
                            "format": ident.get("format", ""),
                            "importance": ident.get("importance", ""),
                        },
                        confidence=ident.get("confidence", "high"),
                        source_reference=ident.get("source_reference"),
                        tags=[ident.get("name", "").lower(), "identifier"],
                    )
                    self._items[item.id] = item

            # Read failure patterns
            if "failures" in data and isinstance(data["failures"], list):
                for fail in data["failures"]:
                    item = KnowledgeItem(
                        id=f"fail_{fail.get('code')}",
                        category="failure",
                        title=fail.get("title", fail.get("code", "Failure Pattern")),
                        description="\n".join(fail.get("symptoms", [])),
                        details={
                            "code": fail.get("code"),
                            "possible_causes": fail.get("possible_causes", []),
                            "recommended_checks": fail.get("recommended_checks", []),
                        },
                        confidence=fail.get("confidence", "high"),
                        source_reference=fail.get("source_reference"),
                        tags=[fail.get("code", "").lower(), "failure", data.get("protocol", "").lower()],
                    )
                    self._items[item.id] = item

            # Read call flows
            if "flows" in data and isinstance(data["flows"], list):
                for flow in data["flows"]:
                    item = KnowledgeItem(
                        id=f"flow_{flow.get('name', 'flow').replace(' ', '_').lower()}",
                        category="callflow",
                        title=flow.get("name", "Call Flow"),
                        description=f"Standard reference flow for {data.get('protocol', 'Voice')}",
                        details={"steps": flow.get("steps", [])},
                        confidence=flow.get("confidence", "high"),
                        source_reference=flow.get("source_reference"),
                        tags=["callflow", data.get("protocol", "").lower()],
                    )
                    self._items[item.id] = item

        except Exception as exc:
            logger.error("Failed to load knowledge file %s: %s", file_path, exc)
