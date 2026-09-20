"""Unified Analysis Service coordinating pipeline ingestion and deep agent reasoning."""

from pathlib import Path
from typing import List, Optional
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.artifacts.models import TraceManifest
from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.agent.models import AgentAnalysisResult
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("analysis.service")


class AnalysisService:
    """Coordinates deterministic trace parsing and agent analysis reasoning."""

    def __init__(self, storage_dir: Optional[Path] = None):
        if storage_dir is None:
            settings = get_settings()
            self._storage_dir = Path(settings.voiceops_trace_storage)
        else:
            self._storage_dir = Path(storage_dir)

        self._pipeline = AnalysisPipelineService(storage_dir=self._storage_dir)
        self._analyzer = VoiceOpsAgentAnalyzer(storage_dir=self._storage_dir)

    @property
    def pipeline(self) -> AnalysisPipelineService:
        return self._pipeline

    @property
    def analyzer(self) -> VoiceOpsAgentAnalyzer:
        return self._analyzer

    def ingest_manifests(self, manifests: List[TraceManifest]) -> AnalysisWorkspace:
        """Ingest selected trace manifests and produce a persistent AnalysisWorkspace."""
        return self._pipeline.ingest_manifests(manifests)

    def load_saved_workspace(self) -> Optional[AnalysisWorkspace]:
        """Load the persisted AnalysisWorkspace."""
        return self._pipeline.load_saved_workspace()

    def run_agent_analysis(self, workspace: AnalysisWorkspace) -> AgentAnalysisResult:
        """Execute deep engineering agent analysis on the workspace."""
        return self._analyzer.analyze(workspace)

    def load_saved_analysis(self) -> Optional[AgentAnalysisResult]:
        """Load previously executed agent analysis."""
        return self._analyzer.load_saved_analysis()
