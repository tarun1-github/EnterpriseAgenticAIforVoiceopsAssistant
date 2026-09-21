"""VoiceOps AI - Enterprise Cisco Voice Troubleshooting Platform (Streamlit UI)."""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Ensure workspace root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import streamlit as st

from app.analysis.anomaly_detector import AnomalyDetector
from app.analysis.evidence_builder import build_evidence_pack
from app.analysis.workspace import AnalysisWorkspace, AnalysisPipelineService
from app.analysis.architecture import detect_call_architecture, ArchitectureEvidence
from app.analysis.evidence import extract_signaling_messages, extract_sdl_observations, calculate_timing_deltas
from app.agent.analyzer import VoiceOpsAgentAnalyzer
from app.agent.models import AgentAnalysisResult
from app.artifacts.models import TraceManifest
from app.artifacts.repository import TraceArtifactRepository
from app.commands.models import CommandRequest, DeviceTypeEnum
from app.commands.history import CommandHistoryManager
from app.commands.service import DeviceCommandService
from app.commands.export import generate_command_filename, format_command_output_package, sanitize_command_for_filename
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.core.timestamps import to_ist_display, format_time_range_ist
from app.correlation.engine import CorrelationEngine
from app.correlation.ladder import CallLifecycleLadder
from app.devices.cucm import CUCMClient, CUCMTraceCollector, TraceSelectionService, SelectionMode, RelativeTimeOption
from app.devices.cucm.collector import CollectionResult
from app.devices.cucm.selection import SelectionResult, SelectionRequest
from app.devices.cucm.models import CUCMTraceFile
from app.models.call_session import CallSession, CallArchitecture
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.detector import detect_protocol
from app.parsers.ingestion import TraceIngestionEngine
from ui.sdl_analysis import render_sdl_analysis_tab

# Initialize logging
setup_logging()

# Streamlit Page Configuration
st.set_page_config(
    page_title="VoiceOps AI - Cisco Voice Troubleshooting",
    page_icon="📞",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Enterprise Dark-Themed Styling
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #E2E8F0;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    .disclaimer-banner {
        background-color: #1E293B;
        border-left: 4px solid #38BDF8;
        padding: 0.75rem 1rem;
        margin-bottom: 1.2rem;
        border-radius: 4px;
        color: #CBD5E1;
        font-size: 0.95rem;
    }
    .call-flow-diagram {
        background: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 1rem 1.5rem;
        font-family: 'Courier New', monospace;
        color: #38BDF8;
        font-size: 0.95rem;
        line-height: 1.6;
        margin-bottom: 1.5rem;
    }
    .anomaly-card-error {
        background: #450A0A;
        border: 1px solid #991B1B;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        color: #FECACA;
    }
    .anomaly-card-warning {
        background: #451A03;
        border: 1px solid #9A3412;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        color: #FED7AA;
    }
    .evidence-tag {
        display: inline-block;
        background: #1E3A5F;
        border: 1px solid #2563EB;
        color: #93C5FD;
        padding: 3px 8px;
        border-radius: 4px;
        margin: 2px 4px 2px 0;
        font-size: 0.85rem;
    }
    .artifact-box {
        background: #0F172A;
        border: 1px solid #1E3A8A;
        border-radius: 8px;
        padding: 1.2rem;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_ingestion_engine() -> TraceIngestionEngine:
    return TraceIngestionEngine()


@st.cache_resource
def get_correlation_engine() -> CorrelationEngine:
    detector = AnomalyDetector()
    return CorrelationEngine(anomaly_detector=detector)


@st.cache_resource
def get_cucm_client() -> CUCMClient:
    return CUCMClient()


@st.cache_resource
def get_artifact_repository() -> TraceArtifactRepository:
    return TraceArtifactRepository()


@st.cache_resource
def get_analysis_pipeline_service() -> AnalysisPipelineService:
    return AnalysisPipelineService()


@st.cache_resource
def get_command_history_manager() -> CommandHistoryManager:
    return CommandHistoryManager()


@st.cache_resource
def get_command_service() -> DeviceCommandService:
    return DeviceCommandService(
        history_manager=get_command_history_manager(),
        cucm_client=get_cucm_client(),
    )


@st.cache_resource
def get_agent_analyzer() -> VoiceOpsAgentAnalyzer:
    repo = get_artifact_repository()
    return VoiceOpsAgentAnalyzer(storage_dir=repo.storage_dir)


def load_bundled_samples() -> List[tuple[str, str]]:
    """Load sample files bundled in repository."""
    sample_dir = ROOT_DIR / "sample_data"
    samples = []
    for rel_path in [
        "isdn/sample_isdn_call.txt",
        "sip/sample_sip_call.txt",
        "mgcp/sample_mgcp_call.txt",
        "mixed/sample_mixed_gateway.txt",
    ]:
        p = sample_dir / rel_path
        if p.exists():
            samples.append((p.name, p.read_text(encoding="utf-8")))
    return samples


def render_trace_artifact_card(result: CollectionResult, artifact_repo: TraceArtifactRepository, key_prefix: str = "cucm"):
    """Render a persistent Trace Artifact container with direct download, view, and deletion controls."""
    if not result.success:
        st.error(f"❌ Failed to collect: {result.filename} - {result.error}")
        return

    ext_p = Path(result.extracted_path) if result.extracted_path else None
    raw_p = Path(result.raw_path) if result.raw_path else None
    manifest = result.manifest

    norm_name = ext_p.name if ext_p else result.filename
    node_name = manifest.node if manifest else "CUCM"
    cucm_ts = manifest.cucm_timestamp if (manifest and manifest.cucm_timestamp) else "N/A"
    size_str = f"{result.extracted_size_bytes:,} bytes ({result.extracted_size_bytes / (1024 * 1024):.2f} MB)" if result.extracted_size_bytes else f"{result.size_bytes:,} bytes"
    sha_str = result.extracted_sha256 or "N/A"

    st.markdown(
        f"""
        <div class="artifact-box">
            <span style="background:#1E40AF; color:#DBEAFE; font-size:0.75rem; font-weight:700; padding:2px 8px; border-radius:4px; letter-spacing:0.05em;">TRACE ARTIFACT</span>
            <h4 style="margin:0.5rem 0 0.2rem 0; color:#F8FAFC;">Filename: <code>{norm_name}</code></h4>
            <p style="margin:0; font-size:0.9rem; color:#94A3B8;">
                <strong>Node:</strong> <code>{node_name}</code> &nbsp;|&nbsp; 
                <strong>CUCM Timestamp:</strong> <code>{cucm_ts}</code> &nbsp;|&nbsp; 
                <strong>Size:</strong> {size_str} &nbsp;|&nbsp; 
                <strong>Status:</strong> <span style="color:#34D399; font-weight:600;">Validated</span>
            </p>
            <p style="margin:0.3rem 0 0.8rem 0; font-size:0.85rem; color:#64748B;">
                <strong>SHA256:</strong> <code>{sha_str}</code>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    bcol1, bcol2, bcol3, bcol4 = st.columns([1.3, 1.3, 1.1, 1.3])
    with bcol1:
        if manifest:
            txt_dl_bytes = artifact_repo.generate_trace_export_text(manifest).encode("utf-8")
        elif ext_p and ext_p.exists():
            txt_dl_bytes = ext_p.read_bytes()
        else:
            txt_dl_bytes = b""

        if txt_dl_bytes:
            st.download_button(
                label="📥 Download TXT",
                data=txt_dl_bytes,
                file_name=norm_name,
                mime="text/plain",
                key=f"{key_prefix}_dl_txt_{result.request_id or norm_name}",
                use_container_width=True,
            )
    with bcol2:
        if raw_p and raw_p.exists():
            st.download_button(
                label="📦 Download Raw",
                data=raw_p.read_bytes(),
                file_name=raw_p.name,
                mime="application/octet-stream",
                key=f"{key_prefix}_dl_raw_{result.request_id or norm_name}",
                use_container_width=True,
            )
    with bcol3:
        view_key = f"{key_prefix}_view_{result.request_id or norm_name}"
        if st.button("👁️ View TXT", key=view_key, use_container_width=True):
            st.session_state[f"show_preview_{view_key}"] = not st.session_state.get(f"show_preview_{view_key}", False)

    with bcol4:
        del_confirm_key = f"confirm_del_{key_prefix}_{result.request_id or norm_name}"
        if not st.session_state.get(del_confirm_key, False):
            if st.button("🗑️ Delete", key=f"{key_prefix}_del_{result.request_id or norm_name}", use_container_width=True):
                st.session_state[del_confirm_key] = True
                st.rerun()
        else:
            c_yes, c_no = st.columns(2)
            with c_yes:
                if st.button("⚠️ Confirm", key=f"{key_prefix}_conf_{result.request_id}", use_container_width=True):
                    if result.request_id:
                        artifact_repo.delete_trace(result.request_id)
                        st.session_state.pop(del_confirm_key, None)
                        st.success(f"Deleted local trace {norm_name}")
                        st.rerun()
            with c_no:
                if st.button("Cancel", key=f"{key_prefix}_cancel_{result.request_id}", use_container_width=True):
                    st.session_state.pop(del_confirm_key, None)
                    st.rerun()

    view_toggle = f"show_preview_{key_prefix}_view_{result.request_id or norm_name}"
    if st.session_state.get(view_toggle, False) and ext_p and ext_p.exists():
        with st.expander(f"📄 Verbatim Trace Content: {norm_name}", expanded=True):
            txt_content = ext_p.read_text(encoding="utf-8", errors="replace")
            lines = txt_content.splitlines()
            preview = "\n".join(lines[:500])
            if len(lines) > 500:
                preview += f"\n\n... [{len(lines) - 500} additional lines truncated for preview. Use Download TXT for full trace.]"
            st.code(preview, language="text")


def main():
    settings = get_settings()
    artifact_repo = get_artifact_repository()
    pipeline_service = get_analysis_pipeline_service()
    command_service = get_command_service()
    agent_analyzer = get_agent_analyzer()

    # Rehydrate AnalysisWorkspace from persistent storage if available
    if "analysis_workspace" not in st.session_state:
        saved_ws = pipeline_service.load_saved_workspace()
        if saved_ws:
            st.session_state["analysis_workspace"] = saved_ws
            st.session_state["parsed_events"] = saved_ws.events
            st.session_state["correlated_sessions"] = saved_ws.call_sessions
            st.session_state["uploaded_file_names"] = saved_ws.source_files

    # Rehydrate Agent Analysis from persistent storage if available
    if "agent_analysis_result" not in st.session_state:
        saved_an = agent_analyzer.load_saved_analysis()
        if saved_an:
            st.session_state["agent_analysis_result"] = saved_an

    # Sidebar: System Status & Configuration
    with st.sidebar:
        st.title("📞 VoiceOps AI")
        st.caption("Agentic Cisco Voice Troubleshooting")
        st.markdown("---")

        st.subheader("System Configuration")
        st.markdown(f"**LLM Provider:** `{settings.llm_provider}`")
        st.markdown(f"**Model:** `{settings.llm_model}`")
        st.markdown(f"**App Env:** `{settings.app_env}`")

        cucm_status = "Configured" if settings.cucm_host else "Not configured"
        st.markdown(f"**CUCM Status:** `{cucm_status}`")

        # CUCM Device Section
        if settings.cucm_host:
            st.markdown("---")
            st.subheader("🖥️ CUCM Device")
            cucm_client = get_cucm_client()

            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔌 Test Connection", use_container_width=True):
                    with st.spinner("Testing CUCM connection..."):
                        try:
                            cucm_client.connect()
                            st.session_state["cucm_connected"] = True
                            st.success("Connected!")
                        except Exception as e:
                            st.session_state["cucm_connected"] = False
                            st.error(f"Failed: {e}")

            with col2:
                if st.button("🔌 Disconnect", use_container_width=True):
                    try:
                        cucm_client.disconnect()
                        st.session_state["cucm_connected"] = False
                        st.success("Disconnected")
                    except Exception as e:
                        st.error(f"Error: {e}")

            if st.button("📋 Get Version", use_container_width=True):
                with st.spinner("Retrieving CUCM version..."):
                    try:
                        if not cucm_client.is_connected():
                            cucm_client.connect()
                        version = cucm_client.get_version()
                        st.session_state["cucm_version"] = version.to_dict()
                        st.success(f"Version: {version.version}")
                    except Exception as e:
                        st.error(f"Failed: {e}")

            if st.button("📁 Discover SDL Files", use_container_width=True):
                with st.spinner("Discovering SDL trace files..."):
                    try:
                        if not cucm_client.is_connected():
                            cucm_client.connect()
                        files = cucm_client.list_sdl_files()
                        st.session_state["cucm_sdl_files"] = [f.to_dict() for f in files]
                        st.success(f"Found {len(files)} SDL file(s)")
                    except Exception as e:
                        st.error(f"Failed: {e}")

            if st.button("🩺 Run Diagnostic", use_container_width=True):
                with st.spinner("Running CUCM diagnostic..."):
                    try:
                        if not cucm_client.is_connected():
                            cucm_client.connect()
                        diag = cucm_client.run_diagnostic()
                        st.session_state["cucm_diagnostic"] = diag
                        st.success(f"Diagnostic: {diag['overall']}")
                    except Exception as e:
                        st.error(f"Failed: {e}")

            st.markdown("---")
            st.subheader("⏱️ CUCM Trace Collection")

            # Collection Mode
            collection_mode = st.radio(
                "Collection Mode",
                ["Latest Trace", "Relative Time", "Custom Time Range"],
                key="cucm_collection_mode",
                horizontal=False,
            )

            if collection_mode == "Relative Time":
                relative_options = [
                    "5 minutes", "10 minutes", "15 minutes", "30 minutes",
                    "1 hour", "2 hours", "4 hours", "8 hours", "12 hours", "24 hours"
                ]
                selected_relative = st.selectbox(
                    "Time Window",
                    relative_options,
                    index=2,
                    key="cucm_relative_time",
                )
                end_time = datetime.now()
                start_time = end_time - RelativeTimeOption.from_string(selected_relative).value
                st.caption(f"Window: {start_time.strftime('%Y-%m-%d %H:%M:%S')} → {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

            elif collection_mode == "Custom Time Range":
                col_start, col_end = st.columns(2)
                with col_start:
                    start_date = st.date_input("Start Date", value=datetime.now(), key="cucm_start_date")
                    start_time_input = st.time_input("Start Time", value=datetime.now().replace(minute=0, second=0), key="cucm_start_time")
                with col_end:
                    end_date = st.date_input("End Date", value=datetime.now(), key="cucm_end_date")
                    end_time_input = st.time_input("End Time", value=datetime.now(), key="cucm_end_time")

                start_dt = datetime.combine(start_date, start_time_input)
                end_dt = datetime.combine(end_date, end_time_input)

                if start_dt >= end_dt:
                    st.error("⚠️ Start must be before End")
                elif end_dt > datetime.now():
                    st.error("⚠️ End cannot be in the future")
                else:
                    st.caption(f"Window: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} → {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")

            elif collection_mode == "Latest Trace":
                st.caption("Will select the newest available SDL trace file.")

            # Find Matching Traces button
            if st.button("🔍 Find Matching Traces", use_container_width=True):
                if not cucm_client.is_connected():
                    with st.spinner("Connecting to CUCM..."):
                        try:
                            cucm_client.connect()
                        except Exception as e:
                            st.error(f"Connection failed: {e}")
                            st.stop()

                with st.spinner("Discovering and selecting traces..."):
                    try:
                        collector = CUCMTraceCollector(client=cucm_client)

                        if collection_mode == "Latest Trace":
                            selection = collector.find_traces(mode="latest")
                        elif collection_mode == "Relative Time":
                            selection = collector.find_traces(mode="relative", relative=selected_relative)
                        elif collection_mode == "Custom Time Range":
                            if start_dt >= end_dt or end_dt > datetime.now():
                                st.error("Invalid time range")
                                st.stop()
                            selection = collector.find_traces(
                                mode="custom",
                                start=start_dt.isoformat(),
                                end=end_dt.isoformat(),
                            )

                        st.session_state["cucm_trace_selection"] = selection.to_dict()
                        st.success(f"Found {selection.total_candidates} candidate file(s) ({selection.estimated_size_mb:.2f} MB)")
                    except Exception as e:
                        st.error(f"Selection failed: {e}")

        st.markdown("---")
        st.subheader("Quick Actions")
        if st.button("📥 Load Bundled Samples", use_container_width=True, help="Load synthetic ISDN, SIP, MGCP & mixed traces"):
            samples = load_bundled_samples()
            with st.spinner("Correlating multi-protocol calls via Analysis Pipeline..."):
                workspace = pipeline_service.ingest_trace_contents(samples)
                st.session_state["analysis_workspace"] = workspace
                st.session_state["parsed_events"] = workspace.events
                st.session_state["correlated_sessions"] = workspace.call_sessions
                st.session_state["uploaded_file_names"] = [s[0] for s in samples]

            st.success(f"Loaded {len(samples)} trace files ({len(workspace.events)} events, {len(workspace.call_sessions)} sessions)!")
            st.rerun()

        if st.button("🗑️ Clear All Traces", use_container_width=True):
            pipeline_service.clear_saved_workspace()
            st.session_state.pop("analysis_workspace", None)
            st.session_state.pop("parsed_events", None)
            st.session_state.pop("uploaded_file_names", None)
            st.session_state.pop("correlated_sessions", None)
            st.rerun()

    # Main Application Header
    st.markdown('<div class="main-header">VoiceOps AI — Call Signaling Diagnostic Center</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Deterministic parsing, multi-signal call correlation, and signaling anomaly detection for Cisco Voice.</div>',
        unsafe_allow_html=True,
    )

    # Active Workspace Banner & State Restoration
    workspace: Optional[AnalysisWorkspace] = st.session_state.get("analysis_workspace")
    events: List[VoiceEvent] = workspace.events if workspace else st.session_state.get("parsed_events", [])
    sessions: List[CallSession] = workspace.call_sessions if workspace else st.session_state.get("correlated_sessions", [])

    if workspace:
        col_ws_info, col_ws_btn1, col_ws_btn2 = st.columns([4, 1.2, 1])
        with col_ws_info:
            st.markdown(
                f"<div style='background:#1E293B; border-left:4px solid #10B981; padding:0.5rem 0.8rem; border-radius:4px; font-size:0.88rem; color:#E2E8F0; margin-bottom:0.8rem;'>"
                f"💾 <strong>Persistent Analysis Workspace Active</strong> — ID: <code>{workspace.workspace_id}</code> | "
                f"Sources: <code>{', '.join(workspace.source_files) or 'Live Capture'}</code> | "
                f"Architecture: <strong>{workspace.architecture}</strong> | Status: <code>{workspace.ingestion_status}</code>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with col_ws_btn1:
            if st.button("🔄 Refresh Workspace", key="refresh_active_ws", use_container_width=True):
                saved_ws = pipeline_service.load_saved_workspace()
                if saved_ws:
                    st.session_state["analysis_workspace"] = saved_ws
                    st.session_state["parsed_events"] = saved_ws.events
                    st.session_state["correlated_sessions"] = saved_ws.call_sessions
                    st.session_state["uploaded_file_names"] = saved_ws.source_files
                saved_an = agent_analyzer.load_saved_analysis()
                if saved_an:
                    st.session_state["agent_analysis_result"] = saved_an
                st.success("Workspace refreshed from persistent storage.")
                st.rerun()
        with col_ws_btn2:
            if st.button("Clear Workspace", key="clear_active_ws", use_container_width=True):
                pipeline_service.clear_saved_workspace()
                st.session_state.pop("analysis_workspace", None)
                st.session_state.pop("parsed_events", None)
                st.session_state.pop("correlated_sessions", None)
                st.session_state.pop("uploaded_file_names", None)
                st.session_state.pop("agent_analysis_result", None)
                st.rerun()

    # Global Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events", len(events))
    with col2:
        st.metric("Correlated Sessions", len(sessions))
    with col3:
        isdn_count = workspace.protocol_counts.get("ISDN", 0) if workspace else sum(1 for e in events if e.protocol == ProtocolEnum.ISDN)
        st.metric("ISDN Q.931", isdn_count)
    with col4:
        sip_count = workspace.protocol_counts.get("SIP", 0) if workspace else sum(1 for e in events if e.protocol == ProtocolEnum.SIP)
        st.metric("SIP Messages", sip_count)
    with col5:
        mgcp_count = workspace.protocol_counts.get("MGCP", 0) if workspace else sum(1 for e in events if e.protocol == ProtocolEnum.MGCP)
        st.metric("MGCP Packets", mgcp_count)

    st.markdown("---")

    # Ingestion & Operation Tabs (11 Dedicated Tabs)
    (
        tab_upload,
        tab_library,
        tab_sessions,
        tab_timeline,
        tab_protocols,
        tab_inspector,
        tab_analysis,
        tab_sdl_analysis,
        tab_architecture,
        tab_cucm,
        tab_commands,
    ) = st.tabs(
        [
            "📁 Trace Upload",
            "📚 Trace Library",
            "📞 Call Sessions",
            "⏱️ Unified Timeline",
            "📊 Protocol View",
            "🔍 Event Inspector",
            "🧠 Analysis",
            "🔬 SDL Trace Analysis",
            "🏗️ Architecture & RCA",
            "🖥️ CUCM Device",
            "⚡ Device Command Center",
        ]
    )

    # =========================================================================
    # TAB 1: Trace Upload
    # =========================================================================
    with tab_upload:
        st.markdown("### Upload Cisco Trace Log Files")
        st.info("💡 **File names are optional metadata.** VoiceOps AI identifies trace type and devices primarily from **content**.")

        with st.expander("📝 Recommended File Naming Convention (Optional)", expanded=False):
            st.markdown(
                """
                Although strict naming is **not required**, the recommended naming format for engineers is:
                ```text
                <device>_<device-ip>_<trace-type>_<date>_<time>.txt
                ```
                **Examples:**
                - `CUCM_10.197.206.141_SDL_20260920_154200.txt`
                - `VG01_10.197.206.150_ISDN_Q931_20260920_154200.txt`
                - `VG01_10.197.206.150_SIP_20260920_154200.txt`
                - `CUBE01_10.197.206.160_SIP_20260920_154200.txt`

                *Files with arbitrary names (such as `SDL001_100_000087.txt`, `debug_isdn_q931.txt`, `router_capture.txt`) will be classified accurately by content inspection.*
                """
            )

        with st.expander("⚙️ Optional Upload Metadata & Overrides (Auto Detect by default)", expanded=False):
            st.caption("Leave as 'Auto Detect' for automatic content detection, or specify device/trace properties:")
            meta_col1, meta_col2, meta_col3 = st.columns(3)
            with meta_col1:
                opt_dev_type = st.selectbox(
                    "Device Type",
                    ["Auto Detect", "CUCM", "Voice Gateway", "CUBE", "IOS Router", "SIP Endpoint", "Other"],
                    index=0,
                    key="opt_meta_dev_type",
                )
                opt_trace_type = st.selectbox(
                    "Trace Type",
                    ["Auto Detect", "CUCM SDL", "ISDN/Q.931", "SIP", "MGCP", "CCAPI", "Mixed", "Other"],
                    index=0,
                    key="opt_meta_trace_type",
                )
            with meta_col2:
                opt_dev_ip = st.text_input("Device IP (optional)", placeholder="e.g. 10.197.206.150", key="opt_meta_dev_ip")
                opt_dev_name = st.text_input("Device Name (optional)", placeholder="e.g. VG01-HQ", key="opt_meta_dev_name")
            with meta_col3:
                opt_region = st.text_input("Region (optional)", placeholder="e.g. APAC / DC-Primary", key="opt_meta_region")
                opt_tz = st.selectbox(
                    "Timestamp Timezone",
                    ["Auto Detect", "IST", "UTC", "PST", "CST", "EST"],
                    index=0,
                    key="opt_meta_tz",
                    help="All timestamps are normalized and rendered in Asia/Kolkata (IST) in UI",
                )

        uploaded_files = st.file_uploader(
            "Select Cisco trace files (Batch upload supported)",
            type=["txt", "log"],
            accept_multiple_files=True,
            help="Upload raw router/CUCM trace text dumps. Multi-file correlation runs across all selected logs.",
        )

        if st.button("🚀 Ingest & Correlate Traces", type="primary", use_container_width=False):
            if uploaded_files:
                with st.spinner("Executing deterministic content classifier, protocol parsers, and multi-trace correlation engine..."):
                    contents = [(uf.name, uf.read().decode("utf-8", errors="replace")) for uf in uploaded_files]

                    # Construct metadata overrides if engineer specified any non-default values
                    meta_overrides = {}
                    if opt_dev_type != "Auto Detect":
                        meta_overrides["device_type"] = opt_dev_type
                    if opt_trace_type != "Auto Detect":
                        meta_overrides["trace_type"] = opt_trace_type
                    if opt_dev_ip.strip():
                        meta_overrides["device_ip"] = opt_dev_ip.strip()
                    if opt_dev_name.strip():
                        meta_overrides["device_name"] = opt_dev_name.strip()
                    if opt_region.strip():
                        meta_overrides["region"] = opt_region.strip()
                    if opt_tz != "Auto Detect":
                        meta_overrides["timezone"] = opt_tz

                    ws = pipeline_service.ingest_trace_contents(contents, metadata_overrides=meta_overrides if meta_overrides else None)
                    st.session_state["analysis_workspace"] = ws
                    st.session_state["parsed_events"] = ws.events
                    st.session_state["correlated_sessions"] = ws.call_sessions
                    st.session_state["uploaded_file_names"] = ws.source_files

                st.success(f"Processed {len(uploaded_files)} file(s). Extracted {len(ws.events)} events into {len(ws.call_sessions)} CallSession(s).")
                st.rerun()
            else:
                st.warning("Please select at least one file or use 'Load Bundled Samples' in the sidebar.")

        if "analysis_workspace" in st.session_state and st.session_state["analysis_workspace"]:
            cur_ws: AnalysisWorkspace = st.session_state["analysis_workspace"]
            if cur_ws.trace_artifacts:
                st.markdown("---")
                st.markdown("### 📋 Trace Inventory (Content-Based Classification)")
                inv_table_data = []
                for a in cur_ws.trace_artifacts:
                    evidence_str = ", ".join(a.get("classification_evidence", [])[:2]) if a.get("classification_evidence") else "Content pattern match"
                    inv_table_data.append({
                        "File": a.get("filename"),
                        "Detected Type": a.get("trace_type"),
                        "Device": a.get("device_type"),
                        "IP": a.get("device_ip") or "-",
                        "Confidence": f"{int(a.get('classification_confidence', 1.0) * 100)}%",
                        "Status": "Classified",
                        "Evidence": evidence_str,
                    })
                st.dataframe(pd.DataFrame(inv_table_data), use_container_width=True, hide_index=True)

                p_stats = cur_ws.parser_statistics or {}
                c_col1, c_col2, c_col3 = st.columns(3)
                with c_col1:
                    st.metric("Correlated Calls", p_stats.get("correlated_calls", len(cur_ws.call_sessions)))
                with c_col2:
                    st.metric("Uncorrelated Events", p_stats.get("uncorrelated_events", 0))
                with c_col3:
                    st.metric("Potentially Ambiguous", p_stats.get("potentially_ambiguous", 0))

        if "uploaded_file_names" in st.session_state:
            st.markdown("#### Currently Ingested Files:")
            for fname in st.session_state["uploaded_file_names"]:
                st.markdown(f"- 📄 `{fname}`")

    # =========================================================================
    # TAB 2: Trace Library (Persistent Inventory)
    # =========================================================================
    with tab_library:
        lib_head_col1, lib_head_col2 = st.columns([5, 1.2])
        with lib_head_col1:
            st.markdown("### 📚 Trace Library")
            st.caption("Persistent repository of all successfully collected CUCM SDL and voice gateway traces. Survives application restarts.")
        with lib_head_col2:
            if st.button("🔄 Refresh Library", key="btn_refresh_lib", use_container_width=True):
                st.rerun()

        manifests = artifact_repo.list_manifests()

        if not manifests:
            st.info("💡 Trace Library is empty. Collect traces from the **🖥️ CUCM Device** tab to persist them here.")
        else:
            lib_col1, lib_col2, lib_col3 = st.columns(3)
            with lib_col1:
                st.metric("Total Collected Traces", len(manifests))
            with lib_col2:
                total_mb = sum(m.extracted_size for m in manifests) / (1024 * 1024)
                st.metric("Total Storage Size", f"{total_mb:.2f} MB")
            with lib_col3:
                latest_m = manifests[0].collection_timestamp[:19].replace("T", " ") if manifests else "N/A"
                st.metric("Latest Collection", latest_m)

            st.markdown("---")

            if "library_selected_ids" not in st.session_state:
                st.session_state["library_selected_ids"] = set()

            col_btn1, col_btn2, col_btn3, col_btn4 = st.columns([1, 1, 2, 2])
            with col_btn1:
                if st.button("☑ Select All", key="lib_select_all", use_container_width=True):
                    st.session_state["library_selected_ids"] = {m.request_id for m in manifests}
                    st.rerun()
            with col_btn2:
                if st.button("☐ Clear Selection", key="lib_clear_all", use_container_width=True):
                    st.session_state["library_selected_ids"] = set()
                    st.rerun()
            with col_btn3:
                has_selection = len(st.session_state["library_selected_ids"]) > 0
                if st.button("🚀 Ingest Selected", type="primary", disabled=not has_selection, key="lib_ingest_btn", use_container_width=True):
                    selected_manifests = [m for m in manifests if m.request_id in st.session_state["library_selected_ids"]]
                    with st.spinner("Ingesting selected traces through analysis pipeline..."):
                        ws = pipeline_service.ingest_manifests(selected_manifests)
                        st.session_state["analysis_workspace"] = ws
                        st.session_state["parsed_events"] = ws.events
                        st.session_state["correlated_sessions"] = ws.call_sessions
                        st.session_state["uploaded_file_names"] = ws.source_files
                    st.success(f"Ingested {len(selected_manifests)} trace(s) into {len(ws.call_sessions)} CallSession(s)!")
                    st.rerun()
            with col_btn4:
                if not st.session_state.get("lib_bulk_del_confirm", False):
                    if st.button("🗑️ Delete Selected", disabled=not has_selection, key="lib_del_btn", use_container_width=True):
                        st.session_state["lib_bulk_del_confirm"] = True
                        st.rerun()
                else:
                    c_del_y, c_del_n = st.columns(2)
                    with c_del_y:
                        if st.button("⚠️ Confirm Delete", key="lib_conf_bulk_del", use_container_width=True):
                            deleted_count = 0
                            for req_id in list(st.session_state["library_selected_ids"]):
                                if artifact_repo.delete_trace(req_id):
                                    deleted_count += 1
                            st.session_state["library_selected_ids"] = set()
                            st.session_state["lib_bulk_del_confirm"] = False
                            st.success(f"Deleted {deleted_count} local trace artifact(s).")
                            st.rerun()
                    with c_del_n:
                        if st.button("Cancel", key="lib_cancel_bulk_del", use_container_width=True):
                            st.session_state["lib_bulk_del_confirm"] = False
                            st.rerun()

            st.markdown("##### Persistent Trace Inventory")
            # Table Header
            h_chk, h_file, h_node, h_cucm_ts, h_type, h_sz, h_coll, h_stat = st.columns([0.6, 2.8, 1.6, 1.8, 1.2, 1.2, 1.8, 1.2])
            with h_chk:
                st.caption("Select")
            with h_file:
                st.caption("Filename")
            with h_node:
                st.caption("Node/IP")
            with h_cucm_ts:
                st.caption("CUCM Timestamp")
            with h_type:
                st.caption("Trace Type")
            with h_sz:
                st.caption("Size")
            with h_coll:
                st.caption("Collected At")
            with h_stat:
                st.caption("Status")

            selected_ids = set()
            for idx, m in enumerate(manifests):
                col_chk, col_file, col_node, col_time, col_type, col_sz, col_coll, col_stat = st.columns([0.6, 2.8, 1.6, 1.8, 1.2, 1.2, 1.8, 1.2])
                with col_chk:
                    checked = st.checkbox(
                        "",
                        key=f"lib_chk_{m.request_id}_{idx}",
                        value=m.request_id in st.session_state["library_selected_ids"],
                    )
                    if checked:
                        selected_ids.add(m.request_id)
                with col_file:
                    st.markdown(f"**`{m.normalized_filename}`**  \n<small style='color:#64748B;'>{m.original_filename}</small>", unsafe_allow_html=True)
                with col_node:
                    st.text(m.node)
                with col_time:
                    st.text(m.cucm_timestamp or "N/A")
                with col_type:
                    st.text(m.trace_type)
                with col_sz:
                    st.text(f"{m.extracted_size / (1024 * 1024):.2f} MB")
                with col_coll:
                    st.text(m.collection_timestamp[:19].replace("T", " "))
                with col_stat:
                    st.markdown(f"<span style='color:#34D399;font-weight:600;'>{m.validation_status}</span>", unsafe_allow_html=True)

            st.session_state["library_selected_ids"] = selected_ids

            # Action cards for selected files
            if selected_ids:
                st.markdown("---")
                st.markdown("##### Actions for Selected Artifact(s)")
                for req_id in selected_ids:
                    m = next((item for item in manifests if item.request_id == req_id), None)
                    if not m:
                        continue
                    ext_p = Path(m.extracted_path)
                    raw_p = Path(m.raw_path)

                    col_info, col_dl_txt, col_dl_raw, col_view, col_ingest = st.columns([3.5, 1.8, 1.8, 1.4, 1.5])
                    with col_info:
                        st.markdown(f"📄 **`{m.normalized_filename}`** (`{m.node}` | `{m.extracted_size / (1024 * 1024):.2f} MB`)")
                    with col_dl_txt:
                        export_txt_data = artifact_repo.generate_trace_export_text(m).encode("utf-8")
                        st.download_button(
                            "📥 Download TXT",
                            data=export_txt_data,
                            file_name=m.normalized_filename,
                            mime="text/plain",
                            key=f"lib_dltxt_{req_id}",
                            use_container_width=True,
                        )
                    with col_dl_raw:
                        if raw_p.exists():
                            st.download_button(
                                "📦 Download Raw",
                                data=raw_p.read_bytes(),
                                file_name=m.original_filename,
                                mime="application/octet-stream",
                                key=f"lib_dlraw_{req_id}",
                                use_container_width=True,
                            )
                    with col_view:
                        if st.button("👁️ View", key=f"lib_view_{req_id}", use_container_width=True):
                            st.session_state[f"view_txt_{req_id}"] = not st.session_state.get(f"view_txt_{req_id}", False)

                    with col_ingest:
                        if st.button("🚀 Ingest", key=f"lib_ingest_single_{req_id}", use_container_width=True):
                            with st.spinner(f"Ingesting {m.normalized_filename}..."):
                                ws = pipeline_service.ingest_manifests([m])
                                st.session_state["analysis_workspace"] = ws
                                st.session_state["parsed_events"] = ws.events
                                st.session_state["correlated_sessions"] = ws.call_sessions
                                st.session_state["uploaded_file_names"] = ws.source_files
                            st.success(f"Ingested {m.normalized_filename}!")
                            st.rerun()

                    if st.session_state.get(f"view_txt_{req_id}", False) and ext_p.exists():
                        with st.expander(f"Preview: {m.normalized_filename}", expanded=True):
                            txt = ext_p.read_text(encoding="utf-8", errors="replace")
                            st.code(txt[:4000] + ("\n... [truncated for preview. Use Download TXT for complete trace package.]" if len(txt) > 4000 else ""), language="text")

    # =========================================================================
    # TAB 3: Call Sessions View
    # =========================================================================
    with tab_sessions:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files in **Trace Upload**, ingest from **Trace Library**, or load **Bundled Samples** in the sidebar.")
        else:
            st.markdown(
                '<div class="disclaimer-banner">ℹ️ <strong>Deterministic multi-signal correlation active.</strong> All sessions and anomalies below are derived purely from rule-based cross-protocol signaling analysis.</div>',
                unsafe_allow_html=True,
            )

            st.markdown("### Correlated Voice Call Sessions")

            if not sessions:
                st.warning("No call sessions correlated.")
            else:
                session_rows = [s.to_summary_dict() for s in sessions]
                df_sessions = pd.DataFrame(session_rows)
                st.dataframe(
                    df_sessions,
                    use_container_width=True,
                    column_config={
                        "session_id": st.column_config.TextColumn("Session ID", width="small"),
                        "architecture": st.column_config.TextColumn("Architecture", width="medium"),
                        "calling": st.column_config.TextColumn("Calling (ANI)", width="small"),
                        "called": st.column_config.TextColumn("Called (DNIS)", width="small"),
                        "start": st.column_config.TextColumn("Start Time", width="small"),
                        "end": st.column_config.TextColumn("End Time", width="small"),
                        "protocols": st.column_config.TextColumn("Protocols", width="medium"),
                        "event_count": st.column_config.NumberColumn("Events", width="small"),
                        "confidence": st.column_config.TextColumn("Confidence", width="small"),
                        "anomalies": st.column_config.NumberColumn("Anomalies", width="small"),
                    },
                    hide_index=True,
                )

                st.markdown("---")
                st.markdown("### Session Drill-Down Inspector")

                session_labels = [
                    f"{s.session_id} | {s.architecture.value} | ANI: {s.calling_number or '-'} ➔ DNIS: {s.called_number or '-'} ({len(s.events)} events, {len(s.anomalies)} anomalies)"
                    for s in sessions
                ]
                selected_sess_idx = st.selectbox(
                    "Select Session to Inspect",
                    range(len(sessions)),
                    format_func=lambda i: session_labels[i],
                )
                selected_session = sessions[selected_sess_idx]

                # Session Metadata Grid
                mcol1, mcol2, mcol3, mcol4 = st.columns(4)
                with mcol1:
                    st.markdown(f"**Call ID / Session:** `{selected_session.session_id}`")
                    st.markdown(f"**Architecture:** `{selected_session.architecture.value}`")
                    duration_s = (selected_session.end_time - selected_session.start_time).total_seconds() if (selected_session.start_time and selected_session.end_time) else 0.0
                    st.markdown(f"**Duration:** `{duration_s:.3f}s`")
                with mcol2:
                    st.markdown(f"**Calling (ANI):** `{selected_session.calling_number or '-'}`")
                    st.markdown(f"**Called (DNIS):** `{selected_session.called_number or '-'}`")
                    st.markdown(f"**Confidence:** `{int(selected_session.correlation_confidence * 100)}%`")
                with mcol3:
                    st.markdown(f"**ISDN Call Ref:** `{', '.join(selected_session.isdn_call_references) or 'None'}`")
                    st.markdown(f"**SIP Call-ID:** `{', '.join(selected_session.sip_call_ids) or 'None'}`")
                    mgcp_ids = selected_session.mgcp_transaction_ids or selected_session.mgcp_call_ids
                    st.markdown(f"**MGCP Identifiers:** `{', '.join(mgcp_ids) or 'None'}`")
                with mcol4:
                    devices_str = ", ".join(selected_session.devices) if selected_session.devices else (settings.cucm_host or "CUCM")
                    st.markdown(f"**CUCM / Gateway:** `{devices_str}`")
                    endpoints_str = ", ".join(selected_session.endpoints) if selected_session.endpoints else "-"
                    st.markdown(f"**Endpoint / Phone:** `{endpoints_str}`")
                    st.markdown(f"**Evidence Count:** `{len(selected_session.correlation_evidence)}`")

                # Drill-Down Sub-Tabs
                s_tab_ladder, s_tab_timeline, s_tab_protocols, s_tab_evidence, s_tab_anomalies, s_tab_pack = st.tabs(
                    [
                        "📈 Call Lifecycle Ladder",
                        "⏱️ Unified Call Timeline",
                        "📊 Protocols",
                        "🔗 Correlation Evidence",
                        "⚠️ Detected Anomalies",
                        "📦 JSON Evidence Pack",
                    ]
                )

                with s_tab_ladder:
                    st.markdown("##### 📈 Dynamic Call Lifecycle Ladder Diagram")
                    st.caption("PSTN ↔ Voice Gateway ↔ CUCM ↔ Phone (CUCM SDL is an internal call-processing leg)")
                    ladder_diagram = CallLifecycleLadder().generate_ascii_ladder(selected_session)
                    st.code(ladder_diagram, language="text")

                with s_tab_timeline:
                    s_events = [ev.to_summary_dict() for ev in selected_session.events]
                    if s_events:
                        st.dataframe(pd.DataFrame(s_events), use_container_width=True, hide_index=True)

                with s_tab_protocols:
                    p_col1, p_col2, p_col3 = st.columns(3)
                    with p_col1:
                        st.markdown("##### 🔵 ISDN Q.931 Events")
                        s_isdn = [e for e in selected_session.events if e.protocol == ProtocolEnum.ISDN]
                        if s_isdn:
                            for e in s_isdn:
                                icon = "📥" if e.direction == DirectionEnum.INBOUND else "📤"
                                st.markdown(f"{icon} `{e.timestamp_raw or 'No TS'}` **{e.message_type}** `ref={e.call_reference}`")
                        else:
                            st.caption("No ISDN events in this session.")

                    with p_col2:
                        st.markdown("##### 🟠 MGCP Packets")
                        s_mgcp = [e for e in selected_session.events if e.protocol == ProtocolEnum.MGCP]
                        if s_mgcp:
                            for e in s_mgcp:
                                icon = "📥" if e.direction == DirectionEnum.INBOUND else "📤"
                                st.markdown(f"{icon} `{e.timestamp_raw or 'No TS'}` **{e.message_type}** `trans={e.transaction_id}`")
                        else:
                            st.caption("No MGCP events in this session.")

                    with p_col3:
                        st.markdown("##### 🟢 SIP Messages")
                        s_sip = [e for e in selected_session.events if e.protocol == ProtocolEnum.SIP]
                        if s_sip:
                            for e in s_sip:
                                icon = "📥" if e.direction == DirectionEnum.INBOUND else "📤"
                                st.markdown(f"{icon} `{e.timestamp_raw or 'No TS'}` **{e.message_type}**")
                        else:
                            st.caption("No SIP events in this session.")

                with s_tab_evidence:
                    st.markdown("##### Signals Matched Across Protocols:")
                    if selected_session.correlation_evidence:
                        for ev_item in selected_session.correlation_evidence:
                            st.markdown(f"- 🔗 {ev_item}")
                    else:
                        st.caption("Single initial event; no multi-signal correlation required.")

                with s_tab_anomalies:
                    st.markdown("##### Deterministic Signaling Anomalies:")
                    if selected_session.anomalies:
                        for anom in selected_session.anomalies:
                            card_class = "anomaly-card-error" if anom.severity.value == "ERROR" else "anomaly-card-warning"
                            st.markdown(
                                f"""
                                <div class="{card_class}">
                                    <strong>[{anom.protocol.value} | {anom.category.value}] {anom.severity.value}</strong><br/>
                                    {anom.description}<br/>
                                    <small>Expected: <code>{anom.expected_message or 'N/A'}</code></small>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.success("✅ No signaling anomalies detected in this session.")

                with s_tab_pack:
                    st.markdown("##### Machine-Readable Evidence Pack (Structured for LLM Agent):")
                    pack = build_evidence_pack(selected_session)
                    st.json(pack.model_dump(mode="json"))

    # =========================================================================
    # TAB 4: Unified Timeline
    # =========================================================================
    with tab_timeline:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files in **Trace Upload** or ingest from **Trace Library**.")
        else:
            st.markdown("### Unified Chronological Timeline")
            st.caption("All protocol events across all traces ordered strictly by chronological sequence.")

            f_col1, f_col2, f_col3 = st.columns(3)
            with f_col1:
                protocol_options = ["ALL"] + [p.value for p in ProtocolEnum if p != ProtocolEnum.UNKNOWN]
                selected_proto = st.selectbox("Filter by Protocol", protocol_options, key="t_proto")
            with f_col2:
                dir_options = ["ALL", "RX (Inbound)", "TX (Outbound)", "INTERNAL"]
                selected_dir = st.selectbox("Filter by Direction", dir_options, key="t_dir")
            with f_col3:
                search_query = st.text_input("Search (Message, ANI, DNIS, Call-ID, Cause)", "", key="t_search")

            filtered_events = events
            if selected_proto != "ALL":
                filtered_events = [e for e in filtered_events if e.protocol.value == selected_proto]
            if selected_dir == "RX (Inbound)":
                filtered_events = [e for e in filtered_events if e.direction == DirectionEnum.INBOUND]
            elif selected_dir == "TX (Outbound)":
                filtered_events = [e for e in filtered_events if e.direction == DirectionEnum.OUTBOUND]
            elif selected_dir == "INTERNAL":
                filtered_events = [e for e in filtered_events if e.direction == DirectionEnum.INTERNAL]

            if search_query:
                q = search_query.lower()
                filtered_events = [
                    e for e in filtered_events
                    if (
                        q in e.message_type.lower()
                        or (e.calling_number and q in e.calling_number.lower())
                        or (e.called_number and q in e.called_number.lower())
                        or (e.call_id and q in e.call_id.lower())
                        or (e.call_reference and q in e.call_reference.lower())
                        or (e.cause_code and q in e.cause_code.lower())
                    )
                ]

            table_rows = [e.to_summary_dict() for e in filtered_events]
            if table_rows:
                st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
            else:
                st.info("No events match the selected filters.")

    # =========================================================================
    # TAB 5: Protocol View
    # =========================================================================
    with tab_protocols:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files in **Trace Upload** or ingest from **Trace Library**.")
        else:
            st.markdown("### Protocol Signaling View")
            st.caption("Inspect parsed signaling attributes and protocol headers without inventing fields.")

            proto_filter = st.radio("Select Protocol Filter", ["All", "ISDN", "SIP", "MGCP"], horizontal=True, key="pv_filter")

            p_events = events
            if proto_filter == "ISDN":
                p_events = [e for e in events if e.protocol == ProtocolEnum.ISDN]
            elif proto_filter == "SIP":
                p_events = [e for e in events if e.protocol == ProtocolEnum.SIP]
            elif proto_filter == "MGCP":
                p_events = [e for e in events if e.protocol == ProtocolEnum.MGCP]

            if not p_events:
                st.info(f"No {proto_filter} events found in the active workspace.")
            else:
                for idx, ev in enumerate(p_events[:50]):
                    icon = "🔵" if ev.protocol == ProtocolEnum.ISDN else "🟢" if ev.protocol == ProtocolEnum.SIP else "🟠"
                    dir_icon = "📥" if ev.direction == DirectionEnum.INBOUND else "📤"

                    with st.expander(f"{icon} {dir_icon} [{ev.protocol.value}] {ev.message_type} — {ev.timestamp_raw or 'No TS'}", expanded=(idx < 2)):
                        # Protocol-specific field exposure
                        if ev.protocol == ProtocolEnum.SIP:
                            sc1, sc2 = st.columns(2)
                            with sc1:
                                st.markdown(f"**Method / Status:** `{ev.message_type}`")
                                st.markdown(f"**SIP Call-ID:** `{ev.call_id or 'N/A'}`")
                                if ev.metadata.get("cseq"):
                                    st.markdown(f"**CSeq:** `{ev.metadata.get('cseq')}`")
                                if ev.calling_number or ev.metadata.get("from"):
                                    st.markdown(f"**From:** `{ev.metadata.get('from') or ev.calling_number}`")
                            with sc2:
                                if ev.called_number or ev.metadata.get("to"):
                                    st.markdown(f"**To:** `{ev.metadata.get('to') or ev.called_number}`")
                                if ev.metadata.get("via"):
                                    st.markdown(f"**Via:** `{ev.metadata.get('via')}`")
                                if ev.metadata.get("sdp"):
                                    st.markdown(f"**SDP:** `{ev.metadata.get('sdp')}`")
                                if ev.metadata.get("rtp"):
                                    st.markdown(f"**RTP:** `{ev.metadata.get('rtp')}`")

                        elif ev.protocol == ProtocolEnum.ISDN:
                            ic1, ic2 = st.columns(2)
                            with ic1:
                                st.markdown(f"**Q.931 Message:** `{ev.message_type}`")
                                st.markdown(f"**Call Reference:** `{ev.call_reference or 'N/A'}`")
                                if ev.metadata.get("bearer_capability"):
                                    st.markdown(f"**Bearer Capability:** `{ev.metadata.get('bearer_capability')}`")
                                if ev.interface or ev.metadata.get("channel"):
                                    st.markdown(f"**Channel / Interface:** `{ev.interface or ev.metadata.get('channel')}`")
                            with ic2:
                                st.markdown(f"**Calling Number:** `{ev.calling_number or '-'}`")
                                st.markdown(f"**Called Number:** `{ev.called_number or '-'}`")
                                if ev.cause_code:
                                    st.markdown(f"**Cause Code:** `{ev.cause_code}`")

                        elif ev.protocol == ProtocolEnum.MGCP:
                            mc1, mc2 = st.columns(2)
                            with mc1:
                                st.markdown(f"**Command / Verb:** `{ev.message_type}`")
                                st.markdown(f"**Transaction ID:** `{ev.transaction_id or 'N/A'}`")
                                st.markdown(f"**Endpoint:** `{ev.endpoint or 'N/A'}`")
                            with mc2:
                                if ev.metadata.get("response"):
                                    st.markdown(f"**Response:** `{ev.metadata.get('response')}`")
                                if ev.call_id:
                                    st.markdown(f"**Call ID:** `{ev.call_id}`")

                        if ev.raw:
                            st.caption("Verbatim Protocol Trace Block:")
                            st.code(ev.raw, language="text")

                if len(p_events) > 50:
                    st.caption(f"Showing first 50 of {len(p_events)} {proto_filter} events.")

    # =========================================================================
    # TAB 6: Event Inspector
    # =========================================================================
    with tab_inspector:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files in **Trace Upload** or ingest from **Trace Library**.")
        else:
            st.markdown("### Detailed Event & Raw Trace Inspector")
            st.caption("Select any individual signaling event to view structured parsed fields and verbatim raw text.")

            event_labels = [
                f"[{i+1}/{len(events)}] {e.protocol.value} | {e.message_type} | {e.timestamp_raw or 'No TS'} | {e.calling_number or ''}->{e.called_number or ''}"
                for i, e in enumerate(events)
            ]
            selected_idx = st.selectbox("Choose Event to Inspect", range(len(events)), format_func=lambda i: event_labels[i])
            sel_event = events[selected_idx]

            # Correlated session lookup
            related_session = None
            for s in sessions:
                if any(ev.id == sel_event.id for ev in s.events):
                    related_session = s
                    break

            col_details, col_raw = st.columns([1, 1])
            with col_details:
                st.markdown("#### Structured Event Attributes")
                event_dict = {
                    "id": sel_event.id,
                    "timestamp": sel_event.timestamp.isoformat() if sel_event.timestamp else None,
                    "timestamp_raw": sel_event.timestamp_raw,
                    "protocol": sel_event.protocol.value,
                    "direction": sel_event.direction.value,
                    "message_type": sel_event.message_type,
                    "source": sel_event.source,
                    "interface": sel_event.interface,
                    "call_reference": sel_event.call_reference,
                    "transaction_id": sel_event.transaction_id,
                    "call_id": sel_event.call_id,
                    "calling_number": sel_event.calling_number,
                    "called_number": sel_event.called_number,
                    "source_ip": sel_event.source_ip,
                    "destination_ip": sel_event.destination_ip,
                    "endpoint": sel_event.endpoint,
                    "cause_code": sel_event.cause_code,
                    "related_call_session": related_session.session_id if related_session else "Uncorrelated",
                    "metadata": sel_event.metadata,
                }
                st.json(event_dict)

                parsed_json_str = json.dumps(event_dict, indent=2)
                st.download_button(
                    "📋 Download Parsed JSON",
                    data=parsed_json_str.encode("utf-8"),
                    file_name=f"event_{sel_event.id}.json",
                    mime="application/json",
                    key="dl_event_json",
                    use_container_width=True,
                )

            with col_raw:
                st.markdown("#### Verbatim Raw Trace Block")
                st.code(sel_event.raw or "(No raw trace content captured)", language="text")

                if sel_event.raw:
                    st.download_button(
                        "📄 Download Raw Block",
                        data=sel_event.raw.encode("utf-8"),
                        file_name=f"event_{sel_event.id}_raw.txt",
                        mime="text/plain",
                        key="dl_event_raw",
                        use_container_width=True,
                    )

    # =========================================================================
    # TAB 7: Analysis (Forensic Overview & Agent Analysis)
    # =========================================================================
    with tab_analysis:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files in **Trace Upload** or ingest from **Trace Library**.")
        else:
            st.markdown("### 🧠 VoiceOps Deep Engineering Analysis")
            st.caption("Comprehensive, evidence-grounded forensic investigation across ISDN Q.931, MGCP, CUCM SDL, and SIP signaling.")

            # Section Overview: ANALYSIS SUMMARY
            st.markdown("#### 📋 Trace Summary")
            sum_col1, sum_col2, sum_col3, sum_col4 = st.columns(4)
            with sum_col1:
                st.markdown(f"**Trace Files:** `{len(workspace.source_files) if workspace else 1}`")
                st.markdown(f"**Total Events:** `{len(events):,}`")
                st.markdown(f"**Call Sessions:** `{len(sessions)}`")
            with sum_col2:
                st.markdown(f"**ISDN Events:** `{isdn_count:,}`")
                st.markdown(f"**MGCP Events:** `{mgcp_count:,}`")
                st.markdown(f"**SIP Messages:** `{sip_count:,}`")
            with sum_col3:
                sdl_ev_count = sum(1 for e in events if "SdlSig" in e.raw or "AppInfo" in e.raw or "MGCPHandler" in e.raw or "SIPD" in e.raw or "StationInit" in e.raw)
                st.markdown(f"**CUCM SDL Events:** `{sdl_ev_count:,}`")
                total_anoms = len(workspace.anomalies) if workspace else sum(len(s.anomalies) for s in sessions)
                st.markdown(f"**Anomalies:** `{total_anoms}`")
                trace_tr = workspace.time_range_ist if (workspace and workspace.time_range_ist) else "N/A"
                st.markdown(f"**Trace Time Range (IST):**  \n`{trace_tr}`")
            with sum_col4:
                arch_name = workspace.architecture if workspace else "UNKNOWN"
                st.markdown(f"**Detected Architecture:**  \n`{arch_name}`")

            # Section 17 Diagnostics Expander: Parser Statistics
            parser_stats = (workspace.parser_statistics if workspace and workspace.parser_statistics else {})
            if parser_stats:
                with st.expander("📊 Parser & Correlation Diagnostics", expanded=False):
                    diag_c1, diag_c2, diag_c3 = st.columns(3)
                    with diag_c1:
                        st.markdown(f"**Raw Lines:** `{parser_stats.get('raw_lines', 0):,}`")
                        st.markdown(f"**Parsed SDL Events:** `{parser_stats.get('parsed_sdl_events', 0):,}`")
                        st.markdown(f"**Total Events:** `{parser_stats.get('total_events', 0):,}`")
                    with diag_c2:
                        st.markdown(f"**ISDN Events:** `{parser_stats.get('isdn_events', 0):,}`")
                        st.markdown(f"**MGCP Events:** `{parser_stats.get('mgcp_events', 0):,}`")
                        st.markdown(f"**SIP Events:** `{parser_stats.get('sip_events', 0):,}`")
                        st.markdown(f"**CUCM Events:** `{parser_stats.get('cucm_events', 0):,}`")
                    with diag_c3:
                        st.markdown(f"**Correlated Calls:** `{parser_stats.get('correlated_calls', 0):,}`")
                        st.markdown(f"**Events Assigned to Calls:** `{parser_stats.get('events_assigned_to_calls', 0):,}`")
                        st.markdown(f"**Events Not Assigned:** `{parser_stats.get('events_not_assigned', 0):,}`")
                        st.markdown(f"**Uncorrelated Events:** `{parser_stats.get('uncorrelated_events', 0):,}`")

            st.markdown("---")

            # =================================================================
            # 1. CALL SELECTION SECTION (Requirements 1, 2)
            # =================================================================
            st.markdown("### 🔍 Call Selection")
            st.caption("A single trace file may contain many calls. Filter and select a specific call session to isolate its signaling sequence and surrounding CUCM SDL activity.")

            # Search/Filter Inputs
            f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([2, 2, 2, 2, 1.5])
            with f_col1:
                search_calling = st.text_input("Calling Number", key="filter_calling_num", placeholder="e.g. 9876543210")
            with f_col2:
                search_called = st.text_input("Called Number", key="filter_called_num", placeholder="e.g. 1800123456")
            with f_col3:
                search_start = st.text_input("Start Time", key="filter_start_time", placeholder="e.g. 15:20 or 20-Sep")
            with f_col4:
                search_end = st.text_input("End Time", key="filter_end_time", placeholder="e.g. 15:30")
            with f_col5:
                st.write("")
                st.write("")
                if st.button("Clear Filters", key="btn_clear_call_filters", use_container_width=True):
                    st.session_state["filter_calling_num"] = ""
                    st.session_state["filter_called_num"] = ""
                    st.session_state["filter_start_time"] = ""
                    st.session_state["filter_end_time"] = ""
                    st.rerun()

            # Filter calls
            filtered_sessions = sessions
            if search_calling:
                filtered_sessions = [s for s in filtered_sessions if search_calling.lower() in (s.calling_number or "").lower()]
            if search_called:
                filtered_sessions = [s for s in filtered_sessions if search_called.lower() in (s.called_number or "").lower()]
            if search_start:
                filtered_sessions = [
                    s for s in filtered_sessions
                    if search_start.lower() in (s.start_time_ist or "").lower()
                    or (s.start_time and search_start.lower() in s.start_time.isoformat().lower())
                ]
            if search_end:
                filtered_sessions = [
                    s for s in filtered_sessions
                    if search_end.lower() in (s.end_time_ist or "").lower()
                    or (s.end_time and search_end.lower() in s.end_time.isoformat().lower())
                ]

            st.markdown(f"**Calls detected:** `{len(filtered_sessions)}` *(Total correlated in trace: {len(sessions)})*")

            selected_session: Optional[CallSession] = None
            if not filtered_sessions:
                st.warning("No calls match the current search filters. Click 'Clear Filters' above to reset.")
            else:
                # Build summary rows for calls table
                call_table_rows = []
                for s in filtered_sessions:
                    proto_map = s.protocol_counts
                    call_table_rows.append({
                        "Call ID": s.session_id,
                        "Calling Number": s.calling_number or "Unknown",
                        "Called Number": s.called_number or "Unknown",
                        "Call Start Time (IST)": s.start_time_ist,
                        "Call End Time (IST)": s.end_time_ist,
                        "Duration": s.duration_display,
                        "Architecture": s.architecture.value,
                        "ISDN": proto_map.get("ISDN", 0),
                        "MGCP": proto_map.get("MGCP", 0),
                        "SIP": proto_map.get("SIP", 0),
                        "CUCM SDL": proto_map.get("CUCM", 0),
                        "Anomalies": len(s.anomalies),
                        "Status": s.status,
                    })

                st.dataframe(
                    pd.DataFrame(call_table_rows),
                    use_container_width=True,
                    hide_index=True,
                )

                # Call Selector Dropdown
                call_options = [s.session_id for s in filtered_sessions]
                curr_selected = st.session_state.get("selected_analysis_call_id")
                default_idx = call_options.index(curr_selected) if curr_selected in call_options else 0

                selected_call_id = st.selectbox(
                    "🎯 Choose Call Session for Investigation:",
                    call_options,
                    index=default_idx,
                    format_func=lambda cid: next(
                        (f"{s.session_id} | Calling: {s.calling_number or 'Unknown'} ➔ Called: {s.called_number or 'Unknown'} | Start: {s.start_time_ist} | {s.architecture.value}" for s in filtered_sessions if s.session_id == cid),
                        cid,
                    ),
                    key="select_call_dropdown",
                )
                st.session_state["selected_analysis_call_id"] = selected_call_id
                selected_session = next((s for s in filtered_sessions if s.session_id == selected_call_id), filtered_sessions[0])

            st.markdown("---")

            # =================================================================
            # 2. SELECTED CALL SECTION (Requirements 8, 9, 10)
            # =================================================================
            sdl_window_secs = 5.0
            if selected_session:
                st.markdown(f"### 📞 Selected Call: `{selected_session.session_id}`")

                sel_c1, sel_c2, sel_c3 = st.columns(3)
                with sel_c1:
                    st.markdown(f"**Calling Number:** `{selected_session.calling_number or 'Unknown'}`")
                    st.markdown(f"**Called Number:** `{selected_session.called_number or 'Unknown'}`")
                    st.markdown(f"**Duration:** `{selected_session.duration_display}`")
                with sel_c2:
                    raw_start = selected_session.start_time.strftime('%H:%M:%S.%f')[:-3] if selected_session.start_time else "N/A"
                    raw_end = selected_session.end_time.strftime('%H:%M:%S.%f')[:-3] if selected_session.end_time else "N/A"
                    st.markdown(f"**CUCM Trace Time:**  \n`{raw_start} → {raw_end}`")
                    st.markdown(f"**IST Time:**  \n`{selected_session.start_time_ist} → {selected_session.end_time_ist}`")
                with sel_c3:
                    st.markdown(f"**Architecture:**  \n`{selected_session.architecture.value}`")
                    st.markdown(f"**Confidence:** `{int(selected_session.correlation_confidence * 100)}%`")

                # SDL Time Window Controls (Requirement 9)
                w_col1, w_col2 = st.columns([2, 3])
                with w_col1:
                    window_option = st.selectbox(
                        "SDL Analysis Window",
                        ["±5 sec (Default)", "±1 sec", "±2 sec", "±10 sec", "±30 sec", "Custom"],
                        index=0,
                        key="sdl_window_select",
                        help="Time window around call start and end to isolate CUCM SDL background processes and signals.",
                    )
                with w_col2:
                    if window_option == "Custom":
                        sdl_window_secs = st.number_input("Custom SDL Window (seconds)", min_value=0.0, max_value=300.0, value=5.0, step=1.0, key="sdl_custom_secs")
                    else:
                        window_mapping = {
                            "±1 sec": 1.0,
                            "±2 sec": 2.0,
                            "±5 sec (Default)": 5.0,
                            "±10 sec": 10.0,
                            "±30 sec": 30.0,
                        }
                        sdl_window_secs = window_mapping.get(window_option, 5.0)

                # Selected Call Evidence Breakdown (Requirement 10)
                st.markdown("#### Selected Call Evidence")
                ev_c1, ev_c2, ev_c3, ev_c4, ev_c5 = st.columns(5)
                p_counts = selected_session.protocol_counts
                with ev_c1:
                    st.metric("ISDN Events", p_counts.get("ISDN", 0))
                with ev_c2:
                    st.metric("MGCP Events", p_counts.get("MGCP", 0))
                with ev_c3:
                    st.metric("SIP Messages", p_counts.get("SIP", 0))
                with ev_c4:
                    st.metric("CUCM SDL Events", p_counts.get("CUCM", 0))
                with ev_c5:
                    st.metric("Anomalies", len(selected_session.anomalies))

                # Deep SDL Evidence Table Expander (Requirement 10)
                with st.expander("🔬 View SDL Evidence", expanded=False):
                    if not workspace:
                        ws_base = AnalysisWorkspace(
                            events=events,
                            call_sessions=sessions,
                            source_files=st.session_state.get("uploaded_file_names", ["trace.txt"]),
                        )
                    else:
                        ws_base = workspace

                    call_scoped_ws = ws_base.create_call_scoped_workspace(selected_session, time_window_seconds=sdl_window_secs)
                    default_fn = ws_base.source_files[0] if ws_base.source_files else "cucm_trace.txt"
                    sdl_obs_list = extract_sdl_observations(call_scoped_ws.events, default_filename=default_fn)

                    if not sdl_obs_list:
                        st.info("No specific CUCM SDL process signals isolated within the selected time window.")
                    else:
                        st.caption(f"Showing {len(sdl_obs_list)} SDL observation(s) within ±{sdl_window_secs}s of call boundaries:")
                        sdl_rows = [obs.to_display_dict() for obs in sdl_obs_list]
                        st.dataframe(pd.DataFrame(sdl_rows), use_container_width=True, hide_index=True)

            st.markdown("---")

            # =================================================================
            # 3. AGENT ANALYSIS CONTROLS (Requirements 13, 15)
            # =================================================================
            st.markdown("### 🤖 Agent Analysis")
            act_col1, act_col2, act_col3 = st.columns([2, 1.5, 2])
            has_existing_analysis = "agent_analysis_result" in st.session_state and st.session_state["agent_analysis_result"] is not None
            run_btn_label = "🔄 Re-run Agent Analysis" if has_existing_analysis else "🚀 Run Agent Analysis"

            with act_col1:
                if st.button(run_btn_label, type="primary", key="btn_run_agent_analysis", use_container_width=True):
                    if not selected_session:
                        st.warning("Please select a call before running Agent Analysis.")
                    else:
                        if not workspace:
                            ws_base = AnalysisWorkspace(
                                events=events,
                                call_sessions=sessions,
                                source_files=st.session_state.get("uploaded_file_names", ["trace.txt"]),
                            )
                        else:
                            ws_base = workspace

                        # Create Call-Scoped Workspace (Requirements 8, 15)
                        call_scoped_ws = ws_base.create_call_scoped_workspace(selected_session, time_window_seconds=sdl_window_secs)

                        if not call_scoped_ws.events:
                            st.warning("Insufficient evidence for deep RCA. Trace contains no signaling events for the selected call window.")
                        else:
                            with st.spinner(f"Analyzing call {selected_session.session_id} ({selected_session.calling_number}->{selected_session.called_number}) across SDL window (±{sdl_window_secs}s)..."):
                                analysis_result = agent_analyzer.analyze(call_scoped_ws)
                                st.session_state["agent_analysis_result"] = analysis_result
                                st.session_state["agent_analyzed_call_id"] = selected_session.session_id
                            st.success(f"Engineering Analysis completed for Call {selected_session.session_id}! (ID: {analysis_result.analysis_id})")
                            st.rerun()

            with act_col2:
                if st.button("🔄 Refresh Analysis", key="btn_refresh_analysis", use_container_width=True):
                    saved_an = agent_analyzer.load_saved_analysis()
                    if saved_an:
                        st.session_state["agent_analysis_result"] = saved_an
                        st.success("Loaded saved analysis report from persistent storage.")
                    else:
                        st.info("No saved analysis report found on disk.")
                    st.rerun()

            with act_col3:
                current_analysis: Optional[AgentAnalysisResult] = st.session_state.get("agent_analysis_result")
                if current_analysis:
                    st.download_button(
                        "📥 Download Engineering Report (.md)",
                        data=current_analysis.markdown_report.encode("utf-8"),
                        file_name=f"VoiceOps_Analysis_{current_analysis.analysis_id}.md",
                        mime="text/markdown",
                        key="btn_download_agent_report",
                        use_container_width=True,
                    )

            # =================================================================
            # 4. RENDER DEEP ENGINEERING REPORT (Requirement 14)
            # =================================================================
            current_analysis = st.session_state.get("agent_analysis_result")
            if not current_analysis:
                st.info("💡 Select a call above and click **Run Agent Analysis** to initiate deep reasoning and forensic analysis.")
            else:
                st.markdown("---")
                st.markdown(f"## 📑 Deep Engineering Analysis Report (`{current_analysis.analysis_id}`)")
                st.caption(f"Generated at {current_analysis.created_at[:19].replace('T', ' ')} UTC | Engine: `{current_analysis.model_provider}` v`{current_analysis.analysis_version}`")

                # Section 0: Call Summary (Requirement 14)
                with st.expander("📋 Call Summary", expanded=True):
                    c_sum1, c_sum2, c_sum3 = st.columns(3)
                    with c_sum1:
                        st.markdown(f"**Call ID:** `{current_analysis.call_id or 'N/A'}`")
                        st.markdown(f"**Calling Number:** `{current_analysis.calling_number or 'Unknown'}`")
                        st.markdown(f"**Called Number:** `{current_analysis.called_number or 'Unknown'}`")
                    with c_sum2:
                        st.markdown(f"**Start Time (IST):** `{current_analysis.start_time_ist or 'N/A'}`")
                        st.markdown(f"**End Time (IST):** `{current_analysis.end_time_ist or 'N/A'}`")
                        st.markdown(f"**Duration:** `{current_analysis.duration or 'N/A'}`")
                    with c_sum3:
                        st.markdown(f"**Architecture:** `{current_analysis.architecture_name}`")
                        st.markdown(f"**Confidence:** `{current_analysis.architecture_confidence}`")

                # Section 1: Executive Summary
                with st.expander("1️⃣ Executive Summary", expanded=True):
                    st.markdown(current_analysis.executive_summary)

                # Section 2: Detected Architecture
                with st.expander("2️⃣ Detected Architecture & Evidence", expanded=True):
                    st.markdown(f"**Detected Topology:** `{current_analysis.architecture_name}`")
                    st.code(current_analysis.architecture_flow, language="text")
                    st.markdown("**Evidence Supporting Each Leg:**")
                    for ev_bullet in current_analysis.architecture_evidence:
                        st.markdown(f"- {ev_bullet}")
                    st.markdown(f"**Confidence:** `{current_analysis.architecture_confidence}`")

                # Section 3: Call Flow Sequence
                with st.expander("3️⃣ Chronological Call Flow Sequence", expanded=True):
                    if current_analysis.call_flow:
                        st.code("\n".join(current_analysis.call_flow[:50]), language="text")
                    else:
                        st.text("No chronological progression parsed.")

                # Section 4: Signaling Analysis
                with st.expander("4️⃣ Signaling Analysis (Observed Protocol Messages)", expanded=True):
                    sig_c1, sig_c2, sig_c3 = st.columns(3)
                    with sig_c1:
                        st.markdown("**ISDN Q.931:**")
                        isdn_msgs = current_analysis.signaling_analysis.get("ISDN", [])
                        if isdn_msgs:
                            for m in isdn_msgs:
                                st.markdown(f"- `{m}`")
                        else:
                            st.caption("None observed")
                    with sig_c2:
                        st.markdown("**MGCP:**")
                        mgcp_msgs = current_analysis.signaling_analysis.get("MGCP", [])
                        if mgcp_msgs:
                            for m in mgcp_msgs:
                                st.markdown(f"- `{m}`")
                        else:
                            st.caption("None observed")
                    with sig_c3:
                        st.markdown("**SIP:**")
                        sip_msgs = current_analysis.signaling_analysis.get("SIP", [])
                        if sip_msgs:
                            for m in sip_msgs:
                                st.markdown(f"- `{m}`")
                        else:
                            st.caption("None observed")

                # Section 5: CUCM SDL Analysis
                with st.expander("5️⃣ CUCM SDL Deep Investigation", expanded=True):
                    st.markdown("Forensic examination of internal CallManager process signals, timers, and gateway handlers:")
                    if not current_analysis.sdl_analysis:
                        st.info("No specific CUCM SDL process signals isolated in trace.")
                    else:
                        for idx, obs in enumerate(current_analysis.sdl_analysis[:25]):
                            st.markdown(
                                f"""
                                <div style="background:#1E293B; border-left:3px solid #38BDF8; padding:0.6rem 0.8rem; margin-bottom:0.6rem; border-radius:4px;">
                                    <strong>⏱️ {obs.timestamp} | {obs.event_name}</strong> ({obs.process_name or 'CUCM'})<br/>
                                    <span style="color:#CBD5E1; font-size:0.9rem;">{obs.interpretation}</span><br/>
                                    <small style="color:#94A3B8;">Line/Evidence in <code>{obs.filename}</code> | Correlated ID: <code>{obs.related_call_id or 'N/A'}</code></small>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                            st.code(obs.raw_evidence, language="text")

                # Section 6: Timing Analysis
                with st.expander("6️⃣ Timing & Latency Analysis", expanded=True):
                    if not current_analysis.timing_analysis:
                        st.caption("Insufficient timestamps to calculate progression deltas.")
                    else:
                        t_rows = [
                            {
                                "Transition": f"{t.from_event} ➔ {t.to_event}",
                                "Start": t.from_time_str,
                                "End": t.to_time_str,
                                "Delta": f"{t.delta_ms} ms",
                                "Status": "⚠️ Suspicious Delay" if t.is_suspicious else "✅ Normal",
                                "Note": t.note or "-",
                            }
                            for t in current_analysis.timing_analysis
                        ]
                        st.dataframe(pd.DataFrame(t_rows), use_container_width=True, hide_index=True)

                # Section 7: Anomaly Analysis
                with st.expander("7️⃣ Anomaly Analysis", expanded=True):
                    if not current_analysis.anomaly_analysis:
                        st.success("✅ No signaling anomalies or unexpected state transitions detected.")
                    else:
                        for an in current_analysis.anomaly_analysis:
                            card_border = "#EF4444" if an.severity == "ERROR" else "#F59E0B"
                            st.markdown(
                                f"""
                                <div style="background:#1E293B; border-left:4px solid {card_border}; padding:0.6rem 0.8rem; margin-bottom:0.6rem; border-radius:4px;">
                                    <strong>[{an.protocol} | {an.severity}] {an.description}</strong><br/>
                                    <span style="font-size:0.9rem; color:#E2E8F0;">Impact: {an.impact}</span><br/>
                                    <small style="color:#94A3B8;">Location: <code>{an.likely_location}</code> | Timestamp: <code>{an.timestamp}</code> | Confidence: <code>{an.confidence}</code></small><br/>
                                    <small style="color:#94A3B8;">Evidence: <code>{an.evidence}</code></small>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

                # Section 8: Root Cause / Most Likely Cause
                with st.expander("8️⃣ Root Cause Determination & Engineering Reasoning Matrix", expanded=True):
                    rc = current_analysis.root_cause_analysis
                    if rc.has_root_cause:
                        st.markdown(f"### **Root Cause:**\n{rc.root_cause}")
                        st.markdown("**Evidence Supporting Root Cause:**")
                        for idx, ev_item in enumerate(rc.evidence, 1):
                            st.markdown(f"{idx}. {ev_item}")
                        st.markdown(f"**Confidence:** `{rc.confidence}`")
                    else:
                        st.warning("⚠️ **Root cause not established from available evidence.**")
                        if rc.missing_evidence:
                            st.markdown(f"**Missing Evidence Required:**\n{rc.missing_evidence}")

                    st.markdown("---")
                    st.markdown("#### 🧠 Engineering Reasoning Matrix")
                    mat_col1, mat_col2, mat_col3, mat_col4 = st.columns(4)
                    with mat_col1:
                        st.markdown("##### 📌 FACTS (Observed)")
                        for f in rc.facts:
                            st.markdown(f"- {f}")
                    with mat_col2:
                        st.markdown("##### 🔗 CORRELATIONS")
                        if rc.correlations:
                            for c in rc.correlations:
                                st.markdown(f"- {c}")
                        else:
                            st.caption("None active")
                    with mat_col3:
                        st.markdown("##### 💡 INFERENCES")
                        for inf in rc.inferences:
                            st.markdown(f"- {inf}")
                    with mat_col4:
                        st.markdown("##### 🔬 HYPOTHESES")
                        if rc.hypotheses:
                            for h in rc.hypotheses:
                                st.markdown(f"- {h}")
                        else:
                            st.caption("None active")

    # =========================================================================
    # TAB 8: Dedicated CUCM SDL Trace Analysis
    # =========================================================================
    with tab_sdl_analysis:
        render_sdl_analysis_tab(
            artifact_repo=artifact_repo,
            cucm_client=get_cucm_client(),
        )

    # =========================================================================
    # TAB 9: Architecture & RCA
    # =========================================================================
    with tab_architecture:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files in **Trace Upload** or ingest from **Trace Library**.")
        else:
            st.markdown("### 🏗️ Call Architecture & Root Cause Analysis")

            arch_ev = (workspace.architecture_evidence if workspace else None) or detect_call_architecture(events, sessions=sessions)

            st.markdown("#### Detected Architecture:")
            st.code(arch_ev.flow_vertical, language="text")

            st.markdown("#### Evidence Checklist:")
            for ev_item in arch_ev.evidence_checklist:
                st.markdown(f"- **{ev_item}**")

            st.markdown(f"**Confidence:** `{arch_ev.confidence}` (Score: `{arch_ev.confidence_score:.2f}`)")

            st.markdown("---")
            st.markdown("#### Detected Call Leg Distribution")
            st.markdown(
                f"""
                - **ISDN Ingress**: `{isdn_count}` signaling frame(s) identified on PRI interface.
                - **Gateway Control / Ingress**: `{mgcp_count}` MGCP packet(s) detected between Gateway and CallManager.
                - **CUCM / SIP Egress**: `{sip_count}` SIP packet(s) between CUCM and destination endpoint.
                """
            )

            # Anomaly & evidence breakdown
            total_anomalies = sum(len(s.anomalies) for s in sessions)
            st.markdown(f"#### Deterministic RCA Findings ({total_anomalies} anomalies isolated)")

            if total_anomalies == 0:
                st.success("✅ No signaling anomalies detected across correlated sessions.")
            else:
                for s in sessions:
                    if s.anomalies:
                        st.markdown(f"**Session `{s.session_id}`** (ANI: `{s.calling_number or '-'}` ➔ DNIS: `{s.called_number or '-'}`):")
                        for anom in s.anomalies:
                            card_class = "anomaly-card-error" if anom.severity.value == "ERROR" else "anomaly-card-warning"
                            st.markdown(
                                f"""
                                <div class="{card_class}">
                                    <strong>[{anom.protocol.value} | {anom.category.value}] {anom.severity.value}</strong><br/>
                                    {anom.description}<br/>
                                    <small>Expected: <code>{anom.expected_message or 'N/A'}</code></small>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )


    # =========================================================================
    # TAB 8: CUCM Device
    # =========================================================================
    with tab_cucm:
        st.markdown("### CUCM Device Integration")
        st.caption("Connect to live CUCM via SSH for version detection and SDL trace discovery.")

        if not settings.cucm_host or not settings.cucm_username:
            st.warning("⚠️ CUCM not configured. Set CUCM_HOST, CUCM_USERNAME, CUCM_PASSWORD in .env")
        else:
            cucm_client = get_cucm_client()

            connected = st.session_state.get("cucm_connected", False)
            status_color = "🟢" if connected else "🔴"
            st.markdown(f"**Connection Status:** {status_color} {'Connected' if connected else 'Disconnected'}")

            if "cucm_version" in st.session_state:
                ver = st.session_state["cucm_version"]
                st.markdown("#### CUCM Version")
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Version", ver.get("version", "N/A"))
                with c2:
                    st.metric("Build", ver.get("build", "N/A"))
                with c3:
                    st.metric("Edition", ver.get("edition", "N/A"))

            if "cucm_diagnostic" in st.session_state:
                diag = st.session_state["cucm_diagnostic"]
                st.markdown("#### Diagnostic Results")
                for key, value in diag.items():
                    if key == "overall":
                        continue
                    status = value.get("status", "UNKNOWN")
                    details = value.get("details", "")
                    icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "❓"
                    st.markdown(f"{icon} **{key.replace('_', ' ').title()}**: {details}")

            # Time-based Trace Selection Results
            if "cucm_trace_selection" in st.session_state:
                selection = st.session_state["cucm_trace_selection"]
                st.markdown("---")
                st.markdown("#### ⏱️ Trace Selection Result")

                mode = selection.get("mode", "unknown")
                st.markdown(f"**Mode:** `{mode}`")

                start_time = selection.get("start_time")
                end_time = selection.get("end_time")
                if start_time and end_time:
                    st.markdown(f"**Requested Window:** `{start_time}` → `{end_time}`")

                candidates = selection.get("candidate_files", [])
                total_candidates = selection.get("total_candidates", 0)
                est_size_mb = selection.get("estimated_size_mb", 0)

                st.markdown(f"**Candidate Files:** {total_candidates}  |  **Estimated Size:** {est_size_mb:.2f} MB")

                if candidates:
                    st.markdown("##### Matching SDL Trace Files")
                    cucm_host = settings.cucm_host

                    if "cucm_selected_candidates" not in st.session_state:
                        st.session_state["cucm_selected_candidates"] = set()

                    col_sel1, col_sel2, _ = st.columns([1, 1, 2])
                    with col_sel1:
                        if st.button("☑ Select All", key="cucm_cand_sel_all", use_container_width=True):
                            st.session_state["cucm_selected_candidates"] = {f["filename"] for f in candidates}
                            st.rerun()
                    with col_sel2:
                        if st.button("☐ Clear Selection", key="cucm_cand_clr_all", use_container_width=True):
                            st.session_state["cucm_selected_candidates"] = set()
                            st.rerun()

                    selected_candidates = set()
                    for i, f in enumerate(candidates):
                        filename = f["filename"]
                        size_mb = f.get("size_mb", 0)
                        modified = f.get("modified", "N/A")
                        trace_type = f.get("trace_type", "SDL")

                        if filename.endswith(".txt.gzo"):
                            type_display = "Active SDL (.gzo)"
                        elif filename.endswith(".txt.gz"):
                            type_display = "Compressed SDL (.gz)"
                        elif filename.endswith(".txt"):
                            type_display = "Plain SDL (.txt)"
                        elif filename.endswith(".index"):
                            type_display = "Index (.index)"
                        else:
                            type_display = trace_type

                        col_check, col_info = st.columns([1, 11])
                        with col_check:
                            is_index = filename.endswith(".index")
                            checked = st.checkbox(
                                "",
                                key=f"cucm_candidate_{i}",
                                value=filename in st.session_state["cucm_selected_candidates"],
                                disabled=is_index,
                            )
                            if checked and not is_index:
                                selected_candidates.add(filename)
                        with col_info:
                            st.markdown(
                                f"**{filename}**  \n"
                                f"Node: `{cucm_host}`  \n"
                                f"CUCM Timestamp: `{modified}`  \n"
                                f"Type: `{type_display}`  \n"
                                f"Size: `{size_mb:.2f} MB`"
                            )

                    st.session_state["cucm_selected_candidates"] = selected_candidates

                    disabled_download = len(selected_candidates) == 0
                    if st.button(
                        "📥 Download Selected Traces",
                        type="primary",
                        disabled=disabled_download,
                        key="btn_download_selected_cucm",
                        use_container_width=True,
                    ):
                        if not cucm_client.is_connected():
                            with st.spinner("Connecting to CUCM..."):
                                try:
                                    cucm_client.connect()
                                except Exception as e:
                                    st.error(f"Connection failed: {e}")
                                    st.stop()

                        collector = CUCMTraceCollector(client=cucm_client)
                        selected_files = [f for f in candidates if f["filename"] in selected_candidates]

                        trace_file_objects = []
                        for f in selected_files:
                            try:
                                modified_dt = datetime.fromisoformat(f["modified"]) if f.get("modified") else datetime.now()
                            except Exception:
                                modified_dt = datetime.now()
                            trace_file_objects.append(
                                CUCMTraceFile(
                                    filename=f["filename"],
                                    path=f"activelog/cm/trace/ccm/sdl/{f['filename']}",
                                    size_bytes=f.get("size_bytes", 0),
                                    modified=modified_dt,
                                    trace_type=f.get("trace_type", "SDL_TRACE"),
                                )
                            )

                        selection_obj = SelectionResult(
                            request=SelectionRequest(mode=SelectionMode(mode)),
                            candidate_files=trace_file_objects,
                            start_time=datetime.fromisoformat(start_time) if start_time else datetime.now(),
                            end_time=datetime.fromisoformat(end_time) if end_time else datetime.now(),
                            total_candidates=len(trace_file_objects),
                            estimated_size_bytes=sum(f.size_bytes for f in trace_file_objects),
                        )

                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        download_results = []

                        def update_progress(res):
                            download_results.append(res)
                            status_text.text(f"Collected: {res.filename} ({'✅' if res.success else '❌'})")

                        with st.spinner(f"Downloading {len(selected_files)} file(s) via SFTP..."):
                            collected = collector.collect_selected_traces(
                                selection_obj,
                                progress_callback=update_progress,
                            )
                            progress_bar.progress(1.0)

                        st.session_state["last_cucm_collected"] = collected

                    # Display Collection Results & Artifacts
                    last_collected = st.session_state.get("last_cucm_collected", [])
                    if last_collected:
                        st.markdown("---")
                        st.markdown("##### Trace Artifacts & Collection Results")

                        success_count = sum(1 for r in last_collected if r.success)
                        fail_count = len(last_collected) - success_count

                        for res in last_collected:
                            render_trace_artifact_card(res, artifact_repo, key_prefix="cucm_sel_card")

                        if success_count > 0:
                            st.success(f"Downloaded {success_count}/{len(last_collected)} file(s) successfully.")
                            if st.button("🔄 Ingest Downloaded Traces", key="ingest_cucm_collected_btn", type="primary"):
                                valid_manifests = [r.manifest for r in last_collected if r.success and r.manifest]
                                with st.spinner("Ingesting downloaded traces into Analysis Workspace..."):
                                    ws = pipeline_service.ingest_manifests(valid_manifests)
                                    st.session_state["analysis_workspace"] = ws
                                    st.session_state["parsed_events"] = ws.events
                                    st.session_state["correlated_sessions"] = ws.call_sessions
                                    st.session_state["uploaded_file_names"] = ws.source_files
                                st.success(f"Ingested {len(valid_manifests)} trace(s) into {len(ws.call_sessions)} CallSession(s)!")
                                st.rerun()

                        if fail_count > 0:
                            st.error(f"{fail_count} file(s) failed to download.")

            # Discover all SDL files table
            if "cucm_sdl_files" in st.session_state:
                files = st.session_state["cucm_sdl_files"]
                st.markdown(f"#### SDL Trace Files ({len(files)} found)")

                if files:
                    df = pd.DataFrame(files)
                    st.dataframe(
                        df[["filename", "size_mb", "modified", "trace_type"]],
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "filename": st.column_config.TextColumn("Filename", width="large"),
                            "size_mb": st.column_config.NumberColumn("Size (MB)", width="small"),
                            "modified": st.column_config.TextColumn("Modified", width="medium"),
                            "trace_type": st.column_config.TextColumn("Type", width="small"),
                        },
                    )

    # =========================================================================
    # TAB 10: Device Command Center
    # =========================================================================
    with tab_commands:
        st.markdown("### ⚡ Device Command Center")
        st.caption("Engineer's interactive CLI console for Cisco Unified Communications Manager and Cisco IOS/IOS-XE Voice Gateways.")

        st.markdown(
            '<div class="disclaimer-banner">🔒 <strong>Read-Only Guardrails Active:</strong> Configuration, state-altering, and destructive commands are blocked. Sensitive tokens, passwords, and cryptographic keys are masked automatically.</div>',
            unsafe_allow_html=True,
        )

        col_left, col_right = st.columns([1, 1.4])

        with col_left:
            st.markdown("#### Command Parameters")

            device_type_choice = st.selectbox(
                "Target Device Type",
                ["CUCM (Cisco Unified Communications Manager)", "IOS Voice Gateway (Cisco IOS / IOS-XE)"],
                key="cmd_device_choice",
            )
            is_cucm = "CUCM" in device_type_choice
            target_device = DeviceTypeEnum.CUCM if is_cucm else DeviceTypeEnum.IOS

            default_host = settings.cucm_host if is_cucm else (settings.gateway_host or "10.10.10.1")
            target_host = st.text_input("Target Host (IP or FQDN)", value=default_host or "", key="cmd_target_host")

            st.markdown("##### Quick Command Suggestions")
            if is_cucm:
                suggestions = [
                    "show version active",
                    "show status",
                    "utils service status",
                    "show network eth0",
                    "file list activelog /cm/trace/ccm/sdl detail",
                ]
            else:
                suggestions = [
                    "show version",
                    "show isdn status",
                    "show dial-peer voice summary",
                    "show voice port summary",
                    "show sip-ua status",
                    "show call active voice",
                    "show controllers t1",
                ]

            # Detect device type change and update command default
            if st.session_state.get("last_selected_device") != target_device.value:
                st.session_state["last_selected_device"] = target_device.value
                st.session_state["cli_command_text"] = "show version active" if is_cucm else "show version"

            if "cli_command_text" not in st.session_state:
                st.session_state["cli_command_text"] = "show version active" if is_cucm else "show version"

            pill_cols = st.columns(min(len(suggestions), 4))
            for i, s in enumerate(suggestions[:4]):
                with pill_cols[i]:
                    if st.button(s, key=f"sug_btn_{target_device.value}_{i}", use_container_width=True):
                        st.session_state["cli_command_text"] = s
                        st.rerun()

            cmd_input = st.text_input(
                "Command to Execute",
                key="cli_command_text",
            )

            cmd_timeout = st.slider("Command Timeout (seconds)", min_value=5, max_value=120, value=30, step=5, key="cmd_timeout")

            if st.button("🚀 Run Command", type="primary", use_container_width=True, key="btn_run_cmd"):
                if not target_host:
                    st.error("Please specify target host IP or FQDN.")
                elif not cmd_input:
                    st.error("Please enter a command to execute.")
                else:
                    with st.spinner(f"Executing command on {target_device.value} ({target_host})..."):
                        req = CommandRequest(
                            device_type=target_device,
                            host=target_host,
                            command=cmd_input,
                            timeout=cmd_timeout,
                        )
                        resp = command_service.execute(req)
                        st.session_state["last_command_response"] = resp.model_dump(mode="json")

        with col_right:
            st.markdown("#### Device Response Terminal")

            last_resp_dict = st.session_state.get("last_command_response")
            if last_resp_dict:
                status_icon = "✅" if last_resp_dict.get("success") else "❌"
                status_text = "SUCCESS" if last_resp_dict.get("success") else ("BLOCKED" if "blocked" in (last_resp_dict.get("error") or "").lower() else "FAILED")
                dev_str = last_resp_dict.get("device_type", "CUCM")
                ip_str = last_resp_dict.get("host", target_host)
                cmd_run = last_resp_dict.get("command", "")
                ts_str = last_resp_dict.get("timestamp", "")[:19].replace("T", " ")
                prompt = last_resp_dict.get("prompt") or ("admin:" if dev_str == "CUCM" else "Gateway#")
                output_text = last_resp_dict.get("output", "")
                error_text = last_resp_dict.get("error")

                st.markdown(
                    f"""
                    <div style="background:#0F172A; border:1px solid #334155; border-radius:6px; padding:0.8rem 1rem; margin-bottom:0.8rem;">
                        <h4 style="margin:0 0 0.5rem 0; color:#38BDF8;">COMMAND EXECUTION</h4>
                        <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap: 0.4rem; font-size:0.9rem;">
                            <div><strong>Device:</strong> <code>{dev_str}</code></div>
                            <div><strong>IP:</strong> <code>{ip_str}</code></div>
                            <div><strong>Timestamp:</strong> <code>{ts_str}</code></div>
                            <div><strong>Status:</strong> {status_icon} <code>{status_text}</code></div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if error_text:
                    st.error(f"⚠️ {error_text}")

                st.markdown("**REQUEST**")
                st.code(cmd_run, language="text")

                st.markdown("**RESPONSE**")
                full_terminal = f"{prompt}{cmd_run}\n{output_text}" if output_text else f"{prompt}{cmd_run}\n(No output or execution failed)"
                st.code(full_terminal, language="text")

                # Formatted Export Download
                download_package = format_command_output_package(
                    device_type=dev_str,
                    ip=ip_str,
                    command=cmd_run,
                    status=status_text,
                    output=output_text or (error_text or ""),
                    prompt=prompt,
                    timestamp_str=ts_str,
                )
                dl_filename = generate_command_filename(dev_str, ip_str, cmd_run)

                btn_col1, _ = st.columns([1.3, 1])
                with btn_col1:
                    st.download_button(
                        "📥 Download Output",
                        data=download_package.encode("utf-8"),
                        file_name=dl_filename,
                        mime="text/plain",
                        key="dl_cmd_output",
                        use_container_width=True,
                    )
            else:
                st.info("💡 Run a command on the left to inspect device output here.")

        # Command History Ledger
        st.markdown("---")
        hist_head_col1, hist_head_col2 = st.columns([4, 1.2])
        with hist_head_col1:
            st.markdown("#### 📜 Command Execution History")
        with hist_head_col2:
            if st.button("🔄 Refresh Commands", key="refresh_commands_btn", use_container_width=True):
                st.rerun()

        history_entries = command_service.history.get_entries()

        if not history_entries:
            st.caption("No commands executed in this session yet.")
        else:
            hist_rows = [
                {
                    "Time": e.timestamp,
                    "Device": e.device_type,
                    "Host": e.host,
                    "Command": e.command,
                    "Duration": f"{e.execution_time_seconds:.3f}s",
                    "Status": e.status,
                }
                for e in history_entries
            ]
            st.dataframe(pd.DataFrame(hist_rows), use_container_width=True, hide_index=True)

            with st.expander("🔍 Inspect Historical Command Outputs"):
                hist_labels = [
                    f"[{e.timestamp}] {e.device_type} - {e.command} ({e.status})"
                    for e in history_entries
                ]
                sel_hist_idx = st.selectbox("Select historical execution", range(len(history_entries)), format_func=lambda i: hist_labels[i], key="hist_sel")
                selected_entry = history_entries[sel_hist_idx]

                st.markdown(f"**Request:** `{selected_entry.command}` on `{selected_entry.host}`")
                if selected_entry.error:
                    st.warning(f"Error: {selected_entry.error}")
                if selected_entry.output:
                    st.code(selected_entry.output, language="text")

                # Download output button for history item
                hist_dl_pkg = format_command_output_package(
                    device_type=selected_entry.device_type,
                    ip=selected_entry.host,
                    command=selected_entry.command,
                    status=selected_entry.status,
                    output=selected_entry.output or (selected_entry.error or ""),
                    prompt="admin:" if selected_entry.device_type == "CUCM" else "Gateway#",
                    timestamp_str=selected_entry.timestamp,
                )
                hist_filename = generate_command_filename(selected_entry.device_type, selected_entry.host, selected_entry.command)
                st.download_button(
                    "📥 Download Output for Selected History",
                    data=hist_dl_pkg.encode("utf-8"),
                    file_name=hist_filename,
                    mime="text/plain",
                    key=f"dl_hist_{selected_entry.entry_id}",
                )


if __name__ == "__main__":
    main()

