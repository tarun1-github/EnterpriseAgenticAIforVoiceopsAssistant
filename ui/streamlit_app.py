"""VoiceOps AI - Enterprise Cisco Voice Troubleshooting Platform (Streamlit UI)."""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List

# Ensure workspace root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import streamlit as st
from app.analysis.anomaly_detector import AnomalyDetector
from app.analysis.evidence_builder import build_evidence_pack
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.correlation.engine import CorrelationEngine
from app.devices.cucm import CUCMClient, CUCMTraceCollector, TraceSelectionService, SelectionMode, RelativeTimeOption
from app.devices.cucm.selection import SelectionResult, SelectionRequest
from app.devices.cucm.models import CUCMTraceFile
from app.models.call_session import CallSession
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent
from app.parsers.detector import detect_protocol
from app.parsers.ingestion import TraceIngestionEngine

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


def main():
    settings = get_settings()
    ingestion_engine = get_ingestion_engine()
    correlation_engine = get_correlation_engine()

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
                    index=2,  # Default to 15 minutes
                    key="cucm_relative_time",
                )
                # Show calculated window
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
            all_events: List[VoiceEvent] = []
            for name, content in samples:
                events = ingestion_engine.ingest_content(content, source=name)
                all_events.extend(events)

            st.session_state["parsed_events"] = all_events
            st.session_state["uploaded_file_names"] = [s[0] for s in samples]

            # Correlate sessions
            with st.spinner("Correlating multi-protocol calls..."):
                sessions = correlation_engine.correlate(all_events)
                st.session_state["correlated_sessions"] = sessions

            st.success(f"Loaded {len(samples)} trace files ({len(all_events)} events, {len(sessions)} correlated sessions)!")

        if st.button("🗑️ Clear All Traces", use_container_width=True):
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

    # Ingestion Tabs
    tab_upload, tab_sessions, tab_timeline, tab_protocols, tab_inspector, tab_architecture, tab_cucm = st.tabs(
        [
            "📁 Trace Upload",
            "📞 Call Sessions",
            "⏱️ Unified Timeline",
            "📊 Protocol View",
            "🔍 Event Inspector",
            "🏗️ Architecture & RCA",
            "🖥️ CUCM Device",
        ]
    )

    # --- TAB 1: Trace Upload ---
    with tab_upload:
        st.markdown("### Upload Cisco Trace Log Files")
        st.markdown(
            "Upload one or more raw Cisco debug files (`.txt`). Supported signaling traces include "
            "`debug isdn q931`, `debug ccsip messages`, `debug mgcp packets`, mixed gateway logs, and `CUCM SDL/SDI`."
        )

        uploaded_files = st.file_uploader(
            "Select Cisco trace files",
            type=["txt", "log"],
            accept_multiple_files=True,
            help="Upload raw router/CUCM trace text dumps",
        )

        if st.button("🚀 Ingest & Correlate Traces", type="primary", use_container_width=False):
            if uploaded_files:
                combined_events: List[VoiceEvent] = []
                file_names: List[str] = []
                with st.spinner("Executing deterministic parsers and correlation engine..."):
                    for uf in uploaded_files:
                        content = uf.read().decode("utf-8", errors="replace")
                        file_names.append(uf.name)
                        events = ingestion_engine.ingest_content(content, source=uf.name)
                        combined_events.extend(events)

                    sessions = correlation_engine.correlate(combined_events)

                st.session_state["parsed_events"] = combined_events
                st.session_state["uploaded_file_names"] = file_names
                st.session_state["correlated_sessions"] = sessions
                st.success(f"Processed {len(uploaded_files)} file(s). Extracted {len(combined_events)} events into {len(sessions)} CallSession(s).")
            else:
                st.warning("Please select at least one file or use 'Load Bundled Samples' in the sidebar.")

        # Show current uploaded files status
        if "uploaded_file_names" in st.session_state:
            st.markdown("#### Currently Active Files:")
            for fname in st.session_state["uploaded_file_names"]:
                st.markdown(f"- 📄 `{fname}`")

    # Retrieve events & sessions from session state
    events: List[VoiceEvent] = st.session_state.get("parsed_events", [])
    sessions: List[CallSession] = st.session_state.get("correlated_sessions", [])

    # Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events", len(events))
    with col2:
        st.metric("Correlated Sessions", len(sessions))
    with col3:
        isdn_count = sum(1 for e in events if e.protocol == ProtocolEnum.ISDN)
        st.metric("ISDN Q.931", isdn_count)
    with col4:
        sip_count = sum(1 for e in events if e.protocol == ProtocolEnum.SIP)
        st.metric("SIP Messages", sip_count)
    with col5:
        mgcp_count = sum(1 for e in events if e.protocol == ProtocolEnum.MGCP)
        st.metric("MGCP Packets", mgcp_count)

    st.markdown("---")

    # --- TAB 2: Call Sessions View ---
    with tab_sessions:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files above or click **'Load Bundled Samples'** in the left sidebar to explore.")
        else:
            st.markdown(
                '<div class="disclaimer-banner">ℹ️ <strong>Deterministic analysis — LLM RCA not enabled in this phase.</strong> All sessions and anomalies below are derived purely from multi-signal deterministic rules.</div>',
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

            # Session Header Info
            mcol1, mcol2, mcol3, mcol4 = st.columns(4)
            with mcol1:
                st.markdown(f"**Architecture:** `{selected_session.architecture.value}`")
            with mcol2:
                st.markdown(f"**Correlation Confidence:** `{int(selected_session.correlation_confidence * 100)}%`")
            with mcol3:
                st.markdown(f"**Call Reference(s):** `{', '.join(selected_session.isdn_call_references) or 'None'}`")
            with mcol4:
                st.markdown(f"**SIP Call-ID(s):** `{', '.join(selected_session.sip_call_ids) or 'None'}`")

            # Drill-Down Sub-Tabs
            s_tab_timeline, s_tab_protocols, s_tab_evidence, s_tab_anomalies, s_tab_pack = st.tabs(
                [
                    "⏱️ Unified Call Timeline",
                    "📊 Protocols",
                    "🔗 Correlation Evidence",
                    "⚠️ Detected Anomalies",
                    "📦 JSON Evidence Pack",
                ]
            )

            # Sub-Tab 1: Unified Timeline for this session
            with s_tab_timeline:
                s_events = [ev.to_summary_dict() for ev in selected_session.events]
                if s_events:
                    st.dataframe(pd.DataFrame(s_events), use_container_width=True, hide_index=True)

            # Sub-Tab 2: Protocol Breakdown
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

            # Sub-Tab 3: Correlation Evidence
            with s_tab_evidence:
                st.markdown("##### Signals Matched Across Protocols:")
                if selected_session.correlation_evidence:
                    for ev_item in selected_session.correlation_evidence:
                        st.markdown(f"- 🔗 {ev_item}")
                else:
                    st.caption("Single initial event; no multi-signal correlation required.")

            # Sub-Tab 4: Detected Anomalies
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

            # Sub-Tab 5: Evidence Pack JSON
            with s_tab_pack:
                st.markdown("##### Machine-Readable Evidence Pack (Structured for LLM Agent):")
                pack = build_evidence_pack(selected_session)
                st.json(pack.model_dump(mode="json"))

    # --- TAB 3: Global Event Timeline ---
    with tab_timeline:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files above or click **'Load Bundled Samples'** in the left sidebar to explore.")
        else:
            st.markdown("### Unified Chronological Timeline (All Events)")

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

# --- TAB 4: Protocol View ---
    with tab_protocols:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files above or click **'Load Bundled Samples'** in the left sidebar to explore.")
        else:
            st.markdown("### Global Protocol Summary Breakdown")
            proto_cols = st.columns(3)
            with proto_cols[0]:
                st.markdown("#### 🔵 ISDN / Q.931")
                isdn_events = [e for e in events if e.protocol == ProtocolEnum.ISDN]
                if isdn_events:
                    for ev in isdn_events:
                        icon = "📥" if ev.direction == DirectionEnum.INBOUND else "📤"
                        st.markdown(f"{icon} **{ev.message_type}** `callref={ev.call_reference}`")
                else:
                    st.caption("No ISDN events detected.")

            with proto_cols[1]:
                st.markdown("#### 🟠 MGCP Packets")
                mgcp_events = [e for e in events if e.protocol == ProtocolEnum.MGCP]
                if mgcp_events:
                    for ev in mgcp_events:
                        icon = "📥" if ev.direction == DirectionEnum.INBOUND else "📤"
                        st.markdown(f"{icon} **{ev.message_type}** `trans={ev.transaction_id}`")
                else:
                    st.caption("No MGCP events detected.")

            with proto_cols[2]:
                st.markdown("#### 🟢 SIP Messages")
                sip_events = [e for e in events if e.protocol == ProtocolEnum.SIP]
                if sip_events:
                    for ev in sip_events:
                        icon = "📥" if ev.direction == DirectionEnum.INBOUND else "📤"
                        st.markdown(f"{icon} **{ev.message_type}** `{ev.calling_number or '-'} ➔ {ev.called_number or '-'}`")
                else:
                    st.caption("No SIP events detected.")

# --- TAB 5: Event Inspector ---
    with tab_inspector:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files above or click **'Load Bundled Samples'** in the left sidebar to explore.")
        else:
            st.markdown("### Detailed Event & Raw Trace Inspector")
            st.caption("Select an individual signaling event to view structured attributes and verbatim trace text.")

            event_labels = [
                f"[{i+1}/{len(events)}] {e.protocol.value} | {e.message_type} | {e.timestamp_raw or 'No TS'} | {e.calling_number or ''}->{e.called_number or ''}"
                for i, e in enumerate(events)
            ]
            selected_idx = st.selectbox("Choose Event to Inspect", range(len(events)), format_func=lambda i: event_labels[i])
            sel_event = events[selected_idx]

            col_details, col_raw = st.columns([1, 1])
            with col_details:
                st.markdown("#### Structured Event Attributes")
                st.json(
                    {
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
                        "metadata": sel_event.metadata,
                    }
                )

            with col_raw:
                st.markdown("#### Verbatim Raw Trace Block")
                st.code(sel_event.raw, language="text")

    # --- TAB 6: Architecture & RCA ---
    with tab_architecture:
        if not events:
            st.info("💡 No trace events loaded yet. Upload files above or click **'Load Bundled Samples'** in the left sidebar to explore.")
        else:
            st.markdown("### Call Architecture & Progression")

            st.markdown(
                """
                <div class="call-flow-diagram">
                PSTN  ──[ISDN Q.931]──▶  Voice Gateway (VGR)  ──[MGCP / SIP]──▶  CUCM 15.0  ──[SIP]──▶  CIPC / SIP Phone
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("#### Detected Call Leg Distribution")
            st.markdown(
                f"""
                - **ISDN Ingress**: `{isdn_count}` signaling frame(s) identified on PRI interface.
                - **Gateway Control**: `{mgcp_count}` MGCP transaction(s) between Gateway and CallManager.
                - **CUCM Egress**: `{sip_count}` SIP packet(s) between CUCM and destination endpoint.
                """
            )

            st.info(
                "ℹ️ **Phase 1 Status**: Deterministic parsing, multi-signal call correlation, and rule-based anomaly detection are fully active.\n\n"
                "The **LangGraph Evidence-Driven RCA Agent** will receive the structured `EvidencePack` in the next milestone to reason over anomalies and recommend diagnostic next steps."
            )

# --- TAB 7: CUCM Device ---
    with tab_cucm:
        st.markdown("### CUCM Device Integration")
        st.caption("Connect to live CUCM via SSH for version detection and SDL trace discovery.")

        if not settings.cucm_host or not settings.cucm_username:
            st.warning("⚠️ CUCM not configured. Set CUCM_HOST, CUCM_USERNAME, CUCM_PASSWORD in .env")
        else:
            cucm_client = get_cucm_client()

            # Connection status
            connected = st.session_state.get("cucm_connected", False)
            status_color = "🟢" if connected else "🔴"
            st.markdown(f"**Connection Status:** {status_color} {'Connected' if connected else 'Disconnected'}")

            # Version info
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
                with st.expander("Raw Output"):
                    st.code(ver.get("raw_output", ""))

            # Diagnostic results
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

                overall_icon = "✅" if diag.get("overall") == "READY" else "⚠️" if diag.get("overall") == "PARTIAL" else "❌"
                st.markdown(f"**Overall: {overall_icon} {diag.get('overall', 'UNKNOWN')}**")

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

                    # CUCM node/host for display
                    cucm_host = settings.cucm_host

                    # Initialize selection state for checkboxes
                    if "cucm_selected_candidates" not in st.session_state:
                        st.session_state["cucm_selected_candidates"] = set()

                    # Selection controls
                    col_sel1, col_sel2, col_sel3 = st.columns([1, 1, 2])
                    with col_sel1:
                        if st.button("☑ Select All", use_container_width=True):
                            st.session_state["cucm_selected_candidates"] = {f["filename"] for f in candidates}
                            st.rerun()
                    with col_sel2:
                        if st.button("☐ Clear Selection", use_container_width=True):
                            st.session_state["cucm_selected_candidates"] = set()
                            st.rerun()

                    selected_candidates = set()
                    for i, f in enumerate(candidates):
                        filename = f["filename"]
                        size_mb = f.get("size_mb", 0)
                        modified = f.get("modified", "N/A")
                        trace_type = f.get("trace_type", "SDL")

                        # Format file type display
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
                            # Skip .index files - they cannot be selected
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

                    # Update session state with selected candidates
                    st.session_state["cucm_selected_candidates"] = selected_candidates

                    # Download button - disabled when nothing selected
                    disabled_download = len(selected_candidates) == 0
                    if st.button(
                        "📥 Download Selected Traces",
                        type="primary",
                        disabled=disabled_download,
                        use_container_width=True,
                    ):
                        if not cucm_client.is_connected():
                            with st.spinner("Connecting to CUCM..."):
                                try:
                                    cucm_client.connect()
                                except Exception as e:
                                    st.error(f"Connection failed: {e}")
                                    st.stop()

                        # Use the collector to download selected files
                        collector = CUCMTraceCollector(client=cucm_client)

                        # Reconstruct SelectionResult with only selected files
                        selected_files = [f for f in candidates if f["filename"] in selected_candidates]

                        # Build a SelectionResult-like object for collect_selected_traces
                        # We need CUCMTraceFile objects
                        from app.devices.cucm.models import CUCMTraceFile

                        trace_file_objects = []
                        for f in selected_files:
                            try:
                                modified_dt = datetime.fromisoformat(f["modified"]) if f.get("modified") else datetime.now()
                            except Exception:
                                modified_dt = datetime.now()
                            trace_file_objects.append(CUCMTraceFile(
                                filename=f["filename"],
                                path=f"activelog/cm/trace/ccm/sdl/{f['filename']}",
                                size_bytes=f.get("size_bytes", 0),
                                modified=modified_dt,
                                trace_type=f.get("trace_type", "SDL_TRACE"),
                            ))

                        # Create a minimal SelectionResult for the collector
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

                        def update_progress(result):
                            download_results.append(result)
                            status_text.text(f"Collected: {result.filename} ({'✅' if result.success else '❌'})")

                        with st.spinner(f"Downloading {len(selected_files)} file(s)..."):
                            collected = collector.collect_selected_traces(
                                selection_obj,
                                progress_callback=update_progress,
                            )
                            progress_bar.progress(1.0)

                        # Display download results
                        st.markdown("---")
                        st.markdown("##### Download Results")

                        success_count = sum(1 for r in collected if r.success)
                        fail_count = len(collected) - success_count

                        for result in collected:
                            if result.success:
                                st.markdown(
                                    f"✅ **Downloaded**  \n"
                                    f"Filename: `{result.filename}`  \n"
                                    f"Node: `{cucm_host}`  \n"
                                    f"Local Path: `{result.local_path}`  \n"
                                    f"Remote Size: `{result.size_bytes:,} bytes`  \n"
                                    f"Local Size: `{result.local_path.stat().st_size if result.local_path and result.local_path.exists() else 0:,} bytes`  \n"
                                    f"Validation: **OK** (size matches)"
                                )
                            else:
                                st.markdown(
                                    f"❌ **Failed**  \n"
                                    f"Filename: `{result.filename}`  \n"
                                    f"Node: `{cucm_host}`  \n"
                                    f"Error: `{result.error}`"
                                )
                                st.markdown("---")

                        if success_count > 0:
                            st.success(f"Downloaded {success_count}/{len(collected)} files successfully")

                            # Auto-ingest option
                            if st.button("🔄 Ingest Downloaded Traces", key="ingest_after_download"):
                                ingestion_engine = get_ingestion_engine()
                                correlation_engine = get_correlation_engine()
                                all_events = []
                                for result in collected:
                                    if result.success and result.local_path:
                                        content = result.local_path.read_text(encoding="utf-8", errors="replace")
                                        events = ingestion_engine.ingest_content(content, source=result.filename)
                                        all_events.extend(events)

                                sessions = correlation_engine.correlate(all_events)
                                st.session_state["parsed_events"] = all_events
                                st.session_state["correlated_sessions"] = sessions
                                st.success(f"Ingested {len(all_events)} events into {len(sessions)} session(s)")
                                st.rerun()

                        if fail_count > 0:
                            st.error(f"{fail_count} file(s) failed to download")

                else:
                    st.info("No candidate files match the selected time window.")

            # SDL Files (full discovery)
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

                    # Collection section
                    st.markdown("---")
                    st.markdown("#### Collect Trace Files")
                    st.caption("Downloads selected SDL files to local storage for analysis.")

                    selected_files = st.multiselect(
                        "Select files to collect",
                        options=[f["filename"] for f in files],
                        default=[f["filename"] for f in files[:5]],
                    )

                    if st.button("📥 Collect Selected Files", type="primary"):
                        if selected_files:
                            collector = CUCMTraceCollector(client=cucm_client)
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            results = []

                            def update_progress(result):
                                results.append(result)
                                status_text.text(f"Collected: {result.filename} ({'✅' if result.success else '❌'})")

                            with st.spinner(f"Collecting {len(selected_files)} file(s)..."):
                                collected = collector.collect_multiple(
                                    selected_files,
                                    progress_callback=update_progress,
                                )
                                progress_bar.progress(1.0)

                            success_count = sum(1 for r in collected if r.success)
                            st.success(f"Collected {success_count}/{len(collected)} files successfully")

                            # Auto-ingest collected files
                            if success_count > 0:
                                if st.button("🔄 Ingest Collected Traces"):
                                    ingestion_engine = get_ingestion_engine()
                                    correlation_engine = get_correlation_engine()
                                    all_events = []
                                    for result in collected:
                                        if result.success and result.local_path:
                                            content = result.local_path.read_text(encoding="utf-8", errors="replace")
                                            events = ingestion_engine.ingest_content(content, source=result.filename)
                                            all_events.extend(events)

                                    sessions = correlation_engine.correlate(all_events)
                                    st.session_state["parsed_events"] = all_events
                                    st.session_state["correlated_sessions"] = sessions
                                    st.success(f"Ingested {len(all_events)} events into {len(sessions)} session(s)")
                                    st.rerun()
                else:
                    st.info("No SDL trace files found in the default directory.")


if __name__ == "__main__":
    main()
