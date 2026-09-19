"""VoiceOps AI - Enterprise Cisco Voice Troubleshooting Platform (Streamlit UI)."""

import json
import sys
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

        cucm_status = "Configured" if settings.cucm_host else "Not connected (Local offline mode)"
        st.markdown(f"**CUCM Status:** `{cucm_status}`")

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
    tab_upload, tab_sessions, tab_timeline, tab_protocols, tab_inspector, tab_architecture = st.tabs(
        [
            "📁 Trace Upload",
            "📞 Call Sessions",
            "⏱️ Unified Timeline",
            "📊 Protocol View",
            "🔍 Event Inspector",
            "🏗️ Architecture & RCA",
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

    if not events:
        st.info("💡 No trace events loaded yet. Upload files above or click **'Load Bundled Samples'** in the left sidebar to explore.")
        return

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
        st.markdown("### Detailed Event & Raw Trace Inspector")
        st.caption("Select an individual signaling event to view structured attributes and verbatim trace text.")

        if events:
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


if __name__ == "__main__":
    main()
