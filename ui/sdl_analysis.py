"""Streamlit UI component for dedicated CUCM SDL Trace Analysis."""

from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import List, Optional
from zoneinfo import ZoneInfo
import pandas as pd
import streamlit as st

from app.agents.models import RCAResult
from app.agents.sdl_analyst import SDLAnalystAgent
from app.artifacts.repository import TraceArtifactRepository
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.timestamps import IST_TZ
from app.devices.cucm.client import CUCMClient
from app.devices.cucm.collector import CUCMTraceCollector
from app.devices.cucm.sdl.call_index import CallIndex
from app.devices.cucm.sdl.correlator import SDLCallCorrelator
from app.devices.cucm.sdl.evidence import build_evidence_pack
from app.devices.cucm.sdl.models import Call, SDLEvent
from app.devices.cucm.sdl.parser import SDLParser
from app.knowledge.retriever import InMemoryKnowledgeRetriever

logger = get_logger("ui.sdl_analysis")


@st.cache_resource
def get_sdl_analyst_agent() -> SDLAnalystAgent:
    retriever = InMemoryKnowledgeRetriever()
    return SDLAnalystAgent(retriever=retriever)


def discover_available_sdl_files() -> List[Path]:
    """Find all extracted or local CUCM SDL trace files."""
    settings = get_settings()
    storage_root = Path(settings.voiceops_trace_storage)
    extracted_dir = storage_root / "extracted"

    files = []
    if extracted_dir.exists():
        files.extend(list(extracted_dir.rglob("*.txt")))

    # Also check repo root sample_data
    repo_root = Path(__file__).resolve().parent.parent
    sample_dir = repo_root / "data" / "voiceops_traces" / "extracted"
    if sample_dir.exists() and sample_dir != extracted_dir:
        for f in sample_dir.rglob("*.txt"):
            if f not in files:
                files.append(f)

    return sorted(files, key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)


def parse_and_index_traces(trace_files: List[Path]) -> CallIndex:
    """Parse trace files with SDLParser and build CallIndex using SDLCallCorrelator."""
    parser = SDLParser()
    correlator = SDLCallCorrelator()
    index = CallIndex()

    all_events: List[SDLEvent] = []
    for tf in trace_files[:5]:  # Limit to 5 newest traces for snappy response
        events = parser.parse_file(tf)
        all_events.extend(events)

    if all_events:
        calls = correlator.correlate(all_events)
        index.add_calls(calls)

    return index


def render_sdl_analysis_tab(
    artifact_repo: TraceArtifactRepository,
    cucm_client: CUCMClient,
):
    """Render dedicated CUCM SDL Trace Analysis section."""
    st.markdown("### 🔬 Dedicated CUCM SDL Trace Analysis Agent")
    st.caption("Deterministic parsing, multi-signal call indexing, and evidence-grounded RCA for CUCM 15.")

    # 1. Top Controls Row: Refresh & Collect
    c_top1, c_top2, c_top3 = st.columns([1.5, 2, 4])
    with c_top1:
        if st.button("🔄 Refresh", use_container_width=True, help="Re-read trace metadata and refresh Call Index"):
            st.session_state.pop("sdl_call_index", None)
            st.session_state.pop("sdl_search_results", None)
            st.success("Refreshed trace metadata and index cache.")
            st.rerun()

    with c_top2:
        if st.button("📥 Collect Latest SDL", use_container_width=True, help="Fetch latest trace from CUCM via SFTP"):
            if not cucm_client.is_connected():
                with st.spinner("Connecting to CUCM..."):
                    try:
                        cucm_client.connect()
                    except Exception as exc:
                        st.error(f"CUCM connection failed: {exc}")
                        st.stop()

            with st.spinner("Collecting latest SDL trace..."):
                try:
                    collector = CUCMTraceCollector(client=cucm_client)
                    res = collector.collect_trace(mode="latest")
                    if res.success:
                        st.success(f"Collected {res.filename} ({res.size_bytes:,} bytes)")
                        st.session_state.pop("sdl_call_index", None)
                        st.rerun()
                    else:
                        st.error(f"Collection failed: {res.error}")
                except Exception as exc:
                    st.error(f"Collection exception: {exc}")

    # Discover trace files
    available_files = discover_available_sdl_files()
    if not available_files:
        st.info("ℹ️ No extracted CUCM SDL traces found in workspace. Collect a trace from CUCM or upload one.")
        return

    # Build or retrieve CallIndex
    if "sdl_call_index" not in st.session_state:
        with st.spinner(f"Indexing {len(available_files)} CUCM SDL trace file(s)..."):
            call_index = parse_and_index_traces(available_files)
            st.session_state["sdl_call_index"] = call_index
    else:
        call_index: CallIndex = st.session_state["sdl_call_index"]

    st.markdown(f"**Indexed Traces:** `{len(available_files)} file(s)` &nbsp;|&nbsp; **Total Calls Detected:** `{call_index.total_calls}`")
    st.markdown("---")

    # 2. Search & Filter Controls
    st.markdown("#### Search & Filter Calls")
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns(5)
    with f_col1:
        calling_input = st.text_input("Calling Number", key="sdl_f_calling", placeholder="e.g. 1001")
    with f_col2:
        called_input = st.text_input("Called Number", key="sdl_f_called", placeholder="e.g. 2002")
    with f_col3:
        filter_date = st.date_input("Date", value=None, key="sdl_f_date")
    with f_col4:
        start_t_input = st.time_input("Start Time", value=None, key="sdl_f_stime")
    with f_col5:
        end_t_input = st.time_input("End Time", value=None, key="sdl_f_etime")

    if st.button("🔍 Find Calls", use_container_width=True):
        st_dt = None
        et_dt = None
        if filter_date and start_t_input:
            st_dt = datetime.combine(filter_date, start_t_input).replace(tzinfo=IST_TZ)
        if filter_date and end_t_input:
            et_dt = datetime.combine(filter_date, end_t_input).replace(tzinfo=IST_TZ)

        matches = call_index.find_calls(
            calling_number=calling_input if calling_input else None,
            called_number=called_input if called_input else None,
            start_time=st_dt,
            end_time=et_dt,
            date_filter=filter_date if filter_date else None,
        )
        st.session_state["sdl_search_results"] = matches

    results: List[Call] = st.session_state.get("sdl_search_results", call_index.get_all_calls())

    if not results:
        st.warning("No calls matched the specified search criteria.")
        return

    # 3. Display Call Table
    st.markdown(f"#### Matching Calls ({len(results)} found)")
    call_table_data = []
    for c in results:
        call_table_data.append({
            "Call ID": c.id,
            "CALLING": c.calling_number or "Unknown",
            "CALLED": c.called_number or "Unknown",
            "TIMESTAMP IST": c.start_time_ist_str,
            "CUCM NODE": ", ".join(c.nodes) or "UCM15-HQ-PUB",
            "PROTOCOL": ", ".join(c.protocols) or "CUCM",
            "EVENT COUNT": c.event_count,
        })

    df_calls = pd.DataFrame(call_table_data)
    st.dataframe(df_calls[["CALLING", "CALLED", "TIMESTAMP IST", "CUCM NODE", "PROTOCOL", "EVENT COUNT"]], use_container_width=True)

    # 4. Select One Call
    call_options = [
        f"{c.calling_number or 'Unknown'} ➔ {c.called_number or 'Unknown'} @ {c.start_time_ist_str} ({c.id})"
        for c in results
    ]
    selected_idx = st.selectbox(
        "Select Call to Analyze:",
        range(len(results)),
        format_func=lambda i: call_options[i],
        key="sdl_selected_call_idx",
    )
    selected_call: Call = results[selected_idx]

    c_an1, c_an2 = st.columns([2, 2])
    with c_an1:
        run_analysis = st.button("⚡ Analyze Selected Call", type="primary", use_container_width=True)
    with c_an2:
        rerun_analysis = st.button("🔄 Re-run Agent Analysis", use_container_width=True)

    # Cache RCA in session state keyed by call id
    cache_key = f"sdl_rca_{selected_call.id}"
    agent = get_sdl_analyst_agent()

    if rerun_analysis:
        agent.retriever = InMemoryKnowledgeRetriever()  # Reload knowledge base
        rca_res = agent.analyze_call(selected_call)
        st.session_state[cache_key] = rca_res
        st.success("Re-ran agent analysis with latest knowledge base.")

    elif run_analysis:
        with st.spinner("Analyzing call flow, verifying state machine, and reasoning RCA..."):
            rca_res = agent.analyze_call(selected_call)
            st.session_state[cache_key] = rca_res

    rca_res: Optional[RCAResult] = st.session_state.get(cache_key)

    if rca_res:
        st.markdown("---")
        # Reproducibility Header (Phase 16)
        r_col1, r_col2, r_col3, r_col4 = st.columns(4)
        with r_col1:
            st.metric("Analysis Timestamp", rca_res.analysis_timestamp)
        with r_col2:
            st.metric("Agent Version", rca_res.agent_version)
        with r_col3:
            st.metric("Parser Version", rca_res.parser_version)
        with r_col4:
            st.metric("Knowledge Version", rca_res.knowledge_version)

        # Tabs for Call Details
        sub_tab_summary, sub_tab_flow, sub_tab_events, sub_tab_timeline, sub_tab_anomalies, sub_tab_rca = st.tabs([
            "📋 Call Summary",
            "🔀 Call Flow",
            "📑 SDL Events",
            "⏱️ Timeline",
            "⚠️ Anomalies",
            "🤖 AI RCA Report",
        ])

        with sub_tab_summary:
            st.markdown(f"**Calling Party:** `{rca_res.calling_number}`")
            st.markdown(f"**Called Party:** `{rca_res.called_number}`")
            st.markdown(f"**Start Time (IST):** `{rca_res.timestamp_ist}`")
            st.markdown(f"**Timezone:** `{rca_res.timezone}`")
            st.markdown(f"**CUCM Nodes:** `{', '.join(rca_res.nodes) or 'UCM15-HQ-PUB'}`")
            st.markdown(f"**Duration:** `{selected_call.duration_seconds:.2f}s`")
            st.markdown(f"**Events:** `{selected_call.event_count}`")
            st.markdown(f"**Correlation Reasons:**")
            for r in selected_call.correlation_reasons:
                st.markdown(f"- {r}")

        with sub_tab_flow:
            st.markdown("#### Sequential Signaling Flow")
            for line in rca_res.call_flow:
                st.markdown(f"- `{line}`")

        with sub_tab_events:
            st.markdown("#### Chronological SDL Event List")
            ev_records = []
            for ev in selected_call.events:
                ev_records.append({
                    "Timestamp IST": ev.timestamp_ist_str,
                    "Signal": ev.signal,
                    "Direction": ev.direction,
                    "Protocol": ev.protocol,
                    "Process": ev.process,
                    "Source": f"{ev.source_file}:{ev.source_line}",
                })
            st.dataframe(pd.DataFrame(ev_records), use_container_width=True)

        with sub_tab_timeline:
            st.markdown("#### Event Timeline")
            t_base = selected_call.start_time
            t_records = []
            for ev in selected_call.events:
                delta_sec = (ev.timestamp - t_base).total_seconds()
                t_records.append({
                    "Offset (s)": round(delta_sec, 3),
                    "Timestamp IST": ev.timestamp_ist_str,
                    "Signal": ev.signal,
                    "Protocol": ev.protocol,
                })
            st.dataframe(pd.DataFrame(t_records), use_container_width=True)

        with sub_tab_anomalies:
            st.markdown("#### Observed Signaling Anomalies")
            if rca_res.observations:
                for obs in rca_res.observations:
                    if "[CRITICAL]" in obs or "[HIGH]" in obs:
                        st.error(obs)
                    elif "[MEDIUM]" in obs:
                        st.warning(obs)
                    else:
                        st.info(obs)
            else:
                st.success("No anomalies observed in call signaling.")

        with sub_tab_rca:
            st.markdown(rca_res.formatted_report)

        # 5. Raw SDL Evidence Section (Phase 15)
        st.markdown("---")
        with st.expander("📄 Show Raw SDL Evidence", expanded=False):
            st.markdown("#### Curated Raw SDL Lines Supporting Analysis")
            if rca_res.evidence:
                for item in rca_res.evidence:
                    st.markdown(f"**`{item.get('source_file')}:{item.get('source_line')}`** &nbsp;|&nbsp; `{item.get('timestamp_ist')}` &nbsp;|&nbsp; `{item.get('signal')}`")
                    st.code(item.get("raw_text", ""), language="text")
            else:
                # Show first 10 verbatim lines of selected call
                st.caption("Showing initial events from selected call:")
                for ev in selected_call.events[:10]:
                    st.markdown(f"**`{ev.source_file}:{ev.source_line}`** @ `{ev.timestamp_ist_str}`")
                    st.code(ev.raw_text, language="text")
