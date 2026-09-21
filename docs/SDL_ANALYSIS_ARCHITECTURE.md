# CUCM SDL Trace Analysis Architecture

## 1. Executive Summary & Philosophy

Enterprise VoiceOps AI implements an evidence-driven, deterministic-first architecture for troubleshooting Cisco Unified Communications Manager (CUCM 15) signaling and call control failures.

### Core Architectural Principle
```
RAW SDL TRACE
      ↓
Deterministic SDL Parser
      ↓
Structured SDL Events (SDLEvent)
      ↓
Call Index & Multi-Criteria Inverted Index
      ↓
Call Correlation Engine (Disjoint-Set Union)
      ↓
Call Flow Engine & Protocol State Machines (SIP, Q.931, MGCP)
      ↓
Deterministic Anomaly Detection
      ↓
Evidence Pack Synthesis
      ↓
Knowledge Retrieval (RAG over Cisco Reference Docs)
      ↓
Agentic AI Analyst (Evidence-Grounded Reasoning)
      ↓
Reproducible Root Cause Analysis (RCA)
```

> [!IMPORTANT]
> **Deterministic First, AI Reasoning Second**: The Large Language Model (LLM) is strictly forbidden from parsing raw, multi-megabyte log files directly. The deterministic parser, correlator, and anomaly detector extract ground facts first. The LLM only reasons over structured, line-referenced `EvidencePack` objects and verified Cisco documentation.

---

## 2. Pipeline Subsystems

### 2.1 Deterministic Streaming Parser (`app/devices/cucm/sdl/parser.py`)
- **Streaming Execution**: Parses CUCM SDL traces using generators without loading entire multi-megabyte files into memory.
- **FileHead Metadata**: Captures CUCM node hostname, software version (`15.0.1.12900-234`), trace base date (e.g. `2026/09/20`), and UTC offset (`UTC:+00:00`).
- **Record Types**:
  - `FileHead`: Metadata, base date, and timezone offset.
  - `SdlSig`: Inter- and intra-process signaling records (`signal | state | receiving_proc | sending_proc | proc_ids | params`).
  - `AppInfo`: Protocol decode blocks (SIP messages, MGCP packets) with multiline continuation buffering.
- **Resilience**: Never crashes on malformed lines; malformed records are preserved for diagnostics.
- **Verbatim Integrity**: Retains verbatim `raw_text`, `source_file`, and 1-based `source_line` numbers for every event.

### 2.2 Timezone Normalization & IST Display (`app/devices/cucm/sdl/normalizer.py`)
- All trace timestamps are parsed into explicit **timezone-aware** Python `datetime` objects using the offset declared in the trace header.
- Naive datetimes are strictly disallowed.
- Normalization provides standard conversion to **Asia/Kolkata (IST)**:
  `CUCM UTC trace timestamp` → `Timezone-aware datetime` → `Asia/Kolkata (IST) display`.

### 2.3 Identifier Extraction (`app/devices/cucm/sdl/identifiers.py`)
Extracts multi-factor correlation keys:
- **CI**: CUCM Call Identification integer (e.g. `CI=33554432`).
- **CDCC**: Call Deflection and Control Block ID (e.g. `cdcc=1234567` or `Cdcc(1,100,20,1)`).
- **Call-ID**: SIP Call-ID header (e.g. `c987654321-callid@cisco.com`).
- **ccbID**: Call Control Block Identifier.
- **TCP Handle / AppCorr**: Connection and application correlation tokens.
- **Calling / Called Numbers**: ANI and DNIS extracted from SIP headers (`From:`, `To:`, `INVITE sip:`) and CUCM internal parameters (`callingPartyNumber=`, `calledPartyNumber=`).

### 2.4 Call Index (`app/devices/cucm/sdl/call_index.py`)
- Multi-criteria inverted index supporting queries across:
  - Calling number
  - Called number
  - Start and end time ranges
  - Specific calendar dates
  - CUCM node hostname
  - Call-ID, CI, CDCC, device name, and protocol
- **Multi-Call Safety**: Returns multiple distinct calls even when calling and called numbers match, disambiguated by timestamp windows.

### 2.5 Multi-Factor Call Correlation Engine (`app/devices/cucm/sdl/correlator.py`)
- Groups disconnected SDL events into coherent `Call` sessions using Disjoint-Set Union (Union-Find).
- Employs transitive closure across overlapping keys:
  - Event A: `(Call-ID, CI)`
  - Event B: `(Call-ID, calling, called)`
  - Event C: `(CI, CDCC)`
- Links proximity-matched number pairs within configured time windows.
- Automatically filters out periodic background timer noise (`DbObjectCacheTimer`, etc.) so only true call signaling sessions are presented.

### 2.6 Call Flow & State Machine Engine (`app/devices/cucm/sdl/call_flow.py`, `state_machine.py`)
- Reconstructs sequential call flow with delta latencies (`time_delta_ms`).
- Protocol-specific state machines enforce valid transitions:
  - **SIP**: `IDLE` → `CALL_SETUP` (INVITE) → `ALERTING` (180 Ringing) → `CONNECT` (200 OK) → `ACTIVE` (ACK) → `DISCONNECT` (BYE) → `CALL_END`.
  - **Q.931**: `SETUP` → `CALL PROCEEDING` → `ALERTING` → `CONNECT` → `DISCONNECT` → `RELEASE` → `RELEASE COMPLETE`.
  - **MGCP**: `NTFY` (offhook/digits) → `CRCX` → `RQNT` (alerting) → `MDCX` → `DLCX`.
- Detects:
  - Observed events
  - Expected events
  - Missing expected milestones (e.g. INVITE without Ringing/200 OK)
  - Unexpected signals
  - Excessive delays (> 4000ms)

### 2.7 Deterministic Anomaly Detection (`app/devices/cucm/sdl/anomaly_detector.py`)
- Reports fact-based observations before invoking the AI agent:
  - `MISSING_EXPECTED_EVENT`: Milestone expected by protocol model was absent.
  - `PREMATURE_DISCONNECT`: Call aborted or disconnected before reaching answer/connect state.
  - `REJECTED_RESPONSE`: Explicit SIP error response (e.g. `503 Service Unavailable`, `404 Not Found`).
  - `EXCESSIVE_DELAY`: Large inter-event time gaps.

### 2.8 EvidencePack Builder (`app/devices/cucm/sdl/evidence.py`)
- Bridges deterministic analysis to the AI reasoning engine.
- Contains:
  - Call metadata (numbers, duration, node, protocols, IST timestamps)
  - Correlated identifiers (CI, CDCC, Call-ID)
  - Chronological call flow
  - State machine transitions
  - Anomaly findings with concrete supporting evidence
  - Line-level verbatim raw SDL trace lines

### 2.9 Versioned Knowledge Base & RAG (`knowledge/sdl/`, `app/knowledge/`)
- Structured YAML knowledge base covering:
  - **Signals** (`signals.yaml`): Internal CCM signals (`CcSetupReq`, `CcSetupInd`, `CcAlertInd`, etc.).
  - **Processes** (`processes.yaml`): Internal daemon roles (`Cdcc`, `SIPCdpc`, `SIPHandler`, `MGCPHandler`, `DigitAnalysis`).
  - **Identifiers** (`identifiers.yaml`): Field specifications for `CI`, `CDCC`, `Call-ID`, `ccbID`.
  - **Call Flows** (`callflows/`): Reference flows for SIP and MGCP.
  - **Failure Patterns** (`failures/`): Common causes, symptoms, and Cisco recommended checks for SIP 503, 404, etc.
- Pluggable `BaseKnowledgeRetriever` interface with `InMemoryKnowledgeRetriever` supporting token scoring and category filtering (extensible to Chroma/FAISS/Azure AI Search).

### 2.10 SDL Analyst Agent (`app/agents/sdl_analyst.py`)
- Evidence-grounded agent following strict reasoning constraints:
  - Clearly distinguishes **Observation**, **Evidence**, **Inference**, **Possible cause**, and **Confirmed cause**.
  - **Never hallucinates root cause**: If evidence is incomplete, explicitly outputs:
    `"Root cause cannot be confirmed from CUCM SDL evidence alone."` and specifies exact additional evidence required.
  - Generates standardized RCA output with confidence justification (High/Medium/Low).
  - Embeds version metadata (`agent_version`, `parser_version`, `knowledge_version`, `analysis_timestamp`) for audit reproducibility.

### 2.11 Streamlit UI (`ui/sdl_analysis.py`)
- Interactive interface:
  - Controls: `[🔄 Refresh]`, `[📥 Collect Latest SDL]`.
  - Filter by Calling, Called, Date, Start/End Time.
  - Multi-call candidate table with one-click selection.
  - `[⚡ Analyze Selected Call]` and `[🔄 Re-run Agent Analysis]`.
  - Dedicated sub-tabs: Call Summary, Call Flow, SDL Events, Timeline, Anomalies, and AI RCA Report.
  - Expandable `Show Raw SDL Evidence` with copy controls and line number attribution.

### 2.12 Safe Device Command Abstraction (`app/commands/service.py`)
- Exposes `run_device_command(device_type, command, approved=False)`:
  - Gated by mandatory `approved=True` parameter.
  - Restricts execution to safe, read-only diagnostic commands.
  - Sanitizes sensitive tokens and logs all executions to audit history.

---

## 3. Limitations & Operational Constraints

1. **Single-Node Traces**: If a call spans multiple CUCM nodes, correlation across separate trace files requires ingesting all node traces into the workspace.
2. **SDL Trace Rollover**: If an active call's initial `CcSetupReq` occurred in a rolled-over trace file (`.txt.gz`) not present in the workspace, initial setup parameters might be missing.
3. **Encrypted Signaling (SIP TLS / SRTP)**: SDL traces capture unencrypted internal signaling between processes even if the wire transport uses TLS, but encrypted payload keys are intentionally masked.
4. **Command Execution Safeguards**: Arbitrary shell commands or configuration commands (`conf t`, `reload`, `delete`) are strictly blocked by safety policies.
