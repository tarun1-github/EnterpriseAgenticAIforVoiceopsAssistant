# VoiceOps AI — Enterprise Agentic Troubleshooting for Cisco Voice

VoiceOps AI is an enterprise-grade agentic AI platform engineered for deep forensic troubleshooting of Cisco Collaboration and Voice environments (CUCM 15, Cisco IOS/IOS-XE Voice Gateways, CUBE, ISDN/Q.931, MGCP, SIP, and CUCM CallManager SDL traces).

Unlike naive chat tools that dump thousands of raw log lines into an LLM prompt, VoiceOps AI strictly adheres to the **Deterministic First, Agentic Reasoning Second** principle:
1. High-speed, deterministic Python parsers decode raw traces into strongly-typed `SDLEvent` and `VoiceEvent` records with line-level source attribution.
2. A multi-signal correlation engine links disparate protocol legs (CI, CDCC, SIP Call-ID, ccbID, TCP handles, ANI/DNIS).
3. Protocol-specific state machines (SIP, Q.931, MGCP) track call milestones and detect missing signals or timing gaps.
4. Rule-based anomaly detectors isolate signaling faults before invoking AI.
5. An evidence-grounded AI Analyst reasons over structured `EvidencePack` objects and versioned Cisco domain knowledge to formulate verified Root Cause Analysis (RCA) without hallucinations.

---

## Architecture

```
RAW CUCM SDL TRACE
        ↓
Deterministic Streaming Parser (SDLParser)
        ↓
Structured SDL Events (SDLEvent)
        ↓
Call Index & Multi-Criteria Inverted Index (CallIndex)
        ↓
Multi-Factor Call Correlation Engine (SDLCallCorrelator)
        ↓
Call Flow Engine & State Machines (SIP / Q.931 / MGCP)
        ↓
Deterministic Anomaly Detector (SDLAnomalyDetector)
        ↓
Evidence Pack Synthesis (EvidencePack)
        ↓
Knowledge Retrieval (RAG over Cisco Reference Docs)
        ↓
Agentic AI Analyst (SDLAnalystAgent)
        ↓
Evidence-Based Root Cause Analysis (RCA)
```

See [docs/SDL_ANALYSIS_ARCHITECTURE.md](docs/SDL_ANALYSIS_ARCHITECTURE.md) for full architectural documentation and component specifications.

---

## Key Features

- **Dedicated CUCM SDL Trace Analysis**:
  - Deterministic streaming parser supporting multiline records, sequence numbers, FileHead base date, and timezone offsets.
  - Automatic timezone conversion to **Asia/Kolkata (IST)** across all UI displays.
  - Disjoint-Set Union (Union-Find) multi-factor call correlation linking CI, CDCC, Call-ID, TCP handles, and numbers.
  - Multi-criteria call search index supporting concurrent call disambiguation.
  - Protocol state machines enforcing legal transitions for SIP, Q.931 PRI, and MGCP.
- **Evidence-Based RCA & Hallucination Prevention**:
  - Only declares confirmed root causes when verified by line-level trace proof (e.g. SIP 503 with Q.850 cause codes).
  - Explicitly states `"Root cause cannot be confirmed from CUCM SDL evidence alone."` when evidence is incomplete, specifying exact additional evidence required.
- **Versioned Domain Knowledge Base & RAG**:
  - Structured YAML knowledge covering SDL signals, CUCM daemons, identifiers, call flows, and failure patterns.
  - Pluggable `BaseKnowledgeRetriever` interface for seamless integration with vector databases.
- **Interactive Streamlit Diagnostic Center**:
  - Search and filter calls by calling/called number, date, and time range.
  - Inspect call flow, sequential milestones, time deltas, anomalies, and timeline.
  - Expandable **Show Raw SDL Evidence** container showing exact trace lines with copy controls.
  - One-click **Re-run Agent Analysis** with reproducibility metadata (versions and timestamp).
- **Safe Device Command Center**:
  - Diagnostic command execution gated by explicit user approval (`approved=True`).
  - Read-only validation, secret masking, timeouts, and audit logging.

---

## Directory Structure

```
voiceops-ai/
├── app/
│   ├── agents/                # Evidence-grounded AI Analysts (SDLAnalystAgent, models)
│   ├── commands/              # Device Command Center (safety guardrails, history, service)
│   ├── core/                  # Configuration, Pydantic settings, logging, timestamps
│   ├── correlation/           # Multi-protocol call correlation engine
│   ├── devices/
│   │   ├── cucm/              # CUCM SSH client, transport, collector, and SDL subsystem
│   │   │   └── sdl/           # Dedicated SDL parser, models, index, correlator, flow, evidence
│   │   └── ios/               # Cisco IOS gateway SSH transport
│   ├── knowledge/             # Knowledge models, loader, and RAG retriever interface
│   ├── models/                # Domain models (SDLEvent, Call, VoiceEvent, Session)
│   └── parsers/               # Protocol parsers (ISDN, SIP, MGCP, CUCM)
├── knowledge/
│   └── sdl/                   # Structured YAML knowledge (signals, processes, failures, flows)
├── ui/
│   ├── sdl_analysis.py        # Dedicated CUCM SDL Trace Analysis UI component
│   └── streamlit_app.py       # Main Streamlit diagnostic dashboard
├── docs/
│   └── SDL_ANALYSIS_ARCHITECTURE.md  # Comprehensive architecture documentation
├── tests/                     # 281+ automated unit and integration tests
└── README.md
```

---

## Quickstart

### 1. Installation

```powershell
python -m pip install -r requirements.txt
```

### 2. Configuration

Copy the example environment file:
```powershell
cp .env.example .env
```
Configure your credentials:
- `CUCM_HOST`, `CUCM_USERNAME`, `CUCM_PASSWORD` (CLI admin credentials for CUCM 15)
- `VOICEOPS_TRACE_STORAGE` (Persistent trace repository path, defaults to `data/voiceops_traces`)

### 3. Run Test Suite

Execute the full automated test suite (281 tests passing):
```powershell
python -m pytest tests/ -v
```

To run only the CUCM SDL subsystem tests:
```powershell
python -m pytest tests/devices/cucm/sdl/ -v
```

### 4. Start Streamlit UI

Launch the dashboard:
```powershell
streamlit run ui/streamlit_app.py
```
Open `http://localhost:8501` in your browser. Navigate to the **"🔬 SDL Trace Analysis"** tab to search, filter, correlate, and analyze CUCM calls.

---

## Sample Workflow: CUCM SDL Trace Analysis

1. **Collect or Upload Trace**:
   - In the **CUCM Device** tab or **🔬 SDL Trace Analysis** tab, click **"Collect Latest SDL"** to fetch traces over SFTP from CUCM 15.
   - Alternatively, place extracted trace `.txt` files into `data/voiceops_traces/extracted/`.
2. **Search Calls**:
   - Enter calling number (e.g. `1001`), called number (e.g. `2002`), or date/time range.
   - Click **"Find Calls"**. The index displays matching candidate calls with timestamps converted to **Asia/Kolkata (IST)**.
3. **Analyze Selected Call**:
   - Choose a call from the selector and click **"Analyze Selected Call"**.
   - Inspect the **Call Summary**, **Call Flow**, **SDL Events**, and **Anomalies**.
   - Review the **AI RCA Report** for identified failure points and recommended checks.
4. **Inspect Raw Evidence**:
   - Expand **"Show Raw SDL Evidence"** to view exact verbatim trace lines with line numbers and file names.
5. **Re-run Analysis**:
   - Click **"Re-run Agent Analysis"** to re-evaluate the selected call with updated knowledge base rules.
