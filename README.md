# VoiceOps AI — Enterprise Agentic Troubleshooting for Cisco Voice

VoiceOps AI is an agentic AI platform designed for troubleshooting Cisco Voice environments (CUCM, Cisco Voice Gateways, ISDN/Q.931, MGCP, SIP, and CUCM SDL/SDI traces).

Unlike naive chat tools that dump thousands of raw log lines into an LLM prompt, VoiceOps AI adheres to the **Deterministic First, Agentic Reasoning Second** principle:
1. High-speed, deterministic Python parsers decode raw traces into strongly-typed `VoiceEvent` records.
2. A multi-signal correlation engine links disparate protocol legs (ISDN call refs, MGCP transactions, SIP Call-IDs, ANI/DNIS).
3. Rule-based anomaly detectors isolate signaling faults.
4. A LangGraph agent reasons over structured evidence to formulate verified Root Cause Analysis (RCA) and actionable next steps.

---

## Supported Architectures

1. **ISDN + MGCP**: PSTN ──[ISDN]──▶ Voice Gateway ──[MGCP]──▶ CUCM 15.0 ──[SIP]──▶ Phone / CIPC
2. **ISDN + SIP**: PSTN ──[ISDN]──▶ Voice Gateway ──[SIP]──▶ CUCM 15.0 ──[SIP]──▶ Phone / CIPC
3. **Direct SIP**: PSTN ──[SIP]──▶ CUCM 15.0 ──[SIP]──▶ Phone / CIPC

---

## Project Structure

```
voiceops-ai/
├── app/
│   ├── core/                  # Configuration, settings (Pydantic Settings), logging
│   │   ├── config.py
│   │   └── logging.py
│   ├── models/                # Domain models
│   │   └── event.py           # VoiceEvent common model & Enums
│   └── parsers/               # Deterministic protocol parsers
│       ├── base.py            # BaseParser interface
│       ├── detector.py        # Heuristic protocol autodetection
│       ├── ingestion.py       # Multi-file trace ingestion engine
│       ├── isdn/              # Cisco Q.931 PRI parser
│       ├── sip/               # Cisco SIP message & SDP parser
│       ├── mgcp/              # Cisco MGCP packet parser
│       └── cucm/              # Initial CUCM SDL/SDI extractor
├── ui/
│   └── streamlit_app.py       # Streamlit operational dashboard
├── sample_data/               # Synthetic traces for offline validation
│   ├── isdn/
│   ├── sip/
│   └── mgcp/
├── tests/                     # Unit test suites (Pytest)
│   └── parsers/
├── .env.example               # Credential template (NEVER commit .env)
├── .gitignore
├── requirements.txt
├── pyproject.toml
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
Configure your desired LLM provider (`openai`, `gemini`, or `ollama`) in `.env`. Note that Phase 1 local deterministic parsing and UI work without any external API keys.

### 3. Run Unit Tests

Execute the automated test suite verifying all parsers, protocol detectors, and ingestion:
```powershell
python -m pytest tests/ -v
```

### 4. Start the Streamlit UI

Launch the interactive diagnostic interface:
```powershell
streamlit run ui/streamlit_app.py
```
Open your browser to `http://localhost:8501`. Use the **"Load Bundled Samples"** button in the sidebar or upload your own `.txt` Cisco trace files.
