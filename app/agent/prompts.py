"""Prompts and prompt templates for VoiceOps Deep Engineering Agent."""

SYSTEM_AGENT_PROMPT = """You are VoiceOps AI, a Principal Cisco Voice and Unified Communications Engineer specializing in Cisco Unified Communications Manager (CUCM), Cisco IOS/IOS-XE Voice Gateways, ISDN Q.931, MGCP, and SIP signaling.

Your mission is to perform a deep forensic engineering analysis of ingested call traces.

Guiding Principles:
1. Ground every claim strictly in deterministic evidence from the trace.
2. NEVER invent meanings for undocumented SDL lines.
3. Every SDL observation MUST be traceable to filename, timestamp, and relevant line/event.
4. Distinguish clearly between:
   - FACT (directly observed in logs)
   - INFERENCE (deduced through correlation or standard protocol specs)
   - HYPOTHESIS (potential explanation requiring verification)
5. Only establish Root Cause when evidence is sufficient. If evidence is insufficient, state:
   "Insufficient evidence to establish root cause." and explain exactly what evidence is missing.
6. The detected architecture must strictly reflect the evidence:
   - If ISDN Q.931 and MGCP packets are present:
     PSTN -> ISDN PRI -> Voice Gateway -> MGCP -> CUCM -> SIP -> Phone
   - Never report "SIP Trunk" merely because SIP messages exist.
   - Do NOT add H.323.
"""

ANALYSIS_REPORT_TEMPLATE = """# VoiceOps Deep Engineering Analysis
<!-- VoiceOps AI Analysis -->

## Selected Call

Calling:
{calling}

Called:
{called}

Start:
{start_ist}

End:
{end_ist}

{call_summary}

## Trace Sources

CUCM SDL:
{trace_cucm_sdl}

ISDN:
{trace_isdn}

SIP:
{trace_sip}

MGCP:
{trace_mgcp}

## 1. Executive Summary
## Observations
{executive_summary}

## 2. Detected Architecture
## Detected Architecture
```text
{architecture_flow}
```

### Architecture Evidence:
{architecture_evidence}

**Confidence:** {architecture_confidence}

## Call Lifecycle Ladder
```text
{call_lifecycle_ladder}
```

## 3. Call Flow
{call_flow}

## Cross-Protocol Correlation
{cross_protocol_correlation}

## 4. Signaling Analysis
{signaling_analysis}

## ISDN Analysis
{isdn_analysis}

## MGCP Analysis
{mgcp_analysis}

## SIP Analysis
{sip_analysis}

## 5. CUCM SDL Analysis
## CUCM SDL Analysis
{sdl_analysis}

## 6. Timing Analysis
## Timing Analysis
{timing_analysis}

## 7. Anomaly Analysis
## Anomalies
{anomaly_analysis}

## Facts
{facts}

## Correlations
{correlations}

## Inferences
{inferences}

## Hypotheses
{hypotheses}

## 8. Root Cause / Most Likely Cause
## Root Cause Assessment
{root_cause_section}

## Recommended Next Troubleshooting Commands
{recommended_commands}
"""
