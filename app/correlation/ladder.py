"""Dynamic Call Lifecycle Ladder diagram generator for multi-protocol voice sessions."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.core.timestamps import ensure_utc
from app.models.call_session import CallSession
from app.models.event import DirectionEnum, ProtocolEnum, VoiceEvent


class LadderStep(BaseModel):
    """Single step in the call lifecycle ladder."""

    step_number: int
    timestamp_ist: str
    time_offset_ms: float
    actor_from: str
    actor_to: str
    arrow: str
    message: str
    protocol: str
    is_internal_cucm: bool = False
    source_file: str
    source_line: Optional[int] = None
    device: Optional[str] = None
    raw_snippet: str = ""


class CallLifecycleLadder:
    """Constructs dynamic lifecycle ladder diagrams from correlated CallSessions."""

    # Canonical lifecycle actor columns
    ACTORS = ["PSTN", "Voice Gateway", "CUCM", "Phone"]

    def build_ladder(self, session: CallSession) -> List[LadderStep]:
        """Build structured ladder steps from a CallSession's chronological events."""
        if not session.events:
            return []

        # Sort events chronologically
        events = sorted(
            session.events,
            key=lambda e: (e.timestamp is None, ensure_utc(e.timestamp) if e.timestamp else None)
        )

        t_base = ensure_utc(events[0].timestamp) if events[0].timestamp else None
        steps: List[LadderStep] = []

        for idx, ev in enumerate(events, start=1):
            offset_ms = 0.0
            if t_base and ev.timestamp:
                offset_ms = max(0.0, (ensure_utc(ev.timestamp) - t_base).total_seconds() * 1000.0)

            ts_ist = ev.timestamp_ist_str

            actor_from, actor_to, arrow, is_internal = self._resolve_actors(ev)
            raw_snip = (ev.raw.strip().splitlines()[0] if ev.raw else "")[:120]

            step = LadderStep(
                step_number=idx,
                timestamp_ist=ts_ist,
                time_offset_ms=round(offset_ms, 1),
                actor_from=actor_from,
                actor_to=actor_to,
                arrow=arrow,
                message=ev.message_type or "SIGNAL",
                protocol=ev.protocol.value if hasattr(ev.protocol, "value") else str(ev.protocol),
                is_internal_cucm=is_internal,
                source_file=ev.source or "unknown",
                source_line=ev.metadata.get("source_line") if ev.metadata else None,
                device=ev.device or ev.device_name or "Unknown",
                raw_snippet=raw_snip,
            )
            steps.append(step)

        return steps

    def _resolve_actors(self, ev: VoiceEvent) -> tuple[str, str, str, bool]:
        """Determine actor placement according to Cisco call lifecycle topology."""
        proto = ev.protocol
        is_rx = ev.direction == DirectionEnum.INBOUND
        is_sdl = (
            ev.trace_type == "CUCM_SDL"
            or "SdlSig" in ev.raw
            or "FileHead" in ev.raw
            or (ev.metadata and "receiving_process" in ev.metadata)
        )

        # Rule: CUCM SDL is strictly an internal CUCM leg (never network leg)
        if is_sdl or (proto == ProtocolEnum.CUCM and ev.device_type == "CUCM"):
            return "CUCM", "CUCM", "│── [SDL Internal]", True

        # ISDN Q.931 leg: strictly between PSTN and Voice Gateway
        if proto == ProtocolEnum.ISDN:
            if is_rx:
                return "PSTN", "Voice Gateway", "──────▶", False
            else:
                return "Voice Gateway", "PSTN", "◀──────", False

        # MGCP leg: strictly between Voice Gateway and CUCM
        if proto == ProtocolEnum.MGCP:
            if is_rx:
                # Gateway received command from CUCM
                return "CUCM", "Voice Gateway", "◀──────", False
            else:
                # Gateway sending notification to CUCM
                return "Voice Gateway", "CUCM", "──────▶", False

        # SIP leg: can be Gateway <-> CUCM or CUCM <-> Phone
        if proto == ProtocolEnum.SIP:
            is_phone = (
                (ev.device and ("SEP" in ev.device or "CSF" in ev.device or "BOT" in ev.device))
                or (ev.device_type == "SIP_ENDPOINT")
            )
            if is_phone:
                if is_rx:
                    return "Phone", "CUCM", "──────▶", False
                else:
                    return "CUCM", "Phone", "──────▶", False
            else:
                # Gateway / CUBE to CUCM
                if is_rx:
                    # Inbound from remote or CUCM
                    if ev.device_type == "CUCM":
                        return "Voice Gateway", "CUCM", "──────▶", False
                    return "CUCM", "Voice Gateway", "◀──────", False
                else:
                    if ev.device_type == "CUCM":
                        return "CUCM", "Voice Gateway", "──────▶", False
                    return "Voice Gateway", "CUCM", "──────▶", False

        # Default fallback
        return "Voice Gateway", "CUCM", "──────▶", False

    def generate_ascii_ladder(self, session: CallSession) -> str:
        """Render a clean, formatted ASCII call lifecycle ladder diagram."""
        steps = self.build_ladder(session)
        if not steps:
            return "No signaling events to display."

        header = (
            "  Time (IST)   |  Offset | PSTN                Voice Gateway             CUCM                      Phone\n"
            "---------------+---------+--------------------------------------------------------------------------------"
        )
        lines = [header]

        for s in steps:
            time_col = s.timestamp_ist.split()[1] if " " in s.timestamp_ist else s.timestamp_ist
            off_col = f"+{s.time_offset_ms:.0f}ms".rjust(7)

            if s.is_internal_cucm:
                # SDL internal processing at CUCM column
                diagram_row = f"{' ' * 48}│ ├── {s.message} [{s.source_file}]"
            elif s.actor_from == "PSTN" and s.actor_to == "Voice Gateway":
                diagram_row = f"|  {s.message} {s.arrow}  |{' ' * 46} [{s.source_file}]"
            elif s.actor_from == "Voice Gateway" and s.actor_to == "PSTN":
                diagram_row = f"|  {s.arrow} {s.message}  |{' ' * 46} [{s.source_file}]"
            elif s.actor_from == "Voice Gateway" and s.actor_to == "CUCM":
                diagram_row = f"{' ' * 22}|  {s.message} {s.arrow}  |{' ' * 23} [{s.source_file}]"
            elif s.actor_from == "CUCM" and s.actor_to == "Voice Gateway":
                diagram_row = f"{' ' * 22}|  {s.arrow} {s.message}  |{' ' * 23} [{s.source_file}]"
            elif s.actor_from == "CUCM" and s.actor_to == "Phone":
                diagram_row = f"{' ' * 48}|  {s.message} {s.arrow}  | [{s.source_file}]"
            elif s.actor_from == "Phone" and s.actor_to == "CUCM":
                diagram_row = f"{' ' * 48}|  {s.arrow} {s.message}  | [{s.source_file}]"
            else:
                diagram_row = f"{' ' * 22}|  {s.message}  | [{s.source_file}]"

            lines.append(f"{time_col:<14} | {off_col} | {diagram_row}")

        return "\n".join(lines)

    @classmethod
    def generate_ascii(cls, session: CallSession) -> str:
        """Convenience classmethod to render ASCII ladder diagram."""
        return cls().generate_ascii_ladder(session)

