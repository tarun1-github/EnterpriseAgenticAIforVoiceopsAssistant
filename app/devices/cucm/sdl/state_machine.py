"""Configurable Call State Machine for CUCM voice signaling protocols."""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field

from app.devices.cucm.sdl.models import SDLEvent


class CallState(str, Enum):
    """Normalized architectural call processing states."""

    IDLE = "IDLE"
    CALL_START = "CALL_START"
    DIGIT_ANALYSIS = "DIGIT_ANALYSIS"
    ROUTE_SELECTION = "ROUTE_SELECTION"
    DEVICE_SELECTION = "DEVICE_SELECTION"
    CALL_SETUP = "CALL_SETUP"
    ALERTING = "ALERTING"
    CONNECT = "CONNECT"
    ACTIVE = "ACTIVE"
    DISCONNECT = "DISCONNECT"
    RELEASE = "RELEASE"
    CALL_END = "CALL_END"


class StateTransition(BaseModel):
    """Representation of an observed state transition in a call."""

    from_state: CallState = Field(..., description="State prior to transition")
    to_state: CallState = Field(..., description="Target state after transition")
    trigger_signal: str = Field(..., description="SDL signal or message verb triggering transition")
    timestamp: datetime = Field(..., description="Timestamp of the event")
    is_valid: bool = Field(default=True, description="Whether transition conforms to protocol model")
    reason: Optional[str] = Field(default=None, description="Diagnostic observation or violation details")


class BaseCallStateMachine:
    """Base class for protocol-specific call state machines."""

    def __init__(self):
        self.current_state: CallState = CallState.IDLE
        self.history: List[StateTransition] = []

    def reset(self) -> None:
        self.current_state = CallState.IDLE
        self.history.clear()

    def step(self, event: SDLEvent) -> StateTransition:
        raise NotImplementedError


class SIPStateMachine(BaseCallStateMachine):
    """State machine governing SIP call setups and teardowns."""

    EXPECTED_SETUP_SEQUENCE = ["INVITE", "100 Trying", "180 Ringing", "200 OK", "ACK"]

    def step(self, event: SDLEvent) -> StateTransition:
        sig = (event.signal or "").upper()
        raw = event.raw_text.upper()
        from_st = self.current_state
        to_st = from_st
        is_valid = True
        reason = None

        if "INVITE" in sig or "INVITE SIP:" in raw:
            if from_st in (CallState.IDLE, CallState.CALL_START):
                to_st = CallState.CALL_SETUP
            else:
                to_st = CallState.CALL_SETUP
                is_valid = False
                reason = f"Unexpected re-INVITE or duplicate INVITE while in state {from_st.value}"

        elif "100 TRYING" in sig or "SIP/2.0 100" in raw:
            if from_st == CallState.CALL_SETUP:
                to_st = CallState.CALL_SETUP
            else:
                to_st = CallState.CALL_SETUP
                is_valid = False
                reason = f"100 Trying received while in unexpected state {from_st.value}"

        elif "180 RINGING" in sig or "183 SESSION PROGRESS" in sig or "SIP/2.0 180" in raw or "SIP/2.0 183" in raw:
            if from_st == CallState.CALL_SETUP:
                to_st = CallState.ALERTING
            else:
                to_st = CallState.ALERTING
                is_valid = False
                reason = f"Alerting received outside setup phase from {from_st.value}"

        elif "200 OK" in sig or "SIP/2.0 200 OK" in raw:
            if from_st in (CallState.ALERTING, CallState.CALL_SETUP):
                to_st = CallState.CONNECT
            elif from_st == CallState.DISCONNECT:
                to_st = CallState.CALL_END
            else:
                to_st = CallState.CONNECT

        elif "ACK" in sig or "ACK SIP:" in raw:
            if from_st == CallState.CONNECT:
                to_st = CallState.ACTIVE
            else:
                to_st = CallState.ACTIVE
                is_valid = False
                reason = f"ACK received in unexpected state {from_st.value}"

        elif "BYE" in sig or "BYE SIP:" in raw:
            if from_st in (CallState.ACTIVE, CallState.CONNECT, CallState.ALERTING):
                to_st = CallState.DISCONNECT
            else:
                to_st = CallState.DISCONNECT
                is_valid = False
                reason = f"Premature BYE received during state {from_st.value}"

        elif any(code in raw or code in sig for code in ["404 NOT FOUND", "486 BUSY", "503 SERVICE", "500 SERVER", "CANCEL"]):
            to_st = CallState.CALL_END
            is_valid = True
            reason = "Call rejected or cancelled"

        trans = StateTransition(
            from_state=from_st,
            to_state=to_st,
            trigger_signal=event.signal or "UNKNOWN",
            timestamp=event.timestamp,
            is_valid=is_valid,
            reason=reason,
        )
        self.current_state = to_st
        self.history.append(trans)
        return trans


class Q931StateMachine(BaseCallStateMachine):
    """State machine governing ISDN PRI / Q.931 and CUCM Cc call processing."""

    EXPECTED_SEQUENCE = ["SETUP", "CALL PROCEEDING", "ALERTING", "CONNECT", "DISCONNECT", "RELEASE", "RELEASE COMPLETE"]

    def step(self, event: SDLEvent) -> StateTransition:
        sig = (event.signal or "").upper()
        from_st = self.current_state
        to_st = from_st
        is_valid = True
        reason = None

        if any(s in sig for s in ["CCSETUPREQ", "CCSETUPIND", "SETUP"]):
            to_st = CallState.CALL_SETUP
        elif any(s in sig for s in ["CALL PROCEEDING", "CCPROCEEDINGIND", "CCPROCEEDINGREQ"]):
            to_st = CallState.ROUTE_SELECTION
        elif any(s in sig for s in ["CCALERTIND", "CCALERTREQ", "ALERTING"]):
            if from_st in (CallState.CALL_SETUP, CallState.ROUTE_SELECTION, CallState.DEVICE_SELECTION):
                to_st = CallState.ALERTING
            else:
                to_st = CallState.ALERTING
                is_valid = False
                reason = f"Alerting in unexpected state {from_st.value}"
        elif any(s in sig for s in ["CCDISCONNECTIND", "CCDISCONNECTREQ", "DISCONNECT"]):
            to_st = CallState.DISCONNECT
        elif any(s in sig for s in ["CCRELEASECOMPLETE", "RELEASE COMPLETE"]):
            to_st = CallState.CALL_END
        elif any(s in sig for s in ["CCRELEASEIND", "CCRELEASEREQ", "RELEASE"]):
            to_st = CallState.RELEASE
        elif any(s in sig for s in ["CCCONNECTIND", "CCCONNECTREQ"]) or ("CONNECT" in sig and "DISCONNECT" not in sig):
            if from_st in (CallState.ALERTING, CallState.CALL_SETUP, CallState.ROUTE_SELECTION):
                to_st = CallState.ACTIVE
            else:
                to_st = CallState.ACTIVE
                is_valid = False
                reason = f"Connect in unexpected state {from_st.value}"

        trans = StateTransition(
            from_state=from_st,
            to_state=to_st,
            trigger_signal=event.signal or "UNKNOWN",
            timestamp=event.timestamp,
            is_valid=is_valid,
            reason=reason,
        )
        self.current_state = to_st
        self.history.append(trans)
        return trans


class MGCPStateMachine(BaseCallStateMachine):
    """State machine governing MGCP gateway call interactions."""

    def step(self, event: SDLEvent) -> StateTransition:
        sig = (event.signal or "").upper()
        raw = event.raw_text.upper()
        from_st = self.current_state
        to_st = from_st
        is_valid = True
        reason = None

        if "NTFY" in raw or "MGCPNOTIFY" in sig:
            if from_st == CallState.IDLE:
                to_st = CallState.CALL_START
        elif "CRCX" in raw:
            to_st = CallState.CALL_SETUP
        elif "RQNT" in raw:
            if "RG" in raw or "RING" in raw:
                to_st = CallState.ALERTING
        elif "MDCX" in raw:
            to_st = CallState.ACTIVE
        elif "DLCX" in raw:
            to_st = CallState.DISCONNECT
        elif "200 " in raw and from_st == CallState.DISCONNECT:
            to_st = CallState.CALL_END

        trans = StateTransition(
            from_state=from_st,
            to_state=to_st,
            trigger_signal=event.signal or "MGCP",
            timestamp=event.timestamp,
            is_valid=is_valid,
            reason=reason,
        )
        self.current_state = to_st
        self.history.append(trans)
        return trans


def get_state_machine_for_protocols(protocols: List[str]) -> BaseCallStateMachine:
    """Factory selecting the appropriate state machine based on observed protocols."""
    protos = {p.upper() for p in protocols}
    if "SIP" in protos:
        return SIPStateMachine()
    if "Q931" in protos or "ISDN" in protos:
        return Q931StateMachine()
    if "MGCP" in protos:
        return MGCPStateMachine()
    return SIPStateMachine()
