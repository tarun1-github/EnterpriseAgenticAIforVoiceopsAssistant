"""CUCM-specific exceptions."""

from typing import Optional


class CUCMError(Exception):
    """Base exception for CUCM-related errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


class CUCMConnectionError(CUCMError):
    """Raised when SSH connection to CUCM fails."""

    def __init__(self, message: str, host: Optional[str] = None, port: Optional[int] = None):
        details = {}
        if host:
            details["host"] = host
        if port:
            details["port"] = port
        super().__init__(message, details)


class CUCMAuthenticationError(CUCMError):
    """Raised when CUCM authentication fails."""

    def __init__(self, message: str, username: Optional[str] = None):
        details = {}
        if username:
            details["username"] = username
        super().__init__(message, details)


class CUCMTimeoutError(CUCMError):
    """Raised when a CUCM operation times out."""

    def __init__(
        self,
        message: str,
        timeout_type: Optional[str] = None,
        timeout_value: Optional[int] = None,
    ):
        details = {}
        if timeout_type:
            details["timeout_type"] = timeout_type
        if timeout_value:
            details["timeout_value"] = timeout_value
        super().__init__(message, details)


class CUCMPromptError(CUCMError):
    """Raised when expected CUCM prompt is not detected."""

    def __init__(self, message: str, expected_prompt: Optional[str] = None):
        details = {}
        if expected_prompt:
            details["expected_prompt"] = expected_prompt
        super().__init__(message, details)


class CUCMCommandError(CUCMError):
    """Raised when a CUCM CLI command fails or returns unexpected output."""

    def __init__(
        self,
        message: str,
        command: Optional[str] = None,
        raw_output: Optional[str] = None,
    ):
        details = {}
        if command:
            details["command"] = command
        if raw_output:
            details["raw_output"] = raw_output[:500]
        super().__init__(message, details)


class CUCMTraceCollectionError(CUCMError):
    """Raised when SDL trace file collection fails."""

    def __init__(
        self,
        message: str,
        filename: Optional[str] = None,
        stage: Optional[str] = None,
    ):
        details = {}
        if filename:
            details["filename"] = filename
        if stage:
            details["stage"] = stage
        super().__init__(message, details)