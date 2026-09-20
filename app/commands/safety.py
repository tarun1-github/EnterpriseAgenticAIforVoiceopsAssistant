"""Command safety enforcement, blocklists, and secret masking."""

import re
from typing import Optional, Tuple

# Commands that alter state, enter configuration mode, or perform destructive actions
BLOCKED_COMMAND_PREFIXES = [
    "configure",
    "conf t",
    "config t",
    "write",
    "wr",
    "reload",
    "erase",
    "delete",
    "del",
    "format",
    "shutdown",
    "shut",
    "no",
    "reboot",
    "rmdir",
    "mkdir",
    "rm",
    "copy",
    "utils system restart",
    "utils system reboot",
    "utils system shutdown",
    "file delete",
]

# Sensitive regex patterns to redact from outputs
SECRET_PATTERNS = [
    (re.compile(r"(password\s+(?:\d+\s+)?)(\S+)", re.IGNORECASE), r"\1********"),
    (re.compile(r"(secret\s+(?:\d+\s+)?)(\S+)", re.IGNORECASE), r"\1********"),
    (re.compile(r"(crypto\s+isakmp\s+key\s+)(\S+)", re.IGNORECASE), r"\1********"),
    (re.compile(r"(pre-shared-key\s+)(\S+)", re.IGNORECASE), r"\1********"),
    (re.compile(r"(key-string\s+)(\S+)", re.IGNORECASE), r"\1********"),
    (re.compile(r"(community\s+)(\S+)", re.IGNORECASE), r"\1********"),
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)", re.IGNORECASE), r"[REDACTED PRIVATE KEY]"),
    (re.compile(r"(api[_-]?key\s*[:=]\s*)['\"]?(\S+?)['\"]?(\s|$)", re.IGNORECASE), r"\1********\3"),
]


def validate_command_safety(command: str) -> Tuple[bool, Optional[str]]:
    """Validate that command is read-only and safe for execution.

    Args:
        command: Raw CLI command string.

    Returns:
        Tuple of (is_safe, failure_reason).
    """
    clean_cmd = command.strip().lower()

    if not clean_cmd:
        return False, "Command cannot be empty."

    # Check for blocked prefixes or exact commands
    for blocked in BLOCKED_COMMAND_PREFIXES:
        if clean_cmd == blocked or clean_cmd.startswith(blocked + " "):
            return False, f"Command '{command.strip()}' is blocked by safety policy (configuration or state-altering commands are not permitted)."

    return True, None


def mask_secrets(text: str) -> str:
    """Mask credentials, passwords, and cryptographic keys in text output.

    Args:
        text: Raw device command output.

    Returns:
        Sanitized text with sensitive tokens masked.
    """
    if not text:
        return ""

    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized
