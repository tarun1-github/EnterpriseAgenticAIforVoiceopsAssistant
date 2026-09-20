"""Export formatting and filename sanitization for Device Command Center."""

import re
from datetime import datetime, timezone
from typing import Optional


def sanitize_command_for_filename(command: str) -> str:
    """Sanitize CLI command string for safe inclusion in filenames.

    Replaces non-alphanumeric characters with hyphens and truncates if necessary.
    """
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", command.strip()).strip("-").lower()
    return cleaned[:40] if cleaned else "cmd"


def generate_command_filename(
    device_type: str,
    ip: str,
    command: str,
    dt: Optional[datetime] = None,
) -> str:
    """Generate standardized filename for command output download.

    Format: <DEVICE>_<IP>_<command-sanitized>_<YYYYMMDD_HHMMSS>.txt
    Example: CUCM_10.197.206.141_show-version-active_20260920_164532.txt
    """
    if dt is None:
        dt = datetime.now()

    clean_dev = device_type.strip().upper()
    clean_ip = re.sub(r"[^a-zA-Z0-9.]+", "_", ip.strip())
    sanitized_cmd = sanitize_command_for_filename(command)
    ts_str = dt.strftime("%Y%m%d_%H%M%S")

    return f"{clean_dev}_{clean_ip}_{sanitized_cmd}_{ts_str}.txt"


def format_command_output_package(
    device_type: str,
    ip: str,
    command: str,
    status: str,
    output: str,
    prompt: Optional[str] = None,
    timestamp_str: Optional[str] = None,
) -> str:
    """Format downloadable command evidence text file with forensic metadata header.

    Structure:
    ==================================================
    VoiceOps AI - Device Command Output
    ===================================

    Device Type : CUCM
    Device IP   : 10.197.206.141
    Timestamp   : 2026-09-20 16:45:32 IST
    Command     : show version active
    Status      : SUCCESS

    ==================================================
    REQUEST
    =======

    show version active

    ==================================================
    RESPONSE
    ========

    admin:show version active
    ...
    """
    if not timestamp_str:
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Format response block with prompt if available
    cmd_clean = command.strip()
    resp_text = output.strip() if output else ""

    if prompt and resp_text:
        # Avoid double prompt if response already starts with prompt
        if not resp_text.startswith(prompt):
            full_resp = f"{prompt}{cmd_clean}\n\n{resp_text}"
        else:
            full_resp = resp_text
    elif prompt and not resp_text:
        full_resp = f"{prompt}{cmd_clean}\n(No output or command returned empty)"
    else:
        full_resp = resp_text if resp_text else "(No output or command returned empty)"

    text = (
        "==================================================\n"
        "VoiceOps AI - Device Command Output\n"
        "===================================\n\n"
        f"Device Type : {device_type}\n"
        f"Device IP   : {ip}\n"
        f"Timestamp   : {timestamp_str}\n"
        f"Command     : {cmd_clean}\n"
        f"Status      : {status}\n\n"
        "==================================================\n"
        "REQUEST\n"
        "=======\n\n"
        f"{cmd_clean}\n\n"
        "==================================================\n"
        "RESPONSE\n"
        "========\n\n"
        f"{full_resp}\n"
    )
    return text
