#!/usr/bin/env python
"""CUCM Connection Diagnostic Tool.

Run this script against a real CUCM to validate connectivity and capabilities.

Usage:
    python scripts/cucm_diagnostic.py

Requires .env with:
    CUCM_HOST=10.197.206.141
    CUCM_USERNAME=Administrator
    CUCM_PASSWORD=c1sc0123!
    CUCM_SSH_PORT=22
"""

import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from app.core.config import get_settings
from app.core.logging import setup_logging, get_logger
from app.devices.cucm import CUCMClient

setup_logging()
logger = get_logger("cucm_diagnostic")


def print_header(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_step(step: str, status: str, details: str = "") -> None:
    icons = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "INFO": "ℹ️", "RUN": "🔄"}
    icon = icons.get(status, "  ")
    print(f"  {icon} {step:<40} {details}")


def run_diagnostic() -> int:
    """Run full CUCM diagnostic. Returns exit code."""
    settings = get_settings()

    print_header("VoiceOps AI - CUCM Connection Diagnostic")
    print(f"Target: {settings.cucm_host}:{settings.cucm_ssh_port}")
    print(f"User: {settings.cucm_username}")

    if not settings.cucm_host or not settings.cucm_username:
        print_step("Configuration", "FAIL", "CUCM_HOST or CUCM_USERNAME not set in .env")
        return 1

    client = CUCMClient()
    results = {}

    # Test 1: SSH Connectivity
    print_step("SSH Connectivity", "RUN")
    try:
        client.connect()
        results["ssh"] = True
        print_step("SSH Connectivity", "PASS", f"Connected to {settings.cucm_host}")
    except Exception as e:
        results["ssh"] = False
        print_step("SSH Connectivity", "FAIL", str(e))
        return 1

    # Test 2: Authentication (implicit in connect)
    results["auth"] = True
    print_step("Authentication", "PASS", "Credentials accepted")

    # Test 3: CUCM Prompt Detection
    print_step("CUCM Prompt Detection", "RUN")
    try:
        prompt = client.get_prompt()
        results["prompt"] = True
        print_step("CUCM Prompt Detection", "PASS", f"Prompt: {prompt}")
    except Exception as e:
        results["prompt"] = False
        print_step("CUCM Prompt Detection", "FAIL", str(e))

    # Test 4: Command Execution
    print_step("Command Execution", "RUN")
    try:
        output = client.execute_read_only("show version active")
        if output and len(output) > 10:
            results["command"] = True
            print_step("Command Execution", "PASS", "Command returned output")
        else:
            results["command"] = False
            print_step("Command Execution", "FAIL", "Empty or minimal output")
    except Exception as e:
        results["command"] = False
        print_step("Command Execution", "FAIL", str(e))

    # Test 5: CUCM Version
    print_step("CUCM Version Retrieval", "RUN")
    try:
        version = client.get_version()
        results["version"] = True
        print_step("CUCM Version Retrieval", "PASS", f"Version: {version.version}, Build: {version.build or 'N/A'}")
        print(f"\n    Full Version: {version.full_version}")
        print(f"    Edition: {version.edition or 'N/A'}")
        print(f"    Install Date: {version.install_date or 'N/A'}")
    except Exception as e:
        results["version"] = False
        print_step("CUCM Version Retrieval", "FAIL", str(e))

    # Test 6: SDL Directory Access
    print_step("SDL Directory Access", "RUN")
    try:
        files = client.list_sdl_files()
        results["sdl_dir"] = True
        print_step("SDL Directory Access", "PASS", f"Directory accessible, {len(files)} file(s) found")
        for f in files[:5]:
            print(f"    - {f.filename} ({f.to_dict()['size_mb']} MB, {f.modified})")
        if len(files) > 5:
            print(f"    ... and {len(files) - 5} more")
    except Exception as e:
        results["sdl_dir"] = False
        print_step("SDL Directory Access", "FAIL", str(e))

    # Test 7: SDL File Discovery
    if results.get("sdl_dir"):
        results["sdl_files"] = True
        print_step("SDL File Discovery", "PASS", f"{len(files)} trace file(s) catalogued")
    else:
        results["sdl_files"] = False
        print_step("SDL File Discovery", "FAIL", "Directory not accessible")

    # Overall Summary
    print_header("Diagnostic Summary")
    all_pass = all(results.values())
    for test, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print_step(test.replace("_", " ").title(), status)

    overall = "READY" if all_pass else "PARTIAL" if any(results.values()) else "FAIL"
    overall_icon = "✅" if overall == "READY" else "⚠️" if overall == "PARTIAL" else "❌"
    print(f"\n  {overall_icon} Overall Status: {overall}")

    if overall == "READY":
        print("\n  🎉 CUCM is ready for trace collection!")
        print("  Next steps:")
        print("    1. Run trace collection via Streamlit UI or collector")
        print("    2. Ingest collected traces into VoiceOps pipeline")
        print("    3. Correlate with gateway/ISDN traces")
    elif overall == "PARTIAL":
        print("\n  ⚠️  Some checks passed. Review failures above.")
        print("  Common issues:")
        print("    - Firewall blocking SSH (port 22)")
        print("    - CUCM CLI privilege level")
        print("    - Network connectivity")
    else:
        print("\n  ❌ CUCM connection failed.")
        print("  Check:")
        print("    - Host IP/hostname in .env")
        print("    - SSH port (default 22)")
        print("    - Credentials")
        print("    - Network reachability")

    client.disconnect()
    return 0 if overall == "READY" else 1


if __name__ == "__main__":
    sys.exit(run_diagnostic())