"""High-level CUCM client for version detection and SDL trace discovery."""

from typing import List, Optional
from app.core.logging import get_logger
from app.core.config import get_settings
from app.devices.cucm.transport import CUCMTransport, create_transport, TransportConfig
from app.devices.cucm.models import CUCMVersion, CUCMTraceFile
from app.devices.cucm.exceptions import (
    CUCMConnectionError,
    CUCMCommandError,
    CUCMTimeoutError,
)

logger = get_logger("devices.cucm.client")


class CUCMClient:
    """High-level CUCM CLI client for read-only operations."""

    def __init__(self, transport: Optional[CUCMTransport] = None):
        self._transport = transport
        self._connected = False

    def connect(self) -> None:
        """Establish connection to CUCM."""
        if self._transport is None:
            self._transport = create_transport()

        self._transport.connect()
        self._connected = True
        logger.info("CUCM client connected")

    def disconnect(self) -> None:
        """Close connection to CUCM."""
        if self._transport and self._connected:
            self._transport.disconnect()
            self._connected = False
            logger.info("CUCM client disconnected")

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected and self._transport and self._transport.is_connected()

    def __enter__(self) -> "CUCMClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()

    def get_version(self) -> CUCMVersion:
        """Get CUCM version information.

        Returns:
            CUCMVersion with parsed version details.

        Raises:
            CUCMConnectionError: If not connected.
            CUCMCommandError: If command fails.
        """
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        logger.info("Retrieving CUCM version")
        output = self._transport.send_command("show version active")
        return CUCMVersion.from_cli_output(output)

    def list_sdl_files(self, path: str = "activelog/cm/trace/ccm/sdl") -> List[CUCMTraceFile]:
        """List SDL trace files in the specified directory.

        Args:
            path: Directory path on CUCM (default: activelog/cm/trace/ccm/sdl)

        Returns:
            List of CUCMTraceFile objects.

        Raises:
            CUCMConnectionError: If not connected.
            CUCMCommandError: If command fails.
        """
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        logger.info("Discovering SDL files in %s", path)
        command = f"file list {path} detail"
        output = self._transport.send_command(command)

        files = []
        for line in output.splitlines():
            trace_file = CUCMTraceFile.from_file_list_output(line, path)
            if trace_file:
                files.append(trace_file)

        logger.info("Found %d SDL trace files", len(files))
        return files

    def get_sdl_file_content(self, filename: str, path: str = "activelog/cm/trace/ccm/sdl") -> str:
        """Get content of a specific SDL trace file.

        Note: This uses 'file view' which may be limited for large files.
        For production use, use CUCMTraceCollector with file get + SFTP.

        Args:
            filename: Name of the SDL file.
            path: Directory path on CUCM.

        Returns:
            File content as string.

        Raises:
            CUCMConnectionError: If not connected.
            CUCMCommandError: If command fails.
        """
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        full_path = f"{path}/{filename}"
        logger.info("Reading SDL file: %s", full_path)
        command = f"file view {full_path}"
        return self._transport.send_command(command)

    def run_diagnostic(self) -> dict:
        """Run connection and capability diagnostic.

        Returns:
            Dictionary with diagnostic results.
        """
        results = {
            "ssh_connectivity": {"status": "UNKNOWN", "details": ""},
            "authentication": {"status": "UNKNOWN", "details": ""},
            "cucm_prompt": {"status": "UNKNOWN", "details": ""},
            "command_execution": {"status": "UNKNOWN", "details": ""},
            "cucm_version": {"status": "UNKNOWN", "details": ""},
            "sdl_directory": {"status": "UNKNOWN", "details": ""},
            "sdl_files": {"status": "UNKNOWN", "details": ""},
            "overall": "UNKNOWN",
        }

        # Test 1: SSH Connectivity
        try:
            if not self.is_connected():
                self.connect()
            results["ssh_connectivity"] = {"status": "PASS", "details": "SSH connection established"}
            results["authentication"] = {"status": "PASS", "details": "Authentication successful"}
        except Exception as e:
            results["ssh_connectivity"] = {"status": "FAIL", "details": str(e)}
            results["overall"] = "FAIL"
            return results

        # Test 2: CUCM Prompt
        try:
            prompt = self._transport.get_prompt()
            results["cucm_prompt"] = {"status": "PASS", "details": f"Prompt detected: {prompt}"}
        except Exception as e:
            results["cucm_prompt"] = {"status": "FAIL", "details": str(e)}
            results["overall"] = "FAIL"
            return results

        # Test 3: Command Execution
        try:
            output = self._transport.send_command("show version active")
            if output:
                results["command_execution"] = {"status": "PASS", "details": "Command executed successfully"}
            else:
                results["command_execution"] = {"status": "FAIL", "details": "Empty output"}
        except Exception as e:
            results["command_execution"] = {"status": "FAIL", "details": str(e)}
            results["overall"] = "FAIL"
            return results

        # Test 4: CUCM Version
        try:
            version = self.get_version()
            results["cucm_version"] = {
                "status": "PASS",
                "details": f"Version: {version.version}, Build: {version.build or 'N/A'}"
            }
        except Exception as e:
            results["cucm_version"] = {"status": "FAIL", "details": str(e)}

        # Test 5: SDL Directory
        try:
            files = self.list_sdl_files()
            results["sdl_directory"] = {"status": "PASS", "details": "SDL directory accessible"}
            results["sdl_files"] = {"status": "PASS", "details": f"{len(files)} SDL file(s) found"}
        except Exception as e:
            results["sdl_directory"] = {"status": "FAIL", "details": str(e)}
            results["sdl_files"] = {"status": "FAIL", "details": str(e)}

        # Overall
        if all(r["status"] == "PASS" for r in results.values() if isinstance(r, dict) and r != results):
            results["overall"] = "READY"
        else:
            results["overall"] = "PARTIAL"

        return results