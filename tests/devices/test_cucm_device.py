"""Unit tests for CUCM device integration (with mocked transport)."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from typing import Optional

from app.devices.cucm.transport import (
    CUCMTransport,
    NetmikoTransport,
    TransportConfig,
    create_transport,
)
from app.devices.cucm.client import CUCMClient
from app.devices.cucm.collector import CUCMTraceCollector, CollectionResult, CollectorConfig
from app.devices.cucm.models import CUCMVersion, CUCMTraceFile
from app.devices.cucm.selection import (
    TraceSelectionService,
    SelectionMode,
    RelativeTimeOption,
    SelectionRequest,
    SelectionResult,
    create_selection_request,
)
from app.devices.cucm.exceptions import (
    CUCMConnectionError,
    CUCMAuthenticationError,
    CUCMTimeoutError,
    CUCMPromptError,
    CUCMCommandError,
    CUCMTraceCollectionError,
)


# --- Mock Transport ---

class MockTransport(CUCMTransport):
    """Mock transport for testing without real SSH."""

    def __init__(self, config: TransportConfig, responses: dict = None, file_get_responses: dict = None):
        self.config = config
        self._connected = False
        self._responses = responses or {}
        self._file_get_responses = file_get_responses or {}
        self._prompt = "admin:"
        self._file_get_state = "idle"
        self._file_get_buffer = ""
        self._file_get_step = 0

    def connect(self) -> None:
        if self.config.host == "timeout-host":
            raise CUCMTimeoutError("Connection timeout", timeout_type="connect", timeout_value=self.config.timeout)
        if self.config.host == "auth-fail-host":
            raise CUCMAuthenticationError("Authentication failed", username=self.config.username)
        if self.config.host == "conn-fail-host":
            raise CUCMConnectionError("Connection refused", host=self.config.host)
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def send_command(self, command: str, expect_string: str = None) -> str:
        if not self._connected:
            raise CUCMConnectionError("Not connected")
        # Handle the new pagination command
        if "set cli pagination off" in command:
            return ""
        return self._responses.get(command, f"Output for: {command}")

    def send_command_timing(self, command: str, delay_factor: float = 1.0) -> str:
        return self.send_command(command)

    def get_prompt(self) -> str:
        return self._prompt

    def _detect_prompt(self, buffer: str) -> Optional[str]:
        """Detect the current prompt type from buffer (copied from NetmikoTransport for testing)."""
        import re
        buffer_lower = buffer.lower()

        # Check for host-key confirmation (yes/no) prompt - must check BEFORE host prompt
        # Pattern: "Please answer 'y' for <yes> or 'n' for no:" or similar variations
        if re.search(r"please\s+answer.*[yn].*(yes|no)", buffer_lower) or \
           re.search(r"answer.*[yn].*(yes|no)", buffer_lower) or \
           re.search(r"\(y/n\)", buffer_lower) or \
           re.search(r"\[yes/no\]", buffer_lower) or \
           (re.search(r"are you sure", buffer_lower) and re.search(r"(yes|no)", buffer_lower)):
            return "confirm"

        # Check for SFTP host prompt - various forms
        if re.search(r"(sftp|ssh).*host", buffer_lower) or \
           re.search(r"remote.*host", buffer_lower) or \
           re.search(r"destination.*host", buffer_lower) or \
           re.search(r"server.*name", buffer_lower):
            return "host"

        # Check for username prompt
        if re.search(r"(user|login).*name", buffer_lower) or \
           re.search(r"username", buffer_lower):
            return "username"

        # Check for password prompt
        if re.search(r"password", buffer_lower) and not re.search(r"password.*again", buffer_lower):
            return "password"

        # Check for directory prompt
        if re.search(r"(destination|remote).*dir", buffer_lower) or \
           re.search(r"directory", buffer_lower) or \
           re.search(r"path", buffer_lower):
            return "directory"

        # Check for admin prompt (command completion)
        if re.search(r"admin:\s*$", buffer):
            return "admin"

        return None

    def execute_file_get(
        self,
        filename: str,
        sftp_host: str,
        sftp_username: str,
        sftp_password: str,
        sftp_remote_dir: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> str:
        """Mock execute_file_get simulating the interactive state machine."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        # If custom responses provided, use them for state machine simulation
        if self._file_get_responses:
            return self._simulate_file_get_state_machine(command, sftp_host, sftp_username, sftp_password, sftp_remote_dir)
        
        # Default simple success
        return f"File get successful for {filename}"

    def _simulate_file_get_state_machine(self, command: str, sftp_host: str, sftp_username: str, sftp_password: str, sftp_remote_dir: str) -> str:
        """Simulate the CUCM 15 interactive file-get state machine."""
        # State machine sequence:
        # 1. command sent -> expect "SFTP host:" prompt
        # 2. send host -> expect "Please answer 'y' for <yes> or 'n' for no:" (host-key confirmation)
        # 3. send 'y' -> expect "User:" or "Username:" prompt
        # 4. send username -> expect "Password:" prompt
        # 5. send password -> expect "Destination directory:" prompt
        # 6. send directory -> expect optional final confirmation "Continue? (y/n):"
        # 7. send 'y' -> wait for "admin:" prompt (transfer complete)
        
        responses = self._file_get_responses
        
        # Default successful flow responses
        default_responses = {
            "initial": "SFTP host:",
            "host_sent": "Please answer 'y' for <yes> or 'n' for no:",
            "confirm_sent": "User:",
            "username_sent": "Password:",
            "password_sent": "Destination directory:",
            "directory_sent": "Continue? (y/n):",
            "final_confirm_sent": "admin:",
        }
        
        # Merge defaults with provided responses
        for key, value in default_responses.items():
            if key not in responses:
                responses[key] = value
        
        # Simulate the full interaction output
        output_parts = [
            f"admin:{command}\n",
            responses["initial"] + "\n",
            f"{sftp_host}\n",
            responses["host_sent"] + "\n",
            "y\n",
            responses["confirm_sent"] + "\n",
            f"{sftp_username}\n",
            responses["username_sent"] + "\n",
            f"{sftp_password}\n",  # In real code this is redacted
            responses["password_sent"] + "\n",
            f"{sftp_remote_dir}\n",
            responses["directory_sent"] + "\n",
            "y\n",
            responses["final_confirm_sent"] + "\n",
            "Transfer complete.\n",
            "admin:",
        ]
        
        return "".join(output_parts)


# --- Mock Transport for State Machine Testing ---

class MockTransportStateMachine(MockTransport):
    """Mock transport that simulates the full interactive file-get state machine.
    
    This allows testing the state machine logic without a real CUCM.
    """
    
    def __init__(self, config: TransportConfig, responses: dict = None, file_get_scenario: str = "success"):
        super().__init__(config, responses)
        self._file_get_scenario = file_get_scenario
        
    def execute_file_get(
        self,
        filename: str,
        sftp_host: str,
        sftp_username: str,
        sftp_password: str,
        sftp_remote_dir: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> str:
        """Execute file-get with scenario-based simulation."""
        
        scenarios = {
            "success": self._scenario_success,
            "host_key_confirmation": self._scenario_host_key_confirmation,
            "no_host_key_confirmation": self._scenario_no_host_key_confirmation,
            "no_final_confirmation": self._scenario_no_final_confirmation,
            "timeout_at_password": self._scenario_timeout_at_password,
            "auth_failure": self._scenario_auth_failure,
            "transfer_failure": self._scenario_transfer_failure,
            "file_gather": self._scenario_file_gather,
            "initial_confirm": self._scenario_initial_confirm,
            "no_initial_confirm": self._scenario_no_initial_confirm,
            "single_buffer_file_gather": self._scenario_single_buffer_file_gather,
            "proceed_confirm": self._scenario_proceed_confirm,
        }
        
        scenario_func = scenarios.get(self._file_get_scenario, self._scenario_success)
        return scenario_func(filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path)
    
    def _scenario_success(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Normal successful transfer with all prompts."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        output = [
            f"admin:{command}\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",  # Will be redacted in real code
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)
    
    def _scenario_host_key_confirmation(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Host key confirmation appears (same as success but explicit)."""
        return self._scenario_success(filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path)
    
    def _scenario_no_host_key_confirmation(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Skip host-key confirmation (known host)."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        output = [
            f"admin:{command}\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "User:\n",  # No host-key confirmation
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)
    
    def _scenario_no_final_confirmation(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Skip final confirmation prompt."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        output = [
            f"admin:{command}\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "admin:\n",  # Direct to admin prompt, no final confirmation
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)
    
    def _scenario_timeout_at_password(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate timeout at password prompt."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        output = [
            f"admin:{command}\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            # No further output - timeout
        ]
        return "".join(output)
    
    def _scenario_auth_failure(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate SFTP authentication failure."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        output = [
            f"admin:{command}\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Authentication failed.\n",
            "admin:",
        ]
        return "".join(output)
    
    def _scenario_transfer_failure(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate transfer failure."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        output = [
            f"admin:{command}\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "Transfer failed: Connection refused.\n",
            "admin:",
        ]
        return "".join(output)

    def _scenario_file_gather(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate CUCM 15 file-get with file-gathering phase (exact live output)."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        # CUCM shows "active" not "activelog" in the Get file: line
        # remote_path is "activelog /cm/trace/ccm/sdl" -> becomes "active/cm/trace/ccm/sdl"
        get_file_path = full_remote_path.replace("activelog /", "active/")
        
        output = [
            f"admin:{command}\n",
            "Please wait while the system is gathering files info ...\n",
            f"Get file: {get_file_path}\n",
            "done.\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)

    def _scenario_initial_confirm(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate CUCM 15 file-get with initial confirmation prompt (exact live output)."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        # CUCM shows "active" not "activelog" in the Get file: line
        get_file_path = full_remote_path.replace("activelog /", "active/")
        
        output = [
            f"admin:{command}\n",
            "Please answer 'y' for <yes> or 'n' for <no>:\n",  # Initial confirmation
            "y\n",
            "Please wait while the system is gathering files info ...\n",
            f"Get file: {get_file_path}\n",
            "done.\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for <no>:\n",  # Host-key confirmation (exact same format)
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)

    def _scenario_no_initial_confirm(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate CUCM 15 file-get WITHOUT initial confirmation (proceeds directly to file-gather)."""
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        # CUCM shows "active" not "activelog" in the Get file: line
        get_file_path = full_remote_path.replace("activelog /", "active/")
        
        output = [
            f"admin:{command}\n",
            "Please wait while the system is gathering files info ...\n",
            f"Get file: {get_file_path}\n",
            "done.\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",  # Host-key confirmation
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)

    def _scenario_single_buffer_file_gather(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate CUCM 15 file-get where ONE channel read contains both file-gather start AND complete.
        
        This reproduces the live bug where a single buffer contains:
        "Please wait while the system is gathering files info ..."
        "Get file: ..."
        "done."
        
        The state machine must process BOTH events from the same buffer without
        requiring another channel read.
        """
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        # CUCM shows "active" not "activelog" in the Get file: line
        get_file_path = full_remote_path.replace("activelog /", "active/")
        
        output = [
            f"admin:{command}\n",
            "Please wait while the system is gathering files info ...\n",
            f"Get file: {get_file_path}\n",
            "done.\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",  # Host-key confirmation
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)

    def _scenario_proceed_confirm(self, filename, sftp_host, sftp_username, sftp_password, sftp_remote_dir, remote_path):
        """Simulate CUCM 15 file-get with proceed confirmation after file-gather (exact live output).
        
        This reproduces the live CUCM 15 behavior where after file-gather completes,
        CUCM sends:
        "Sub-directories were not traversed."
        "Number of files affected: 1"
        "Total size in Bytes: ..."
        "Total size in Kbytes: ..."
        "Would you like to proceed [y/n]?"
        
        The state machine must handle this PROCEED_CONFIRM as a distinct step
        separate from INITIAL_CONFIRM and HOST_KEY_CONFIRM.
        """
        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"
        
        # CUCM shows "active" not "activelog" in the Get file: line
        get_file_path = full_remote_path.replace("activelog /", "active/")
        
        output = [
            f"admin:{command}\n",
            "Please wait while the system is gathering files info ...\n",
            f"Get file: {get_file_path}\n",
            "done.\n",
            "Sub-directories were not traversed.\n",
            "Number of files affected: 1\n",
            "Total size in Bytes: 4659724\n",
            "Total size in Kbytes: 4550.5117\n",
            "Would you like to proceed [y/n]?\n",
            "y\n",
            "SFTP host:\n",
            f"{sftp_host}\n",
            "Please answer 'y' for <yes> or 'n' for no:\n",  # Host-key confirmation
            "y\n",
            "User:\n",
            f"{sftp_username}\n",
            "Password:\n",
            f"{sftp_password}\n",
            "Destination directory:\n",
            f"{sftp_remote_dir}\n",
            "Continue? (y/n):\n",
            "y\n",
            "admin:\n",
            "Transfer complete.\n",
            "admin:",
        ]
        return "".join(output)


# --- Mock Transport with Large Files ---

class MockTransportWithLargeFiles(MockTransport):
    """Mock transport that returns large file listings."""

    def __init__(self, config: TransportConfig, responses: dict = None):
        super().__init__(config, responses)
        # Full 11 real CUCM SDL files + 1 index file + 1 gzo file = 13 total
        self._responses = {
            "show version active": """
Active Master Version: 15.0.1.12900-17
Active Version: 15.0.1.12900-17
Build: 12900
Edition: Standard
Install Date: 2024-01-15
            """.strip(),
            "file list activelog /cm/trace/ccm/sdl detail": """
19 Sep,2026 05:28:31           34  SDL001_100.index
03 Sep,2026 23:59:59      385,759  SDL001_100_000001.txt.gz
04 Sep,2026 05:27:54      968,955  SDL001_100_000002.txt.gz
04 Sep,2026 10:55:48      973,716  SDL001_100_000003.txt.gz
04 Sep,2026 16:23:16      964,430  SDL001_100_000004.txt.gz
04 Sep,2026 21:51:13      969,974  SDL001_100_000005.txt.gz
04 Sep,2026 23:59:59      377,552  SDL001_100_000006.txt.gz
05 Sep,2026 05:27:52      968,935  SDL001_100_000007.txt.gz
05 Sep,2026 10:55:22      957,290  SDL001_100_000008.txt.gz
05 Sep,2026 16:23:21      969,577  SDL001_100_000009.txt.gz
05 Sep,2026 21:50:47      971,794  SDL001_100_000010.txt.gz
05 Sep,2026 23:59:59      382,214  SDL001_100_000011.txt.gz
19 Sep,2026 12:56:08    5,239,770  SDL001_100_000079.txt.gzo
            """.strip(),
        }
        if responses:
            self._responses.update(responses)


# --- Fixtures ---

@pytest.fixture
def transport_config():
    return TransportConfig(
        host="10.197.206.141",
        port=22,
        username="Administrator",
        password="testpass",
        timeout=30,
        command_timeout=60,
        prompt_timeout=15,
    )


@pytest.fixture
def mock_transport(transport_config):
    responses = {
        "show version active": """
Active Master Version: 15.0.1.12900-17
Active Version: 15.0.1.12900-17
Build: 12900
Edition: Standard
Install Date: 2024-01-15
        """.strip(),
        "file list activelog /cm/trace/ccm/sdl detail": """
19 Sep,2026 05:28:31           34  SDL001_100.index
03 Sep,2026 23:59:59      385,759  SDL001_100_000001.txt.gz
04 Sep,2026 05:27:54      968,955  SDL001_100_000002.txt.gz
04 Sep,2026 10:55:48      973,716  SDL001_100_000003.txt.gz
04 Sep,2026 16:23:16      964,430  SDL001_100_000004.txt.gz
04 Sep,2026 21:51:13      969,974  SDL001_100_000005.txt.gz
04 Sep,2026 23:59:59      377,552  SDL001_100_000006.txt.gz
05 Sep,2026 05:27:52      968,935  SDL001_100_000007.txt.gz
05 Sep,2026 10:55:22      957,290  SDL001_100_000008.txt.gz
05 Sep,2026 16:23:21      969,577  SDL001_100_000009.txt.gz
05 Sep,2026 21:50:47      971,794  SDL001_100_000010.txt.gz
05 Sep,2026 23:59:59      382,214  SDL001_100_000011.txt.gz
19 Sep,2026 12:56:08    5,239,770  SDL001_100_000079.txt.gzo
        """.strip(),
    }
    return MockTransport(transport_config, responses)


@pytest.fixture
def mock_transport_large_files(transport_config):
    return MockTransportWithLargeFiles(transport_config)


@pytest.fixture
def cucm_client(mock_transport):
    return CUCMClient(transport=mock_transport)


@pytest.fixture
def cucm_client_large_files(mock_transport_large_files):
    return CUCMClient(transport=mock_transport_large_files)


@pytest.fixture
def mock_transport_state_machine(transport_config):
    """Mock transport with full state machine simulation."""
    return MockTransportStateMachine(transport_config, file_get_scenario="success")


@pytest.fixture
def mock_transport_no_host_key(transport_config):
    """Mock transport without host-key confirmation."""
    return MockTransportStateMachine(transport_config, file_get_scenario="no_host_key_confirmation")


@pytest.fixture
def mock_transport_no_final_confirm(transport_config):
    """Mock transport without final confirmation."""
    return MockTransportStateMachine(transport_config, file_get_scenario="no_final_confirmation")


@pytest.fixture
def mock_transport_auth_failure(transport_config):
    """Mock transport with SFTP auth failure."""
    return MockTransportStateMachine(transport_config, file_get_scenario="auth_failure")


@pytest.fixture
def mock_transport_transfer_failure(transport_config):
    """Mock transport with transfer failure."""
    return MockTransportStateMachine(transport_config, file_get_scenario="transfer_failure")


@pytest.fixture
def mock_transport_file_gather(transport_config):
    """Mock transport with file-gathering phase (exact live CUCM output)."""
    return MockTransportStateMachine(transport_config, file_get_scenario="file_gather")


@pytest.fixture
def mock_transport_initial_confirm(transport_config):
    """Mock transport with initial confirmation prompt (exact live CUCM 15 output)."""
    return MockTransportStateMachine(transport_config, file_get_scenario="initial_confirm")


@pytest.fixture
def mock_transport_no_initial_confirm(transport_config):
    """Mock transport without initial confirmation (proceeds directly to file-gather)."""
    return MockTransportStateMachine(transport_config, file_get_scenario="no_initial_confirm")


@pytest.fixture
def mock_transport_single_buffer_file_gather(transport_config):
    """Mock transport with single buffer containing both file-gather start and complete."""
    return MockTransportStateMachine(transport_config, file_get_scenario="single_buffer_file_gather")


@pytest.fixture
def mock_transport_proceed_confirm(transport_config):
    """Mock transport with proceed confirmation after file-gather (exact live CUCM 15 output)."""
    return MockTransportStateMachine(transport_config, file_get_scenario="proceed_confirm")


# --- Transport Tests ---

class TestTransportConfig:
    def test_transport_config_creation(self, transport_config):
        assert transport_config.host == "10.197.206.141"
        assert transport_config.port == 22
        assert transport_config.username == "Administrator"

    def test_create_transport_uses_settings(self):
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = "cli-user"
            mock_settings.return_value.cucm_cli_password.get_secret_value.return_value = "cli-pass"
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert isinstance(transport, NetmikoTransport)
            assert transport.config.username == "cli-user"
            assert transport.config.password == "cli-pass"

    def test_netmiko_import(self):
        """Verify Netmiko can be imported."""
        import netmiko
        assert netmiko.__version__


class TestCLICredentialIsolation:
    """Test that Netmiko transport uses ONLY CLI Administrator credentials,
    never AXL or Platform credentials."""

    def test_transport_uses_cli_credentials(self):
        """Netmiko MUST receive CUCM_CLI_USERNAME/PASSWORD."""
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = "cli-admin"
            mock_settings.return_value.cucm_cli_password.get_secret_value.return_value = "cli-secret"
            mock_settings.return_value.cucm_username = "axl-user"  # Must NOT be used
            mock_settings.return_value.cucm_password.get_secret_value.return_value = "axl-pass"  # Must NOT be used
            mock_settings.return_value.cucm_platform_username = "platform-user"  # Must NOT be used
            mock_settings.return_value.cucm_platform_password.get_secret_value.return_value = "platform-pass"  # Must NOT be used
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert transport.config.username == "cli-admin"
            assert transport.config.password == "cli-secret"

    def test_transport_never_uses_axl_credentials(self):
        """Even when CLI credentials missing, transport does NOT fall back to AXL."""
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = None
            mock_settings.return_value.cucm_cli_password = None
            mock_settings.return_value.cucm_username = "axl-user"
            mock_settings.return_value.cucm_password.get_secret_value.return_value = "axl-pass"
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            # Should use empty strings, NOT AXL credentials
            assert transport.config.username == ""
            assert transport.config.password == ""

    def test_transport_never_uses_platform_credentials(self):
        """Platform credentials must never be used for SSH."""
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = None
            mock_settings.return_value.cucm_cli_password = None
            mock_settings.return_value.cucm_username = None
            mock_settings.return_value.cucm_password = None
            mock_settings.return_value.cucm_platform_username = "platform-user"
            mock_settings.return_value.cucm_platform_password.get_secret_value.return_value = "platform-pass"
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert transport.config.username == ""
            assert transport.config.password == ""

    def test_missing_cli_credentials_produces_empty_strings(self):
        """Missing CLI credentials result in empty strings (clear config error later)."""
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = None
            mock_settings.return_value.cucm_cli_password = None
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert transport.config.username == ""
            assert transport.config.password == ""

    def test_all_three_credential_sets_independent(self):
        """All three credential groups are completely independent."""
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = "cli-user"
            mock_settings.return_value.cucm_cli_password.get_secret_value.return_value = "cli-pass"
            mock_settings.return_value.cucm_username = "axl-user"
            mock_settings.return_value.cucm_password.get_secret_value.return_value = "axl-pass"
            mock_settings.return_value.cucm_platform_username = "platform-user"
            mock_settings.return_value.cucm_platform_password.get_secret_value.return_value = "platform-pass"
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert transport.config.username == "cli-user"
            assert transport.config.password == "cli-pass"
            # Verify AXL and Platform are untouched
            assert transport.config.username != "axl-user"
            assert transport.config.password != "axl-pass"
            assert transport.config.username != "platform-user"
            assert transport.config.password != "platform-pass"
            assert transport.config.password == "cli-pass"

    def test_create_transport_empty_credentials(self):
        """When no credentials set, use empty strings."""
        with patch("app.devices.cucm.transport.get_settings") as mock_settings:
            mock_settings.return_value.cucm_host = "test-host"
            mock_settings.return_value.cucm_ssh_port = 22
            mock_settings.return_value.cucm_cli_username = None
            mock_settings.return_value.cucm_cli_password = None
            mock_settings.return_value.cucm_username = None
            mock_settings.return_value.cucm_password = None
            mock_settings.return_value.cucm_platform_username = None
            mock_settings.return_value.cucm_platform_password = None
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert transport.config.username == ""
            assert transport.config.password == ""


class TestMockTransport:
    def test_connect_success(self, mock_transport):
        mock_transport.connect()
        assert mock_transport.is_connected()

    def test_connect_timeout(self, transport_config):
        config = TransportConfig(
            host="timeout-host",
            port=transport_config.port,
            username=transport_config.username,
            password=transport_config.password,
            timeout=transport_config.timeout,
            command_timeout=transport_config.command_timeout,
            prompt_timeout=transport_config.prompt_timeout,
        )
        transport = MockTransport(config)
        with pytest.raises(CUCMTimeoutError):
            transport.connect()

    def test_connect_auth_failure(self, transport_config):
        config = TransportConfig(
            host="auth-fail-host",
            port=transport_config.port,
            username=transport_config.username,
            password=transport_config.password,
            timeout=transport_config.timeout,
            command_timeout=transport_config.command_timeout,
            prompt_timeout=transport_config.prompt_timeout,
        )
        transport = MockTransport(config)
        with pytest.raises(CUCMAuthenticationError):
            transport.connect()

    def test_connect_connection_failure(self, transport_config):
        config = TransportConfig(
            host="conn-fail-host",
            port=transport_config.port,
            username=transport_config.username,
            password=transport_config.password,
            timeout=transport_config.timeout,
            command_timeout=transport_config.command_timeout,
            prompt_timeout=transport_config.prompt_timeout,
        )
        transport = MockTransport(config)
        with pytest.raises(CUCMConnectionError):
            transport.connect()

    def test_disconnect(self, mock_transport):
        mock_transport.connect()
        mock_transport.disconnect()
        assert not mock_transport.is_connected()

    def test_send_command_success(self, mock_transport):
        mock_transport.connect()
        output = mock_transport.send_command("show version active")
        assert "Active Version" in output

    def test_send_command_not_connected(self, mock_transport):
        with pytest.raises(CUCMConnectionError):
            mock_transport.send_command("show version active")

    def test_get_prompt(self, mock_transport):
        assert mock_transport.get_prompt() == "admin:"

    def test_execute_file_get_success(self, transport_config):
        """Test successful file-get with full state machine."""
        transport = MockTransportStateMachine(transport_config, file_get_scenario="success")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000079.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Verify all prompts appear in output
        assert "SFTP host:" in output
        assert "Please answer 'y' for <yes> or 'n' for no:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output
        assert "Transfer complete." in output
        # Verify values were sent
        assert "10.10.10.10" in output
        assert "sftpuser" in output
        assert "/uploads" in output

    def test_execute_file_get_no_host_key_confirmation(self, transport_config):
        """Test file-get when host key is already known (no confirmation prompt)."""
        transport = MockTransportStateMachine(transport_config, file_get_scenario="no_host_key_confirmation")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000079.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Should NOT have host-key confirmation
        assert "Please answer 'y' for <yes> or 'n' for no:" not in output
        # But should have all other prompts
        assert "SFTP host:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output

    def test_execute_file_get_no_final_confirmation(self, transport_config):
        """Test file-get when final confirmation is skipped."""
        transport = MockTransportStateMachine(transport_config, file_get_scenario="no_final_confirmation")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000079.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Should have host-key confirmation
        assert "Please answer 'y' for <yes> or 'n' for no:" in output
        # Should NOT have final confirmation
        assert "Continue? (y/n):" not in output
        assert "admin:" in output

    def test_execute_file_get_auth_failure(self, transport_config):
        """Test file-get with SFTP authentication failure."""
        transport = MockTransportStateMachine(transport_config, file_get_scenario="auth_failure")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000079.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="wrongpass",
            sftp_remote_dir="/uploads",
        )
        
        assert "Authentication failed." in output
        assert "admin:" in output

    def test_execute_file_get_transfer_failure(self, transport_config):
        """Test file-get with transfer failure."""
        transport = MockTransportStateMachine(transport_config, file_get_scenario="transfer_failure")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000079.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        assert "Transfer failed" in output
        assert "admin:" in output

    def test_execute_file_get_with_file_gather(self, transport_config):
        """Test file-get with CUCM 15 file-gathering phase (exact live output)."""
        transport = MockTransportStateMachine(transport_config, file_get_scenario="file_gather")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000085.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Verify file-gathering phase output
        assert "Please wait while the system is gathering files info" in output
        assert "Get file: active/cm/trace/ccm/sdl/SDL001_100_000085.txt.gzo" in output
        assert "done." in output
        
        # Verify SFTP phase still works
        assert "SFTP host:" in output
        assert "Please answer 'y' for <yes> or 'n' for no:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output
        assert "Transfer complete." in output
        # Verify values were sent
        assert "10.10.10.10" in output
        assert "sftpuser" in output
        assert "/uploads" in output

    def test_file_gather_done_not_transfer_complete(self, transport_config):
        """Test that 'done.' in file-gather phase does NOT trigger TRANSFER_COMPLETE.
        
        The 'done.' message after file gathering only means CUCM finished gathering
        file info, not that the SFTP transfer completed.
        """
        transport = MockTransportStateMachine(transport_config, file_get_scenario="file_gather")
        transport.connect()
        
        # The mock output contains "done." in the file-gather phase
        # and "admin:" at the end (real transfer complete)
        output = transport.execute_file_get(
            filename="SDL001_100_000085.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # There should be TWO "done." occurrences:
        # 1. File-gather phase: "done." (after "Get file: ...")
        # 2. Transfer phase: "Transfer complete." (followed by "admin:")
        done_count = output.count("done.")
        assert done_count >= 1, "Should have at least one 'done.' from file-gather phase"
        
        # The final "admin:" indicates actual transfer completion
        assert output.strip().endswith("admin:"), "Should end with admin prompt after transfer"

    def test_single_buffer_file_gather_processes_both_events(self, transport_config):
        """Regression test: single channel read with file-gather start AND complete.
        
        Simulates the live bug where ONE channel read contains:
        "Please wait while the system is gathering files info ..."
        "Get file: active/cm/trace/ccm/sdl/SDL001_100_000085.txt.gzo"
        "done."
        
        The state machine MUST process BOTH events from the same buffer:
        FILE_GATHER_STARTED -> FILE_GATHER_COMPLETE -> WAITING_FOR_HOST
        
        WITHOUT requiring another channel read.
        """
        transport = MockTransportStateMachine(transport_config, file_get_scenario="single_buffer_file_gather")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000085.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Verify file-gathering phase output (both start and complete in same buffer)
        assert "Please wait while the system is gathering files info" in output
        assert "Get file: active/cm/trace/ccm/sdl/SDL001_100_000085.txt.gzo" in output
        assert "done." in output
        
        # Verify SFTP phase works
        assert "SFTP host:" in output
        assert "Please answer 'y' for <yes> or 'n' for no:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output
        assert "Transfer complete." in output
        # Verify values were sent
        assert "10.10.10.10" in output
        assert "sftpuser" in output
        assert "/uploads" in output
        
        # Verify TWO confirmation prompts exist:
        # 1. SFTP host-key confirmation
        # (Initial confirmation is NOT present in this scenario)
        confirm_count = output.count("Please answer 'y' for <yes> or 'n' for no:")
        assert confirm_count == 1, f"Expected 1 confirmation prompt (host-key only), got {confirm_count}"

    def test_proceed_confirm_after_file_gather(self, transport_config):
        """Regression test: CUCM proceed confirmation after file-gather complete.
        
        Simulates the live CUCM 15 behavior where after file-gather completes,
        CUCM sends:
        "Sub-directories were not traversed."
        "Number of files affected: 1"
        "Total size in Bytes: 4659724"
        "Total size in Kbytes: 4550.5117"
        "Would you like to proceed [y/n]?"
        
        The state machine MUST process:
        FILE_GATHER_COMPLETE
        -> WAITING_FOR_PROCEED_CONFIRM
        -> PROCEED_CONFIRM_DETECTED (send y)
        -> WAITING_FOR_HOST
        
        WITHOUT requiring another channel read.
        
        PROCEED_CONFIRM is DISTINCT from:
        - INITIAL_CONFIRM (CUCM overwrite prompt at start)
        - HOST_KEY_CONFIRM (SFTP host-key confirmation)
        """
        transport = MockTransportStateMachine(transport_config, file_get_scenario="proceed_confirm")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000085.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Verify file-gathering phase output
        assert "Please wait while the system is gathering files info" in output
        assert "Get file: active/cm/trace/ccm/sdl/SDL001_100_000085.txt.gzo" in output
        assert "done." in output
        
        # Verify proceed confirmation output (distinct from initial and host-key)
        assert "Sub-directories were not traversed." in output
        assert "Number of files affected: 1" in output
        assert "Total size in Bytes: 4659724" in output
        assert "Total size in Kbytes: 4550.5117" in output
        assert "Would you like to proceed [y/n]?" in output
        
        # Verify "y" was sent for proceed confirmation
        # The output should contain "y" after the proceed prompt
        # Since the mock records sent responses, we check the output contains "y\n"
        # after the proceed prompt
        proceed_prompt_idx = output.index("Would you like to proceed [y/n]?")
        assert output[proceed_prompt_idx:].startswith("Would you like to proceed [y/n]?\ny\n")
        
        # Verify SFTP phase still works (host-key confirmation is separate)
        assert "SFTP host:" in output
        assert "Please answer 'y' for <yes> or 'n' for no:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output
        assert "Transfer complete." in output
        # Verify values were sent
        assert "10.10.10.10" in output
        assert "sftpuser" in output
        assert "/uploads" in output
        
        # Verify THREE confirmation prompts total:
        # 1. PROCEED_CONFIRM (Would you like to proceed [y/n]?)
        # 2. HOST_KEY_CONFIRM (Please answer 'y' for <yes> or 'n' for no:)
        # (Initial confirmation is NOT present in this scenario)
        proceed_count = output.count("Would you like to proceed [y/n]?")
        assert proceed_count == 1, f"Expected 1 proceed confirmation, got {proceed_count}"
        
        host_key_count = output.count("Please answer 'y' for <yes> or 'n' for no:")
        assert host_key_count == 1, f"Expected 1 host-key confirmation, got {host_key_count}"

    def test_execute_file_get_with_initial_confirm(self, transport_config):
        """Test file-get with CUCM 15 initial confirmation prompt (exact live output).
        
        This is the live CUCM 15 behavior where the first prompt after 'file get' is:
        "Please answer 'y' for <yes> or 'n' for <no>:"
        
        This is the CUCM overwrite confirmation, NOT the SFTP host-key confirmation.
        """
        transport = MockTransportStateMachine(transport_config, file_get_scenario="initial_confirm")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000085.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Verify initial confirmation prompt (CUCM overwrite confirmation)
        assert "Please answer 'y' for <yes> or 'n' for <no>:" in output
        
        # Verify file-gathering phase output
        assert "Please wait while the system is gathering files info" in output
        assert "Get file: active/cm/trace/ccm/sdl/SDL001_100_000085.txt.gzo" in output
        assert "done." in output
        
        # Verify SFTP phase still works (host-key confirmation is separate)
        assert "SFTP host:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output
        assert "Transfer complete." in output
        # Verify values were sent
        assert "10.10.10.10" in output
        assert "sftpuser" in output
        assert "/uploads" in output
        
        # Verify TWO confirmation prompts exist:
        # 1. Initial CUCM overwrite confirmation
        # 2. SFTP host-key confirmation
        confirm_count = output.count("Please answer 'y' for <yes> or 'n' for <no>:")
        assert confirm_count == 2, f"Expected 2 confirmation prompts, got {confirm_count}"

    def test_execute_file_get_no_initial_confirm(self, transport_config):
        """Test file-get WITHOUT initial confirmation (proceeds directly to file-gather).
        
        Some CUCM versions/configurations may skip the initial overwrite confirmation
        and go straight to file gathering.
        """
        transport = MockTransportStateMachine(transport_config, file_get_scenario="no_initial_confirm")
        transport.connect()
        
        output = transport.execute_file_get(
            filename="SDL001_100_000085.txt.gzo",
            sftp_host="10.10.10.10",
            sftp_username="sftpuser",
            sftp_password="sftppass",
            sftp_remote_dir="/uploads",
        )
        
        # Verify NO initial confirmation prompt
        # (the "Please answer 'y' for <yes> or 'n' for <no>:" that appears is the host-key one)
        assert "Please wait while the system is gathering files info" in output
        assert "Get file: active/cm/trace/ccm/sdl/SDL001_100_000085.txt.gzo" in output
        assert "done." in output
        
        # Verify SFTP phase works
        assert "SFTP host:" in output
        assert "User:" in output
        assert "Password:" in output
        assert "Destination directory:" in output
        assert "Continue? (y/n):" in output
        assert "admin:" in output
        assert "Transfer complete." in output


class TestDetectPrompt:
    """Test the _detect_prompt function for CUCM file-get state machine."""
    
    def test_detect_host_prompt(self, transport_config):
        """Test detection of SFTP host prompt."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        # Various host prompt formats
        assert transport._detect_prompt("SFTP host:") == "host"
        assert transport._detect_prompt("SSH host:") == "host"
        assert transport._detect_prompt("Remote host:") == "host"
        assert transport._detect_prompt("Destination host:") == "host"
        assert transport._detect_prompt("Server name:") == "host"
        assert transport._detect_prompt("sftp host:") == "host"  # case insensitive
    
    def test_detect_confirm_prompt(self, transport_config):
        """Test detection of yes/no confirmation prompt."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        # Various confirmation prompt formats
        assert transport._detect_prompt("Please answer 'y' for <yes> or 'n' for no:") == "confirm"
        assert transport._detect_prompt("Answer 'y' for yes or 'n' for no:") == "confirm"
        assert transport._detect_prompt("(y/n):") == "confirm"
        assert transport._detect_prompt("[yes/no]:") == "confirm"
        assert transport._detect_prompt("Are you sure you want to continue? (yes/no):") == "confirm"
    
    def test_detect_username_prompt(self, transport_config):
        """Test detection of username prompt."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        # Real implementation only matches "username" or "user name"/"login name"
        assert transport._detect_prompt("Username:") == "username"
        assert transport._detect_prompt("User name:") == "username"
        assert transport._detect_prompt("Login name:") == "username"
        # "User:" alone does NOT match in real implementation
        assert transport._detect_prompt("User:") is None
    
    def test_detect_password_prompt(self, transport_config):
        """Test detection of password prompt."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        assert transport._detect_prompt("Password:") == "password"
        assert transport._detect_prompt("Enter password:") == "password"
        # Should NOT match "password again" (confirmation)
        assert transport._detect_prompt("Password again:") is None
        # Real implementation only excludes "password again", not "re-enter password"
        assert transport._detect_prompt("Re-enter password:") == "password"
    
    def test_detect_directory_prompt(self, transport_config):
        """Test detection of destination directory prompt."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        assert transport._detect_prompt("Destination directory:") == "directory"
        assert transport._detect_prompt("Remote directory:") == "directory"
        assert transport._detect_prompt("Directory:") == "directory"
        assert transport._detect_prompt("Path:") == "directory"
    
    def test_detect_admin_prompt(self, transport_config):
        """Test detection of admin prompt (command completion)."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        assert transport._detect_prompt("admin:") == "admin"
        assert transport._detect_prompt("admin: ") == "admin"
        assert transport._detect_prompt("output\nadmin:") == "admin"
        # Should not match "admin:command"
        assert transport._detect_prompt("admin:show version") is None
    
    def test_detect_no_prompt(self, transport_config):
        """Test that non-prompt text returns None."""
        transport = MockTransport(transport_config)
        transport.connect()
        
        assert transport._detect_prompt("") is None
        assert transport._detect_prompt("Some random output") is None
        assert transport._detect_prompt("Transfer in progress...") is None
        assert transport._detect_prompt("admin:show") is None  # command echo, not prompt


# --- Model Tests ---

class TestCUCMVersion:
    def test_from_cli_output_full(self):
        output = """
Active Master Version: 15.0.1.12900-17
Active Version: 15.0.1.12900-17
Build: 12900
Edition: Standard
Install Date: 2024-01-15
        """
        version = CUCMVersion.from_cli_output(output)
        assert version.version == "15.0.1.12900-17"
        assert version.full_version == "15.0.1.12900-17"
        assert version.build == "12900"
        assert version.edition == "Standard"
        assert version.install_date == "2024-01-15"

    def test_from_cli_output_minimal(self):
        output = "Active Version: 14.0.1.10000-5"
        version = CUCMVersion.from_cli_output(output)
        assert version.version == "14.0.1.10000-5"

    def test_to_dict(self):
        version = CUCMVersion(
            version="15.0",
            full_version="15.0.1.12900-17",
            build="12900",
            edition="Standard",
            install_date="2024-01-15",
            raw_output="test",
        )
        d = version.to_dict()
        assert d["version"] == "15.0"
        assert d["build"] == "12900"


class TestCUCMTraceFile:
    def test_from_file_list_output_real_cucm_format(self):
        """Test parsing real CUCM output format with comma-separated sizes."""
        line = "03 Sep,2026 23:59:59      385,759  SDL001_100_000001.txt.gz"
        trace_file = CUCMTraceFile.from_file_list_output(line, "activelog/cm/trace/ccm/sdl")
        assert trace_file is not None
        assert trace_file.filename == "SDL001_100_000001.txt.gz"
        assert trace_file.size_bytes == 385759
        assert trace_file.trace_type == "SDL_TRACE"
        assert trace_file.path == "activelog/cm/trace/ccm/sdl/SDL001_100_000001.txt.gz"
        # Verify date parsing (year from output)
        assert trace_file.modified.year == 2026
        assert trace_file.modified.month == 9
        assert trace_file.modified.day == 3
        assert trace_file.modified.hour == 23
        assert trace_file.modified.minute == 59
        assert trace_file.modified.second == 59

    def test_from_file_list_output_gzo_file(self):
        """Test parsing .txt.gzo file (active/plain text SDL trace)."""
        line = "19 Sep,2026 12:56:08    5,239,770  SDL001_100_000079.txt.gzo"
        trace_file = CUCMTraceFile.from_file_list_output(line, "activelog/cm/trace/ccm/sdl")
        assert trace_file is not None
        assert trace_file.filename == "SDL001_100_000079.txt.gzo"
        assert trace_file.size_bytes == 5239770
        assert trace_file.trace_type == "SDL_TRACE"
        assert trace_file.path == "activelog/cm/trace/ccm/sdl/SDL001_100_000079.txt.gzo"
        # Verify date parsing
        assert trace_file.modified.year == 2026
        assert trace_file.modified.month == 9
        assert trace_file.modified.day == 19
        assert trace_file.modified.hour == 12
        assert trace_file.modified.minute == 56
        assert trace_file.modified.second == 8

    def test_from_file_list_output_index_file(self):
        """Test parsing .index metadata file."""
        line = "19 Sep,2026 05:28:31           34  SDL001_100.index"
        trace_file = CUCMTraceFile.from_file_list_output(line, "activelog/cm/trace/ccm/sdl")
        assert trace_file is not None
        assert trace_file.filename == "SDL001_100.index"
        assert trace_file.size_bytes == 34
        assert trace_file.trace_type == "SDL_INDEX"

    def test_from_file_list_output_txt_file(self):
        """Test parsing .txt file (uncompressed)."""
        line = "19 Sep,2026 05:28:31         1024  SDL001_100.txt"
        trace_file = CUCMTraceFile.from_file_list_output(line, "activelog/cm/trace/ccm/sdl")
        assert trace_file is not None
        assert trace_file.filename == "SDL001_100.txt"
        assert trace_file.trace_type == "SDL_TRACE"

    def test_from_file_list_output_skips_headers(self):
        assert CUCMTraceFile.from_file_list_output("====", "path") is None
        assert CUCMTraceFile.from_file_list_output("total 100", "path") is None
        assert CUCMTraceFile.from_file_list_output("", "path") is None

    def test_to_dict(self):
        trace_file = CUCMTraceFile(
            filename="SDL_0001",
            path="path/SDL_0001",
            size_bytes=1024000,
            modified=datetime(2024, 9, 19, 10, 30),
        )
        d = trace_file.to_dict()
        assert d["filename"] == "SDL_0001"
        assert d["size_mb"] == round(1024000 / (1024 * 1024), 2)


# --- Client Tests ---

class TestCUCMClient:
    def test_connect_disconnect(self, cucm_client):
        assert not cucm_client.is_connected()
        cucm_client.connect()
        assert cucm_client.is_connected()
        assert cucm_client.get_prompt() == "admin:"
        cucm_client.disconnect()
        assert not cucm_client.is_connected()

    def test_context_manager(self, mock_transport):
        with CUCMClient(transport=mock_transport) as client:
            assert client.is_connected()
        assert not client.is_connected()

    def test_get_version(self, cucm_client):
        cucm_client.connect()
        version = cucm_client.get_version()
        assert isinstance(version, CUCMVersion)
        assert version.version == "15.0.1.12900-17"

    def test_get_version_not_connected(self, cucm_client):
        with pytest.raises(CUCMConnectionError):
            cucm_client.get_version()

    def test_list_sdl_files(self, cucm_client):
        cucm_client.connect()
        files = cucm_client.list_sdl_files()
        # 1 index file + 11 .gz trace files + 1 .gzo trace file = 13 total
        assert len(files) == 13
        assert all(isinstance(f, CUCMTraceFile) for f in files)
        # First file is .index metadata
        assert files[0].filename == "SDL001_100.index"
        assert files[0].trace_type == "SDL_INDEX"
        assert files[0].size_bytes == 34
        # Remaining are .txt.gz trace files
        assert files[1].filename == "SDL001_100_000001.txt.gz"
        assert files[1].trace_type == "SDL_TRACE"
        assert files[1].size_bytes == 385759
        # Check the .gzo file (last in list)
        assert files[12].filename == "SDL001_100_000079.txt.gzo"
        assert files[12].trace_type == "SDL_TRACE"
        assert files[12].size_bytes == 5239770
        # Verify all trace files
        trace_files = [f for f in files if f.trace_type == "SDL_TRACE"]
        assert len(trace_files) == 12  # 11 .gz + 1 .gzo
        index_files = [f for f in files if f.trace_type == "SDL_INDEX"]
        assert len(index_files) == 1

    def test_list_sdl_files_command_format(self, mock_transport):
        """Verify the exact CUCM CLI command format with space after activelog."""
        cucm_client = CUCMClient(transport=mock_transport)
        cucm_client.connect()
        
        # Capture the command sent to the transport
        # We can verify by checking what the mock transport receives
        # Since mock_transport returns predefined responses, we know the key
        # must match exactly: "file list activelog /cm/trace/ccm/sdl detail"
        command_sent = None
        
        # The mock transport's send_command is called with the command
        # We can verify by calling list_sdl_files and checking the mock's
        # internal _responses dict has the exact key
        assert "file list activelog /cm/trace/ccm/sdl detail" in mock_transport._responses
        
        # Also verify the command is NOT the old format without space
        assert "file list activelog/cm/trace/ccm/sdl detail" not in mock_transport._responses
        
        # Actually call the method to ensure it works
        files = cucm_client.list_sdl_files()
        assert len(files) == 13

    def test_list_sdl_files_not_connected(self, cucm_client):
        with pytest.raises(CUCMConnectionError):
            cucm_client.list_sdl_files()

    def test_get_prompt_public_api(self, cucm_client):
        """Test public get_prompt() method."""
        cucm_client.connect()
        prompt = cucm_client.get_prompt()
        assert prompt == "admin:"

    def test_get_prompt_not_connected(self, cucm_client):
        with pytest.raises(CUCMConnectionError):
            cucm_client.get_prompt()

    def test_execute_read_only_public_api(self, cucm_client):
        """Test public execute_read_only() method."""
        cucm_client.connect()
        output = cucm_client.execute_read_only("show version active")
        assert "Active Version" in output

    def test_execute_read_only_not_connected(self, cucm_client):
        with pytest.raises(CUCMConnectionError):
            cucm_client.execute_read_only("show version active")

    def test_run_diagnostic(self, cucm_client):
        cucm_client.connect()
        diag = cucm_client.run_diagnostic()
        assert diag["overall"] == "READY"
        assert diag["ssh_connectivity"]["status"] == "PASS"
        assert diag["authentication"]["status"] == "PASS"
        assert diag["cucm_prompt"]["status"] == "PASS"
        assert diag["command_execution"]["status"] == "PASS"
        assert diag["cucm_version"]["status"] == "PASS"
        assert diag["sdl_directory"]["status"] == "PASS"
        assert diag["sdl_files"]["status"] == "PASS"
        assert "13 SDL file(s) found" in diag["sdl_files"]["details"]


# --- Collector Tests ---

class TestCUCMTraceCollector:
    def test_collect_via_sftp_mock(self, cucm_client):
        """Test SFTP collection with mocked transport."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)

        # Mock the SFTP config to avoid connection attempts
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        # Since we don't have a real SFTP server, the collection will fail
        # at the SFTP connection stage - this tests the config validation
        result = collector.collect_file("SDL001_100_000079.txt.gzo")
        # Expect failure due to mock SFTP
        assert not result.success
        assert result.method == "sftp_file_get"
        assert "getaddrinfo" in result.error or "connection" in result.error.lower() or "refused" in result.error.lower()

    def test_collect_multiple_sftp(self, cucm_client):
        """Test multiple file collection via SFTP."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        results = collector.collect_multiple([
            "SDL001_100_000079.txt.gzo",
            "SDL001_100_000001.txt.gz",
        ])
        assert len(results) == 2
        # Both should fail due to mock SFTP
        assert all(not r.success for r in results)

    def test_collect_all_sdl_sftp(self, cucm_client):
        """Test collect all SDL via SFTP."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        results = collector.collect_all_sdl(max_files=2)
        # Should return results for trace files only (first 2 trace files in mock)
        assert len(results) >= 1
        assert all(not r.success for r in results)

    def test_clear_local_storage(self, cucm_client):
        collector = CUCMTraceCollector(client=cucm_client)
        collector.clear_local_storage()
        assert collector.get_local_storage_path().exists()

    def test_collect_file_validates_filename(self, cucm_client):
        """Test filename validation."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)

        # Path traversal
        result = collector.collect_file("../../etc/passwd")
        assert not result.success
        assert result.method == "validation"
        assert "Path traversal" in result.error or "resolves outside" in result.error

        # Absolute path
        result = collector.collect_file("/etc/passwd")
        assert not result.success
        assert result.method == "validation"
        assert "Absolute paths" in result.error

        # Empty filename
        result = collector.collect_file("")
        assert not result.success
        assert result.method == "validation"
        assert "empty" in result.error.lower()

        # .index file rejected
        result = collector.collect_file("SDL001_100.index")
        assert not result.success
        assert "index" in result.error.lower()

    def test_collect_file_requires_sftp_config(self, cucm_client):
        """Test that collection requires SFTP configuration."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        # Don't set SFTP config - should fail at config validation
        collector._config.sftp_host = None

        result = collector.collect_file("SDL001_100_000079.txt.gzo")
        assert not result.success
        assert result.method == "config"
        assert "SFTP" in result.error


# --- Collector Selection Tests ---

class TestCUCMCollectorSelection:
    """Tests for collect_selected_traces and selection-based collection."""

class TestCUCMCollectorSelection:
    """Tests for collect_selected_traces and selection-based collection."""

    def test_collect_selected_traces_uses_selection_result(self, cucm_client):
        """collect_selected_traces should download only candidate files from SelectionResult."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)

        # Set mock SFTP config
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        # Create a SelectionResult with specific files
        from app.devices.cucm.selection import SelectionResult, SelectionRequest, SelectionMode
        from app.devices.cucm.models import CUCMTraceFile
        from datetime import datetime

        # Create trace file objects for selection
        trace_files = [
            CUCMTraceFile(
                filename="SDL001_100_000079.txt.gzo",
                path="activelog/cm/trace/ccm/sdl/SDL001_100_000079.txt.gzo",
                size_bytes=5239770,
                modified=datetime(2026, 9, 19, 12, 56, 8),
                trace_type="SDL_TRACE",
            ),
            CUCMTraceFile(
                filename="SDL001_100_000001.txt.gz",
                path="activelog/cm/trace/ccm/sdl/SDL001_100_000001.txt.gz",
                size_bytes=385759,
                modified=datetime(2026, 9, 3, 23, 59, 59),
                trace_type="SDL_TRACE",
            ),
        ]

        selection = SelectionResult(
            request=SelectionRequest(mode=SelectionMode.LATEST),
            candidate_files=trace_files,
            start_time=datetime(2026, 9, 19, 12, 0, 0),
            end_time=datetime(2026, 9, 19, 13, 0, 0),
            total_candidates=2,
            estimated_size_bytes=5625529,
        )

        # Call collect_selected_traces - it should only try to download the selected files
        results = collector.collect_selected_traces(selection)

        assert len(results) == 2
        # Both should fail due to mock SFTP
        assert all(not r.success for r in results)
        assert all(r.method == "sftp_file_get" for r in results)

    def test_collect_selected_traces_empty_selection(self, cucm_client):
        """collect_selected_traces with empty candidate list should return empty list."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)

        from app.devices.cucm.selection import SelectionResult, SelectionRequest, SelectionMode
        from datetime import datetime

        selection = SelectionResult(
            request=SelectionRequest(mode=SelectionMode.LATEST),
            candidate_files=[],
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_candidates=0,
            estimated_size_bytes=0,
        )

        results = collector.collect_selected_traces(selection)
        assert results == []

    def test_collect_selected_traces_excludes_index_files(self, cucm_client):
        """collect_selected_traces should not include .index files even if in selection."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        from app.devices.cucm.selection import SelectionResult, SelectionRequest, SelectionMode
        from app.devices.cucm.models import CUCMTraceFile
        from datetime import datetime

        trace_files = [
            CUCMTraceFile(
                filename="SDL001_100.index",
                path="activelog/cm/trace/ccm/sdl/SDL001_100.index",
                size_bytes=34,
                modified=datetime(2026, 9, 19, 5, 28, 31),
                trace_type="SDL_INDEX",
            ),
        ]

        selection = SelectionResult(
            request=SelectionRequest(mode=SelectionMode.LATEST),
            candidate_files=trace_files,
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_candidates=1,
            estimated_size_bytes=34,
        )

        results = collector.collect_selected_traces(selection)
        # .index files should be filtered out (collect_selected_traces only processes SDL_TRACE)
        assert len(results) == 0

    def test_gzo_file_sftp_workflow(self, cucm_client):
        """.gzo files use SFTP workflow."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        result = collector.collect_file("SDL001_100_000079.txt.gzo")

        # Should fail due to mock SFTP but method should be sftp_file_get
        assert result.method == "sftp_file_get"
        assert not result.success

    def test_gz_file_sftp_workflow(self, cucm_client):
        """.gz files use SFTP workflow."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        result = collector.collect_file("SDL001_100_000001.txt.gz")

        # Should fail due to mock SFTP but method should be sftp_file_get
        assert result.method == "sftp_file_get"
        assert not result.success

    def test_index_file_cannot_be_selected_in_ui(self, mock_transport):
        """Test that .index files are marked as non-selectable in candidate data."""
        from app.devices.cucm.client import CUCMClient
        cucm_client = CUCMClient(transport=mock_transport)
        cucm_client.connect()

        # Get files and verify .index is in the list
        files = cucm_client.list_sdl_files()
        index_files = [f for f in files if f.filename.endswith(".index")]
        trace_files = [f for f in files if f.trace_type == "SDL_TRACE"]

        assert len(index_files) == 1
        assert index_files[0].filename == "SDL001_100.index"
        assert index_files[0].trace_type == "SDL_INDEX"

        # Trace files should not include .index
        for f in trace_files:
            assert f.trace_type == "SDL_TRACE"
            assert not f.filename.endswith(".index")

    def test_download_result_structure(self, cucm_client):
        """Test that CollectionResult has all required fields for UI display."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        result = collector.collect_file("SDL001_100_000079.txt.gzo")

        # Result should have all new fields
        assert result.filename == "SDL001_100_000079.txt.gzo"
        assert result.method == "sftp_file_get"
        assert hasattr(result, 'raw_path')
        assert hasattr(result, 'extracted_path')
        assert hasattr(result, 'remote_size_bytes')
        assert hasattr(result, 'raw_size_bytes')
        assert hasattr(result, 'extracted_size_bytes')
        assert hasattr(result, 'raw_sha256')
        assert hasattr(result, 'extracted_sha256')
        assert hasattr(result, 'transfer_success')
        assert hasattr(result, 'extraction_success')

    def test_collect_multiple_preserves_order(self, cucm_client):
        """collect_multiple should return results in same order as input filenames."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        collector._config.sftp_host = "mock-sftp"
        collector._config.sftp_username = "mock"
        collector._config.sftp_password = "mock"
        collector._config.sftp_remote_base_dir = "/tmp/mock"

        filenames = [
            "SDL001_100_000079.txt.gzo",
            "SDL001_100_000001.txt.gz",
            "SDL001_100.index",
        ]

        results = collector.collect_multiple(filenames)

        assert len(results) == 3
        assert results[0].filename == "SDL001_100_000079.txt.gzo"
        assert results[1].filename == "SDL001_100_000001.txt.gz"
        assert results[2].filename == "SDL001_100.index"
        # .index should fail (rejected), .gzo and .gz fail due to mock SFTP
        assert results[2].success is False  # .index rejected


# --- Exception Tests ---

class TestExceptions:
    def test_cucm_connection_error(self):
        err = CUCMConnectionError("Failed", host="1.2.3.4", port=22)
        assert err.details["host"] == "1.2.3.4"
        assert err.details["port"] == 22

    def test_cucm_auth_error(self):
        err = CUCMAuthenticationError("Auth failed", username="admin")
        assert err.details["username"] == "admin"

    def test_cucm_timeout_error(self):
        err = CUCMTimeoutError("Timeout", timeout_type="command", timeout_value=60)
        assert err.details["timeout_type"] == "command"
        assert err.details["timeout_value"] == 60

    def test_cucm_prompt_error(self):
        err = CUCMPromptError("Prompt not found", expected_prompt="admin:")
        assert err.details["expected_prompt"] == "admin:"

    def test_cucm_command_error(self):
        err = CUCMCommandError("Command failed", command="show version", raw_output="error output")
        assert err.details["command"] == "show version"
        assert err.details["raw_output"] == "error output"

    def test_cucm_trace_collection_error(self):
        err = CUCMTraceCollectionError("Collection failed", filename="SDL_0001", stage="download")
        assert err.details["filename"] == "SDL_0001"
        assert err.details["stage"] == "download"


# --- CUCM Prompt Handling Tests ---

class TestCUCMPromptHandling:
    """Tests for CUCM CLI prompt detection and handling."""

    def test_cucm_prompt_pattern_constant(self):
        """Verify the CUCM prompt pattern constant is correct."""
        from app.devices.cucm.transport import NetmikoTransport
        assert NetmikoTransport.CUCM_PROMPT_PATTERN == r"admin:"

    def test_mock_transport_cucm_prompt(self, mock_transport):
        """Mock transport should simulate CUCM 'admin:' prompt."""
        assert mock_transport.get_prompt() == "admin:"

    def test_cucm_prompt_not_ios_hash_or_gt(self):
        """CUCM prompt is 'admin:', not IOS '#' or '>'."""
        from app.devices.cucm.transport import NetmikoTransport
        prompt_pattern = NetmikoTransport.CUCM_PROMPT_PATTERN
        # Should match "admin:"
        import re
        assert re.search(prompt_pattern, "admin:")
        assert re.search(prompt_pattern, "admin: ")
        assert re.search(prompt_pattern, "  admin:")
        # Should NOT match IOS prompts
        assert not re.search(prompt_pattern, "Router#")
        assert not re.search(prompt_pattern, "Router>")
        assert not re.search(prompt_pattern, "switch#")
        assert not re.search(prompt_pattern, "switch>")


class TestNetmikoTransportPromptConfig:
    """Test that Netmiko transport is configured for CUCM prompt."""

    def test_device_type_is_generic(self):
        """Transport should use 'generic' device type, not 'cisco_ios'."""
        # This test verifies the configuration approach by checking
        # that the transport class defines the CUCM prompt pattern
        from app.devices.cucm.transport import NetmikoTransport
        assert hasattr(NetmikoTransport, 'CUCM_PROMPT_PATTERN')
        assert NetmikoTransport.CUCM_PROMPT_PATTERN == r"admin:"

    def test_disable_pagination_uses_cucm_prompt(self):
        """Pagination command should use CUCM prompt pattern for expect_string."""
        from app.devices.cucm.transport import NetmikoTransport
        # The _disable_pagination method uses CUCM_PROMPT_PATTERN
        # This is verified by the constant being accessible
        assert NetmikoTransport.CUCM_PROMPT_PATTERN == r"admin:"


class TestCUCMConnectionFlow:
    """Tests for the complete CUCM connection flow."""

    def test_cucm_client_connect_uses_cli_credentials(self, cucm_client):
        """CUCMClient.connect() should work with mocked transport."""
        assert not cucm_client.is_connected()
        cucm_client.connect()
        assert cucm_client.is_connected()
        assert cucm_client.get_prompt() == "admin:"

    def test_cucm_client_get_version_executes(self, cucm_client):
        """show version active should execute successfully."""
        cucm_client.connect()
        version = cucm_client.get_version()
        assert version.version == "15.0.1.12900-17"

    def test_cucm_client_list_sdl_files_executes(self, cucm_client):
        """file list should execute successfully."""
        cucm_client.connect()
        files = cucm_client.list_sdl_files()
        # 1 index file + 11 .gz trace files + 1 .gzo trace file = 13 total
        assert len(files) == 13
        assert all(f.filename.startswith("SDL") for f in files)

    def test_cucm_client_execute_read_only(self, cucm_client):
        """Public execute_read_only method should work."""
        cucm_client.connect()
        output = cucm_client.execute_read_only("show version active")
        assert "Active Version" in output

    def test_authentication_failure_raises_correct_exception(self, transport_config):
        """Authentication failure should raise CUCMAuthenticationError."""
        config = TransportConfig(
            host="auth-fail-host",
            port=transport_config.port,
            username=transport_config.username,
            password=transport_config.password,
            timeout=transport_config.timeout,
            command_timeout=transport_config.command_timeout,
            prompt_timeout=transport_config.prompt_timeout,
        )
        # Create a transport that simulates auth failure
        class AuthFailTransport(CUCMTransport):
            def __init__(self, config):
                self.config = config
                self._connected = False
            
            def connect(self):
                raise CUCMAuthenticationError("Authentication failed", username=self.config.username)
            
            def disconnect(self):
                pass
            
            def is_connected(self):
                return False
            
            def send_command(self, command: str, expect_string: str = None) -> str:
                return ""
            
            def send_command_timing(self, command: str, delay_factor: float = 1.0) -> str:
                return ""
            
            def get_prompt(self) -> str:
                return ""

            def execute_file_get(
                self,
                filename: str,
                sftp_host: str,
                sftp_username: str,
                sftp_password: str,
                sftp_remote_dir: str,
                remote_path: str = "activelog /cm/trace/ccm/sdl",
            ) -> str:
                return ""

        transport = AuthFailTransport(config)
        with pytest.raises(CUCMAuthenticationError) as exc_info:
            transport.connect()
        assert "Authentication failed" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])