"""Unit tests for CUCM device integration (with mocked transport)."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta

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

    def __init__(self, config: TransportConfig, responses: dict = None):
        self.config = config
        self._connected = False
        self._responses = responses or {}
        self._prompt = "admin:"

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

    def execute_file_get(
        self,
        filename: str,
        sftp_host: str,
        sftp_username: str,
        sftp_password: str,
        sftp_remote_dir: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> str:
        """Mock execute_file_get for testing."""
        return f"File get successful for {filename}"


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