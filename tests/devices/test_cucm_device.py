"""Unit tests for CUCM device integration (with mocked transport)."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from app.devices.cucm.transport import (
    CUCMTransport,
    NetmikoTransport,
    TransportConfig,
    create_transport,
)
from app.devices.cucm.client import CUCMClient
from app.devices.cucm.collector import CUCMTraceCollector, CollectionResult, CollectorConfig
from app.devices.cucm.models import CUCMVersion, CUCMTraceFile
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
        return self._responses.get(command, f"Output for: {command}")

    def send_command_timing(self, command: str, delay_factor: float = 1.0) -> str:
        return self.send_command(command)

    def get_prompt(self) -> str:
        return self._prompt


# --- Mock Transport with Large Files ---

class MockTransportWithLargeFiles(MockTransport):
    """Mock transport that returns large file listings."""

    def __init__(self, config: TransportConfig, responses: dict = None):
        super().__init__(config, responses)
        self._responses = {
            "show version active": """
Active Master Version: 15.0.1.12900-17
Active Version: 15.0.1.12900-17
Build: 12900
Edition: Standard
Install Date: 2024-01-15
            """.strip(),
            "file list activelog/cm/trace/ccm/sdl detail": """
-rw-r--r--  1 admin admin  1024000 Sep 19 10:30 SDL_0001_20240919_103000
-rw-r--r--  1 admin admin  2048000 Sep 19 11:00 SDL_0002_20240919_110000
-rw-r--r--  1 admin admin  52428800 Sep 19 11:30 SDL_LARGE_20240919_113000
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
        "file list activelog/cm/trace/ccm/sdl detail": """
-rw-r--r--  1 admin admin  1024000 Sep 19 10:30 SDL_0001_20240919_103000
-rw-r--r--  1 admin admin  2048000 Sep 19 11:00 SDL_0002_20240919_110000
-rw-r--r--  1 admin admin   512000 Sep 19 11:30 SDL_0003_20240919_113000
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
            mock_settings.return_value.cucm_username = "testuser"
            mock_settings.return_value.cucm_password.get_secret_value.return_value = "testpass"
            mock_settings.return_value.cucm_ssh_timeout = 30
            mock_settings.return_value.cucm_command_timeout = 60
            mock_settings.return_value.cucm_prompt_timeout = 15

            transport = create_transport()
            assert isinstance(transport, NetmikoTransport)

    def test_netmiko_import(self):
        """Verify Netmiko can be imported."""
        import netmiko
        assert netmiko.__version__


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
    def test_from_file_list_output(self):
        line = "-rw-r--r--  1 admin admin  1024000 Sep 19 10:30 SDL_0001_20240919_103000"
        trace_file = CUCMTraceFile.from_file_list_output(line, "activelog/cm/trace/ccm/sdl")
        assert trace_file is not None
        assert trace_file.filename == "SDL_0001_20240919_103000"
        assert trace_file.size_bytes == 1024000
        assert trace_file.path == "activelog/cm/trace/ccm/sdl/SDL_0001_20240919_103000"

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
        assert len(files) == 3
        assert all(isinstance(f, CUCMTraceFile) for f in files)
        assert files[0].filename == "SDL_0001_20240919_103000"

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


# --- Collector Tests ---

class TestCUCMTraceCollector:
    def test_collect_via_view(self, cucm_client):
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        result = collector.collect_file("SDL_0001_20240919_103000", method="view")
        assert result.success
        assert result.method == "view"
        assert result.local_path is not None
        assert result.size_bytes > 0

    def test_collect_multiple(self, cucm_client):
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        results = collector.collect_multiple([
            "SDL_0001_20240919_103000",
            "SDL_0002_20240919_110000",
        ], method="view")
        assert len(results) == 2
        assert all(r.success for r in results)

    def test_collect_all_sdl(self, cucm_client):
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        results = collector.collect_all_sdl(max_files=2, method="view")
        assert len(results) == 2

    def test_clear_local_storage(self, cucm_client):
        collector = CUCMTraceCollector(client=cucm_client)
        collector.clear_local_storage()
        assert collector.get_local_storage_path().exists()

    def test_collect_via_get_returns_failure(self, cucm_client):
        """Test that 'get' method returns clear failure (not implemented)."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        result = collector.collect_file("SDL_0001_20240919_103000", method="get")
        assert not result.success
        assert result.method == "get"
        assert "SFTP-based file get is not yet configured" in result.error
        assert result.local_path is None

    def test_auto_method_large_file_returns_failure(self, cucm_client_large_files):
        """Test auto method returns failure for large files (get not implemented)."""
        cucm_client_large_files.connect()
        # Configure collector with 10MB threshold (default)
        collector = CUCMTraceCollector(client=cucm_client_large_files)
        # SDL_LARGE is 50MB (> 10MB threshold)
        result = collector.collect_file("SDL_LARGE_20240919_113000", method="auto")
        assert not result.success
        assert result.method == "get"
        assert "SFTP-based file get is not yet configured" in result.error

    def test_auto_method_small_file_uses_view(self, cucm_client_large_files):
        """Test auto method uses view for small files."""
        cucm_client_large_files.connect()
        collector = CUCMTraceCollector(client=cucm_client_large_files)
        # SDL_0001 is 1MB (< 10MB threshold)
        result = collector.collect_file("SDL_0001_20240919_103000", method="auto")
        assert result.success
        assert result.method == "view"

    def test_filename_validation_rejects_path_traversal(self, cucm_client):
        """Test that path traversal attempts are rejected."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        result = collector.collect_file("../../etc/passwd", method="view")
        assert not result.success
        assert result.method == "validation"
        assert "Path traversal" in result.error or "resolves outside" in result.error

    def test_filename_validation_rejects_absolute_path(self, cucm_client):
        """Test that absolute paths are rejected."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        result = collector.collect_file("/etc/passwd", method="view")
        assert not result.success
        assert result.method == "validation"
        assert "Absolute paths" in result.error

    def test_filename_validation_rejects_empty(self, cucm_client):
        """Test that empty filenames are rejected."""
        cucm_client.connect()
        collector = CUCMTraceCollector(client=cucm_client)
        result = collector.collect_file("", method="view")
        assert not result.success
        assert result.method == "validation"
        assert "empty" in result.error.lower()

    def test_custom_large_file_threshold(self, cucm_client_large_files):
        """Test that large file threshold is configurable."""
        cucm_client_large_files.connect()
        # Set threshold to 100MB - SDL_LARGE (50MB) should now use view
        config = CollectorConfig(large_file_threshold_mb=100)
        collector = CUCMTraceCollector(client=cucm_client_large_files, config=config)
        result = collector.collect_file("SDL_LARGE_20240919_113000", method="auto")
        assert result.success
        assert result.method == "view"


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])