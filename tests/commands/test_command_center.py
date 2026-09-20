"""Tests for Device Command Center safety, history, and multi-device dispatch."""

from unittest.mock import MagicMock, patch
import pytest

from app.commands.models import CommandRequest, DeviceTypeEnum
from app.commands.safety import validate_command_safety, mask_secrets
from app.commands.history import CommandHistoryManager
from app.commands.service import DeviceCommandService
from app.devices.cucm.client import CUCMClient


class TestCommandSafety:
    """Test read-only safety rules and secret masking."""

    @pytest.mark.parametrize(
        "safe_cmd",
        [
            "show version",
            "show status",
            "utils service status",
            "file list activelog /cm/trace/ccm/sdl detail",
            "show network eth0",
            "show isdn status",
            "show dial-peer voice summary",
            "show voice port summary",
            "show sip-ua status",
            "show call active voice",
        ],
    )
    def test_safe_commands_allowed(self, safe_cmd):
        is_safe, reason = validate_command_safety(safe_cmd)
        assert is_safe is True
        assert reason is None

    @pytest.mark.parametrize(
        "dangerous_cmd",
        [
            "configure terminal",
            "conf t",
            "config t",
            "write",
            "write memory",
            "wr",
            "reload",
            "erase startup-config",
            "delete nvram:",
            "format flash:",
            "shutdown",
            "no shutdown",
            "no dial-peer voice 100",
            "utils system restart",
            "utils system reboot",
            "utils system shutdown",
            "file delete activelog test.txt",
        ],
    )
    def test_dangerous_commands_blocked(self, dangerous_cmd):
        is_safe, reason = validate_command_safety(dangerous_cmd)
        assert is_safe is False
        assert reason is not None
        assert "blocked" in reason.lower()

    def test_mask_secrets(self):
        sample_output = (
            "username admin password 7 0822455D0A16\n"
            "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\n"
            "crypto isakmp key cisco123 address 10.1.1.1\n"
            "crypto isakmp pre-shared-key TopSecret123\n"
            "snmp-server community public RO\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1W\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        masked = mask_secrets(sample_output)

        assert "0822455D0A16" not in masked
        assert "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0" not in masked
        assert "TopSecret123" not in masked
        assert "public" not in masked
        assert "MIIEowIBAAKCAQEA0Y1W" not in masked
        assert "********" in masked
        assert "[REDACTED PRIVATE KEY]" in masked


class TestCommandHistory:
    """Test command execution history manager."""

    def test_add_and_retrieve_entries(self):
        mgr = CommandHistoryManager(max_entries=3)
        assert len(mgr.get_entries()) == 0

        req1 = CommandRequest(device_type=DeviceTypeEnum.CUCM, host="10.1.1.1", command="show version")
        from app.commands.models import CommandHistoryEntry
        e1 = CommandHistoryEntry(device_type="CUCM", host="10.1.1.1", command="show version", output="v1", execution_time_seconds=0.5, status="SUCCESS")
        mgr.add_entry(e1)

        assert len(mgr.get_entries()) == 1
        assert mgr.get_entries()[0].command == "show version"

    def test_history_cap(self):
        mgr = CommandHistoryManager(max_entries=2)
        from app.commands.models import CommandHistoryEntry
        for i in range(5):
            mgr.add_entry(CommandHistoryEntry(device_type="CUCM", host="10.1.1.1", command=f"cmd {i}", output="", execution_time_seconds=0.1, status="SUCCESS"))

        assert len(mgr.get_entries()) == 2
        # Most recent first
        assert mgr.get_entries()[0].command == "cmd 4"


class TestDeviceCommandService:
    """Test service execution flow, blocking, and transport dispatch."""

    def test_blocked_command_execution(self):
        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history)

        req = CommandRequest(
            device_type=DeviceTypeEnum.CUCM,
            host="10.197.206.141",
            command="configure terminal",
        )
        resp = service.execute(req)

        assert resp.success is False
        assert "blocked" in resp.error.lower()
        assert len(history.get_entries()) == 1
        assert history.get_entries()[0].status == "BLOCKED"

    def test_cucm_command_execution(self):
        mock_client = MagicMock(spec=CUCMClient)
        mock_client.is_connected.return_value = True
        mock_client.execute_read_only.return_value = "Cisco Unified Communications Manager\nVersion 15.0.1.12900-234"
        mock_client.get_prompt.return_value = "admin:"

        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history, cucm_client=mock_client)

        req = CommandRequest(
            device_type=DeviceTypeEnum.CUCM,
            host="10.197.206.141",
            command="show version active",
        )
        resp = service.execute(req)

        assert resp.success is True
        assert "15.0.1.12900-234" in resp.output
        assert resp.prompt == "admin:"
        assert len(history.get_entries()) == 1
        assert history.get_entries()[0].status == "SUCCESS"
        mock_client.execute_read_only.assert_called_once_with("show version active")

    def test_ios_command_execution(self):
        history = CommandHistoryManager()
        service = DeviceCommandService(history_manager=history)

        with patch("app.commands.service.IOSVoiceGatewayTransport") as mock_transport_cls:
            mock_transport = MagicMock()
            mock_transport.__enter__.return_value = mock_transport
            mock_transport.send_command.return_value = "Cisco IOS XE Software, Version 17.06.01a"
            mock_transport_cls.return_value = mock_transport

            req = CommandRequest(
                device_type=DeviceTypeEnum.IOS,
                host="10.10.10.1",
                command="show version",
            )
            resp = service.execute(req)

            assert resp.success is True
            assert "17.06.01a" in resp.output
            assert resp.prompt == "Gateway#"
            mock_transport.send_command.assert_called_once_with("show version", timeout=30)

    def test_copy_command_blocked(self):
        is_safe, reason = validate_command_safety("copy running-config startup-config")
        assert is_safe is False
        assert "blocked" in reason.lower()


class TestCommandExport:
    """Test command output formatting and filename sanitization."""

    def test_generate_command_filename(self):
        from app.commands.export import generate_command_filename, sanitize_command_for_filename
        from datetime import datetime

        fixed_dt = datetime(2026, 9, 20, 16, 45, 32)
        filename = generate_command_filename("CUCM", "10.197.206.141", "show version active", dt=fixed_dt)
        assert filename == "CUCM_10.197.206.141_show-version-active_20260920_164532.txt"

    def test_format_command_output_package(self):
        from app.commands.export import format_command_output_package

        text = format_command_output_package(
            device_type="CUCM",
            ip="10.197.206.141",
            command="show version active",
            status="SUCCESS",
            output="Cisco Unified Communications Manager\nVersion 15.0.1",
            prompt="admin:",
            timestamp_str="2026-09-20 16:45:32 IST",
        )

        assert "VoiceOps AI - Device Command Output" in text
        assert "Device Type : CUCM" in text
        assert "Device IP   : 10.197.206.141" in text
        assert "Timestamp   : 2026-09-20 16:45:32 IST" in text
        assert "Command     : show version active" in text
        assert "Status      : SUCCESS" in text
        assert "REQUEST\n=======\n\nshow version active" in text
        assert "RESPONSE\n========\n\nadmin:show version active" in text
        assert "Version 15.0.1" in text

