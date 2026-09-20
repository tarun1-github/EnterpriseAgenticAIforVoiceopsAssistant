"""Service for executing commands on CUCM and Cisco IOS gateways with safety guardrails."""

import time
from typing import Optional
from app.commands.models import CommandRequest, CommandResponse, CommandHistoryEntry, DeviceTypeEnum
from app.commands.safety import validate_command_safety, mask_secrets
from app.commands.history import CommandHistoryManager
from app.devices.cucm.client import CUCMClient
from app.devices.ios.transport import IOSVoiceGatewayTransport
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("commands.service")


class DeviceCommandService:
    """Executes commands on target network devices with validation and audit history."""

    def __init__(
        self,
        history_manager: Optional[CommandHistoryManager] = None,
        cucm_client: Optional[CUCMClient] = None,
    ):
        self._history = history_manager or CommandHistoryManager()
        self._cucm_client = cucm_client

    @property
    def history(self) -> CommandHistoryManager:
        return self._history

    def execute(self, request: CommandRequest) -> CommandResponse:
        """Execute a validated read-only command on the specified device.

        Args:
            request: CommandRequest parameters.

        Returns:
            CommandResponse containing output, duration, and status.
        """
        cmd = request.command.strip()
        host = request.host

        # Step 1: Safety validation
        is_safe, reason = validate_command_safety(cmd)
        if not is_safe:
            error_msg = reason or "Command rejected by safety policy."
            logger.warning("Command blocked for %s: %s", request.device_type.value, error_msg)
            entry = CommandHistoryEntry(
                device_type=request.device_type.value,
                host=host,
                command=cmd,
                output="",
                execution_time_seconds=0.0,
                status="BLOCKED",
                error=error_msg,
            )
            self._history.add_entry(entry)
            return CommandResponse(
                command=cmd,
                device_type=request.device_type,
                host=host,
                output="",
                execution_time_seconds=0.0,
                success=False,
                error=error_msg,
            )

        start_time = time.perf_counter()

        # Step 2: Device Dispatch
        try:
            if request.device_type == DeviceTypeEnum.CUCM:
                client = self._cucm_client or CUCMClient()
                if not client.is_connected():
                    client.connect()

                raw_output = client.execute_read_only(cmd)
                try:
                    prompt = client.get_prompt()
                except Exception:
                    prompt = "admin:"

            elif request.device_type == DeviceTypeEnum.IOS:
                settings = get_settings()
                pw = settings.gateway_password.get_secret_value() if settings.gateway_password else None
                with IOSVoiceGatewayTransport(
                    host=host,
                    username=settings.gateway_username,
                    password=pw,
                    port=settings.gateway_ssh_port,
                    timeout=request.timeout,
                ) as ios_transport:
                    raw_output = ios_transport.send_command(cmd, timeout=request.timeout)
                prompt = "Gateway#"

            else:
                raise ValueError(f"Unsupported device type: {request.device_type}")

            duration = round(time.perf_counter() - start_time, 3)

            # Step 3: Sanitize output
            safe_output = mask_secrets(raw_output)

            entry = CommandHistoryEntry(
                device_type=request.device_type.value,
                host=host,
                command=cmd,
                output=safe_output,
                execution_time_seconds=duration,
                status="SUCCESS",
            )
            self._history.add_entry(entry)

            return CommandResponse(
                command=cmd,
                device_type=request.device_type,
                host=host,
                output=safe_output,
                execution_time_seconds=duration,
                success=True,
                prompt=prompt,
            )

        except Exception as e:
            duration = round(time.perf_counter() - start_time, 3)
            error_msg = mask_secrets(str(e))
            logger.error("Command execution failed on %s: %s", request.device_type.value, error_msg)

            entry = CommandHistoryEntry(
                device_type=request.device_type.value,
                host=host,
                command=cmd,
                output="",
                execution_time_seconds=duration,
                status="FAILED",
                error=error_msg,
            )
            self._history.add_entry(entry)

            return CommandResponse(
                command=cmd,
                device_type=request.device_type,
                host=host,
                output="",
                execution_time_seconds=duration,
                success=False,
                error=error_msg,
            )
