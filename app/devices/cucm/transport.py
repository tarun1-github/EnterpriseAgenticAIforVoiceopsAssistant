"""SSH transport layer for CUCM CLI interaction using Netmiko.

Netmiko is chosen because:
- Designed for network devices (Cisco, including CUCM)
- Handles delayed prompts automatically via expect_string
- Built-in timeout and retry logic
- Simpler than Paramiko for interactive CLI sessions
- Properly handles SSH negotiation and authentication delays
"""

from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass

from app.core.config import get_settings
from app.core.logging import get_logger
from app.devices.cucm.exceptions import (
    CUCMConnectionError,
    CUCMAuthenticationError,
    CUCMTimeoutError,
    CUCMPromptError,
    CUCMCommandError,
)

logger = get_logger("devices.cucm.transport")


@dataclass
class TransportConfig:
    """Configuration for SSH transport."""
    host: str
    port: int = 22
    username: str = ""
    password: str = ""
    timeout: int = 30
    command_timeout: int = 60
    prompt_timeout: int = 15


class CUCMTransport(ABC):
    """Abstract transport interface for CUCM CLI communication."""

    @abstractmethod
    def connect(self) -> None:
        """Establish SSH connection to CUCM."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close SSH connection."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connection is active."""
        pass

    @abstractmethod
    def send_command(self, command: str, expect_string: Optional[str] = None) -> str:
        """Send command and return output."""
        pass

    @abstractmethod
    def send_command_timing(self, command: str, delay_factor: float = 1.0) -> str:
        """Send command using timing-based approach (no prompt detection)."""
        pass


class NetmikoTransport(CUCMTransport):
    """Netmiko-based SSH transport for CUCM.

    Handles:
    - Delayed password prompt via Netmiko's connection logic
    - Delayed CUCM CLI prompt via expect_string
    - Command timeouts
    - Pagination (terminal length 0)
    """

    def __init__(self, config: TransportConfig):
        self.config = config
        self._connection = None
        self._connected = False
        self._base_prompt = ""

    def connect(self) -> None:
        """Establish SSH connection to CUCM with proper prompt handling."""
        try:
            from netmiko import ConnectHandler
            from netmiko.exceptions import (
                NetmikoTimeoutException,
                NetmikoAuthenticationException,
                SSHException,
            )
        except ImportError:
            raise CUCMConnectionError("Netmiko not installed. Run: pip install netmiko")

        device = {
            "device_type": "cisco_cts",  # Closest Netmiko device type for CUCM
            "host": self.config.host,
            "port": self.config.port,
            "username": self.config.username,
            "password": self.config.password,
            "timeout": self.config.timeout,
            "session_timeout": self.config.command_timeout,
            "auth_timeout": self.config.timeout,
            "banner_timeout": self.config.prompt_timeout,
            "conn_timeout": self.config.timeout,
            "read_timeout_override": self.config.command_timeout,
            "global_delay_factor": 1.5,
            "fast_cli": False,
        }

        try:
            logger.info("Connecting to CUCM at %s:%d", self.config.host, self.config.port)
            self._connection = ConnectHandler(**device)
            self._connected = True

            # Disable pagination
            self._disable_pagination()

            # Detect base prompt
            self._base_prompt = self._connection.find_prompt().strip()
            logger.info("CUCM connection established. Prompt: %s", self._base_prompt)

        except NetmikoTimeoutException as e:
            logger.error("SSH connection timeout to %s:%d", self.config.host, self.config.port)
            raise CUCMConnectionError(
                f"SSH connection timeout to {self.config.host}:{self.config.port}",
                host=self.config.host,
                port=self.config.port,
            ) from e
        except NetmikoAuthenticationException as e:
            logger.error("CUCM authentication failed for user %s", self.config.username)
            raise CUCMAuthenticationError(
                f"Authentication failed for user {self.config.username}",
                username=self.config.username,
            ) from e
        except SSHException as e:
            logger.error("SSH protocol error: %s", e)
            raise CUCMConnectionError(f"SSH protocol error: {e}", host=self.config.host) from e
        except Exception as e:
            logger.error("Unexpected connection error: %s", e)
            raise CUCMConnectionError(f"Connection failed: {e}", host=self.config.host) from e

    def _disable_pagination(self) -> None:
        """Disable CLI pagination (terminal length 0)."""
        try:
            output = self._connection.send_command(
                "set cli pagination off",
                expect_string=r"[#>]",
                read_timeout=self.config.prompt_timeout,
            )
            logger.debug("Pagination disabled: %s", output.strip())
        except Exception as e:
            logger.warning("Failed to disable pagination: %s", e)

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._connection and self._connected:
            try:
                self._connection.disconnect()
                logger.info("CUCM connection closed")
            except Exception as e:
                logger.warning("Error during disconnect: %s", e)
            finally:
                self._connected = False
                self._connection = None

    def is_connected(self) -> bool:
        """Check if connection is active."""
        return self._connected and self._connection is not None

    def send_command(self, command: str, expect_string: Optional[str] = None) -> str:
        """Send command with prompt-based completion detection."""
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        if expect_string is None:
            expect_string = self._base_prompt

        try:
            logger.debug("Sending command: %s", command)
            output = self._connection.send_command(
                command,
                expect_string=expect_string,
                read_timeout=self.config.command_timeout,
                strip_prompt=True,
                strip_command=True,
            )
            logger.debug("Command completed, output length: %d", len(output))
            return output
        except Exception as e:
            logger.error("Command failed: %s - %s", command, e)
            raise CUCMCommandError(
                f"Command execution failed: {e}",
                command=command,
            ) from e

    def send_command_timing(self, command: str, delay_factor: float = 1.0) -> str:
        """Send command using timing-based approach (no prompt detection)."""
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        try:
            logger.debug("Sending command (timing): %s", command)
            output = self._connection.send_command_timing(
                command,
                delay_factor=delay_factor,
                strip_prompt=True,
                strip_command=True,
            )
            logger.debug("Timing command completed, output length: %d", len(output))
            return output
        except Exception as e:
            logger.error("Timing command failed: %s - %s", command, e)
            raise CUCMCommandError(
                f"Timing command execution failed: {e}",
                command=command,
            ) from e

    def get_prompt(self) -> str:
        """Get the current CUCM CLI prompt."""
        return self._base_prompt


def create_transport(config: Optional[TransportConfig] = None) -> CUCMTransport:
    """Factory function to create CUCM transport."""
    if config is None:
        settings = get_settings()
        config = TransportConfig(
            host=settings.cucm_host or "",
            port=settings.cucm_ssh_port,
            username=settings.cucm_username or "",
            password=settings.cucm_password.get_secret_value() if settings.cucm_password else "",
            timeout=settings.cucm_ssh_timeout,
            command_timeout=settings.cucm_command_timeout,
            prompt_timeout=settings.cucm_prompt_timeout,
        )
    return NetmikoTransport(config)