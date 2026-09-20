"""SSH transport layer for CUCM CLI interaction using Netmiko.

Netmiko is chosen because:
- Designed for network devices (Cisco, including CUCM)
- Handles delayed prompts automatically via expect_string
- Built-in timeout and retry logic
- Simpler than Paramiko for interactive CLI sessions
- Properly handles SSH negotiation and authentication delays

Device Type Selection:
- CUCM SSH authentication works with cisco_ios SSH parameters
- CUCM CLI presents "admin:" prompt, not IOS "#" or ">"
- Solution: Custom Netmiko connection class inheriting from CiscoIosSSH
  that overrides session_preparation() to skip IOS prompt detection
  and provides CUCM-specific prompt detection.
"""

from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass
import time
import re

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

    @abstractmethod
    def get_prompt(self) -> str:
        """Get the detected CUCM CLI prompt."""
        pass

    @abstractmethod
    def execute_file_get(
        self,
        filename: str,
        sftp_host: str,
        sftp_username: str,
        sftp_password: str,
        sftp_remote_dir: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> str:
        """Execute interactive CUCM 'file get' command for SFTP transfer."""
        pass


class NetmikoTransport(CUCMTransport):
    """Netmiko-based SSH transport for CUCM.

    Uses a custom CUCM connection class that inherits from CiscoIosSSH
    but overrides prompt detection for CUCM's "admin:" prompt.
    """

    # CUCM CLI prompt pattern
    CUCM_PROMPT_PATTERN = r"admin:"

    def __init__(self, config: TransportConfig):
        self.config = config
        self._connection = None
        self._connected = False
        self._base_prompt = ""

    def connect(self) -> None:
        """Establish SSH connection to CUCM using custom CUCM connection class."""
        try:
            from netmiko import ConnectHandler
            from netmiko.cisco.cisco_ios import CiscoIosSSH
            from netmiko.exceptions import (
                NetmikoTimeoutException,
                NetmikoAuthenticationException,
                SSHException,
            )
        except ImportError:
            raise CUCMConnectionError("Netmiko not installed. Run: pip install netmiko")

        # Custom CUCM connection class that overrides prompt detection
        class CUCMConnection(CiscoIosSSH):
            """CUCM-specific Netmiko connection class.

            Inherits SSH authentication from CiscoIosSSH but overrides
            prompt detection for CUCM's "admin:" prompt.
            """

            def session_preparation(self) -> None:
                """Prepare session after SSH auth - CUCM version.

                Does NOT call parent session_preparation() which would
                try to detect IOS "#" or ">" prompt.

                Sequence:
                1. Detect CUCM prompt FIRST (before any commands)
                2. Disable CUCM paging using CUCM command
                3. Verify prompt remains "admin:"
                """
                # Step 1: Detect CUCM prompt FIRST
                self.base_prompt = self._detect_cucm_prompt()

                if not self.base_prompt:
                    raise ValueError("Failed to detect CUCM CLI prompt")

                # Normalize to exact "admin:"
                if self.base_prompt != "admin:":
                    logger.warning("Normalizing prompt from %r to 'admin:'", self.base_prompt)
                    self.base_prompt = "admin:"

                logger.info("CUCM initial prompt detected: %s", self.base_prompt)

                # Step 2: Disable CUCM paging using CUCM command (NOT IOS "terminal length 0")
                self.disable_paging(command="set cli pagination off")

                # Step 3: Verify prompt remains "admin:" after pagination command
                verified_prompt = self._detect_cucm_prompt()
                if verified_prompt and verified_prompt != "admin:":
                    logger.warning("Prompt changed after pagination: %r, resetting to 'admin:'", verified_prompt)
                self.base_prompt = "admin:"

                logger.info("CUCM connection established. Prompt: %s", self.base_prompt)

            def _detect_cucm_prompt(self) -> str:
                """Detect CUCM CLI prompt by reading channel output.

                After SSH authentication, CUCM presents:
                - Login banner
                - admin: prompt

                We read the channel until we see the "admin:" prompt.
                Uses self.banner_timeout (from device config) for timeout.
                Returns ONLY the exact prompt "admin:", never command echo.
                """
                if not self.remote_conn:
                    return ""

                try:
                    channel = self.remote_conn

                    output = ""
                    start_time = time.time()
                    timeout = getattr(self, "banner_timeout", 15)

                    while time.time() - start_time < timeout:
                        if channel.recv_ready():
                            chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                            output += chunk
                            logger.debug("Prompt detection received: %r", chunk)

                            # Look for exact "admin:" prompt in the last line
                            lines = output.strip().splitlines()
                            for line in reversed(lines):
                                line = line.strip()
                                # Match EXACT "admin:" only, not "admin:command"
                                if line == "admin:":
                                    logger.info("Detected CUCM prompt: %s", line)
                                    return line
                        else:
                            time.sleep(0.1)

                    logger.warning("Prompt detection timeout, output: %r", output)
                    return ""

                except Exception as e:
                    logger.error("Error during prompt detection: %s", e)
                    return ""

            def set_base_prompt(
                self,
                pri_prompt_terminator: str = "#",
                alt_prompt_terminator: str = ">",
                delay_factor: float = 1.0,
                pattern: Optional[str] = None,
            ) -> str:
                """Override set_base_prompt to use CUCM pattern.

                If called with defaults (IOS pattern), use CUCM detection instead.
                """
                # If called with default IOS terminators, use CUCM detection
                if pri_prompt_terminator == "#" and alt_prompt_terminator == ">" and pattern is None:
                    return self._detect_cucm_prompt()

                # Otherwise use parent logic (should not happen in normal CUCM flow)
                return super().set_base_prompt(
                    pri_prompt_terminator=pri_prompt_terminator,
                    alt_prompt_terminator=alt_prompt_terminator,
                    delay_factor=delay_factor,
                    pattern=pattern,
                )

        # Device configuration for CUCM
        device = {
            "device_type": "cisco_ios",  # Will use our custom class via device_type override
            "host": self.config.host,
            "port": self.config.port,
            "username": self.config.username,
            "password": self.config.password,
            "timeout": self.config.timeout,
            "session_timeout": self.config.command_timeout,
            "auth_timeout": self.config.timeout,
            "banner_timeout": self.config.prompt_timeout,
            "conn_timeout": self.config.timeout,
            "read_timeout_override": 300,  # Default 5 min for large file view commands
            "global_delay_factor": 1.5,
            "fast_cli": False,
            # We'll swap the class after ConnectHandler creates it
        }

        try:
            logger.info("Connecting to CUCM at %s:%d", self.config.host, self.config.port)

            # We need to use our custom class. Netmiko's ConnectHandler
            # selects class based on device_type. We'll create the connection
            # directly using our custom class.
            self._connection = CUCMConnection(**device)
            self._connected = True

            # The session_preparation() is called inside ConnectHandler
            # which calls our overridden version
            logger.info("CUCM connection established. Prompt: %s", self._connection.base_prompt)
            self._base_prompt = self._connection.base_prompt

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
        """Send command with prompt-based completion detection using CUCM prompt."""
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        if expect_string is None:
            expect_string = self._base_prompt

        # Use longer timeout for file view commands which can have large output
        read_timeout = self.config.command_timeout
        if command.startswith("file view "):
            read_timeout = max(read_timeout, 300)  # 5 minutes for file view

        try:
            logger.debug("Sending command: %s (expect: %s, timeout: %ds)", command, expect_string, read_timeout)
            output = self._connection.send_command(
                command,
                expect_string=expect_string,
                read_timeout=read_timeout,
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

    def execute_file_get(
        self,
        filename: str,
        sftp_host: str,
        sftp_username: str,
        sftp_password: str,
        sftp_remote_dir: str,
        remote_path: str = "activelog /cm/trace/ccm/sdl",
    ) -> str:
        """Execute interactive CUCM 'file get' command for SFTP transfer.

        This method handles the interactive prompts from CUCM:
        1. SFTP host prompt
        2. SFTP username prompt
        3. SFTP password prompt
        4. Destination directory prompt
        5. Confirmation prompt (if any)

        Args:
            filename: Name of the SDL file to transfer.
            sftp_host: SFTP server hostname/IP.
            sftp_username: SFTP username.
            sftp_password: SFTP password (never logged).
            sftp_remote_dir: Remote directory on SFTP server.
            remote_path: CUCM source directory.

        Returns:
            Command output from CUCM.

        Raises:
            CUCMCommandError: If command fails or transfer fails.
            CUCMTimeoutError: If transfer times out.
        """
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"

        logger.info("Starting CUCM file-get: filename=%s sftp_host=%s", filename, sftp_host)

        # Use send_command_timing for interactive command with manual prompt handling
        # We'll send the command and then respond to each prompt sequentially
        try:
            # Send the initial command
            output = self._connection.send_command_timing(
                command,
                delay_factor=2.0,
                strip_prompt=False,
                strip_command=False,
            )
            logger.debug("Initial file-get output: %r", output)

            # Handle SFTP host prompt
            output += self._send_and_wait(sftp_host + "\n", "username", "SFTP host")

            # Handle SFTP username prompt
            output += self._send_and_wait(sftp_username + "\n", "password", "SFTP username")

            # Handle SFTP password prompt (never log password)
            output += self._send_and_wait(sftp_password + "\n", "directory", "SFTP password")

            # Handle destination directory prompt
            output += self._send_and_wait(sftp_remote_dir + "\n", "proceed", "SFTP directory")

            # Handle confirmation/proceed prompt if present
            if "proceed" in output.lower() or "confirm" in output.lower() or "continue" in output.lower():
                output += self._send_and_wait("y\n", "admin:", "confirmation")

            # Wait for transfer completion - look for admin: prompt return
            output += self._wait_for_prompt(timeout=300)

            logger.info("CUCM file-get completed: filename=%s", filename)
            return output

        except Exception as e:
            logger.error("CUCM file-get failed: filename=%s error=%s", filename, e)
            raise CUCMCommandError(
                f"CUCM file-get failed: {e}",
                command=command,
            ) from e

    def _send_and_wait(self, text: str, expect_pattern: str, description: str, timeout: int = 30) -> str:
        """Send text and wait for expected pattern in output.

        Args:
            text: Text to send (e.g., username, password, directory).
            expect_pattern: Pattern to wait for in output.
            description: Description for logging (never includes sensitive data).
            timeout: Timeout in seconds.

        Returns:
            Accumulated output.
        """
        if not self._connection or not self._connection.remote_conn:
            raise CUCMConnectionError("No active SSH channel")

        channel = self._connection.remote_conn
        channel.send(text)

        output = ""
        start_time = time.time()
        pattern_re = re.compile(expect_pattern, re.IGNORECASE)

        while time.time() - start_time < timeout:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                output += chunk
                logger.debug("%s response chunk: %r", description, chunk)

                if pattern_re.search(output):
                    logger.debug("%s prompt detected", description)
                    return output
            else:
                time.sleep(0.2)

        logger.warning("%s prompt not detected within %ds, output so far: %r", description, timeout, output)
        return output

    def _wait_for_prompt(self, timeout: int = 300) -> str:
        """Wait for the admin: prompt to return, indicating command completion.

        Args:
            timeout: Maximum time to wait in seconds.

        Returns:
            Output accumulated while waiting.
        """
        if not self._connection or not self._connection.remote_conn:
            raise CUCMConnectionError("No active SSH channel")

        channel = self._connection.remote_conn
        output = ""
        start_time = time.time()
        prompt_re = re.compile(r"admin:\s*$")

        while time.time() - start_time < timeout:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                output += chunk
                logger.debug("Transfer wait chunk: %r", chunk)

                if prompt_re.search(output):
                    logger.debug("admin: prompt detected - transfer complete")
                    return output
            else:
                time.sleep(0.5)

        logger.warning("admin: prompt not detected within %ds", timeout)
        return output


def create_transport(config: Optional[TransportConfig] = None) -> CUCMTransport:
    """Factory function to create CUCM transport.

    Uses CUCM CLI Administrator credentials (CUCM_CLI_USERNAME/PASSWORD).
    Does NOT use AXL credentials (CUCM_USERNAME/PASSWORD) or Platform credentials.
    """
    if config is None:
        settings = get_settings()
        cli_username = settings.cucm_cli_username or ""
        cli_password = (
            settings.cucm_cli_password.get_secret_value()
            if settings.cucm_cli_password else ""
        )
        config = TransportConfig(
            host=settings.cucm_host or "",
            port=settings.cucm_ssh_port,
            username=cli_username,
            password=cli_password,
            timeout=settings.cucm_ssh_timeout,
            command_timeout=settings.cucm_command_timeout,
            prompt_timeout=settings.cucm_prompt_timeout,
        )
    return NetmikoTransport(config)