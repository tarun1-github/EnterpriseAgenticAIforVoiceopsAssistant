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
import logging

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

    def _redact_secrets(self, text: str, secrets: list[str]) -> str:
        """Redact sensitive data from text for safe logging."""
        if not text:
            return text
        redacted = text
        for secret in secrets:
            if secret:
                redacted = redacted.replace(secret, "[REDACTED]")
        return redacted

    def _detect_prompt(self, buffer: str) -> Optional[str]:
        """Detect the current prompt type from buffer.

        Returns the prompt type: 'host', 'confirm', 'username', 'password', 'directory', 'admin', or None.
        """
        buffer_lower = buffer.lower()

        # Check for host-key confirmation (yes/no) prompt - must check BEFORE host prompt
        # Pattern: "Please answer 'y' for <yes> or 'n' for no:" or similar variations
        if re.search(r"please\s+answer.*[yn].*(yes|no)", buffer_lower) or \
           re.search(r"answer.*[yn].*(yes|no)", buffer_lower) or \
           re.search(r"\(y/n\)", buffer_lower) or \
           re.search(r"\[yes/no\]", buffer_lower) or \
           (re.search(r"are you sure", buffer_lower) and re.search(r"(yes|no)", buffer_lower)) or \
           re.search(r"would\s+you\s+like\s+to\s+proceed\s*\[y/n\]", buffer_lower):
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
        """Execute interactive CUCM 'file get' command for SFTP transfer.

        State machine for CUCM 15 interactive file-get:
        1. Send 'file get ...' command
        2. Wait for initial confirmation (CUCM overwrite prompt):
           - "Please answer 'y' for <yes> or 'n' for <no>:" -> send 'y'
        3. Wait for file-gathering phase:
           - "Please wait while the system is gathering files info ..."
           - "Get file: ..."
           - "done."
        4. Wait for SFTP host prompt -> send host
        5. Wait for host-key confirmation (yes/no) -> send 'y'
        6. Wait for username prompt -> send username
        7. Wait for password prompt -> send password (never logged)
        8. Wait for destination directory prompt -> send directory
        9. Handle optional confirmation prompt -> send 'y'
        10. Wait for transfer completion (admin: prompt)

        Args:
            filename: Name of the SDL file to transfer.
            sftp_host: SFTP server hostname/IP.
            sftp_username: SFTP username.
            sftp_password: SFTP password (never logged).
            sftp_remote_dir: Remote directory on SFTP server.
            remote_path: CUCM source directory.

        Returns:
            Command output from CUCM (redacted).

        Raises:
            CUCMCommandError: If command fails or transfer fails.
            CUCMTimeoutError: If transfer times out.
        """
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"

        logger.info("FILE_GET_SENT: filename=%s sftp_host=%s", filename, sftp_host)

        # Secrets to redact from logs
        secrets = [sftp_password, self.config.password]
        if sftp_username:
            secrets.append(sftp_username)

        def _sanitize_preview(text: str, max_len: int = 200) -> str:
            """Return redacted preview of text, limited to max_len chars."""
            if not text:
                return ""
            sanitized = self._redact_secrets(text, secrets)
            # Replace newlines and limit length
            sanitized = sanitized.replace("\n", "\\n").replace("\r", "\\r")
            if len(sanitized) > max_len:
                sanitized = sanitized[:max_len] + "..."
            return sanitized

        def _log_state_transition(new_state: str, prompt_type: str = None, preview: str = None):
            """Log state transition with optional prompt info."""
            if prompt_type and preview:
                logger.info("STATE_TRANSITION: state=%s prompt=%s preview=%s", new_state, prompt_type, preview)
            elif prompt_type:
                logger.info("STATE_TRANSITION: state=%s prompt=%s", new_state, prompt_type)
            else:
                logger.info("STATE_TRANSITION: state=%s", new_state)

        def _check_file_gather_complete(buffer: str) -> bool:
            """Check if file-gathering phase has completed (detect 'done.' line)."""
            # Look for "done." as a standalone line (allowing CR/LF and whitespace)
            import re
            # Match "done." at end of line, possibly preceded by whitespace
            return bool(re.search(r'(^|\n)\s*done\.\s*($|\n)', buffer))

        def _check_proceed_confirm(buffer: str) -> bool:
            """Check if CUCM is asking to proceed after file-gather.
            
            Matches: "Would you like to proceed [y/n]?"
            """
            import re
            return bool(re.search(r"would\s+you\s+like\s+to\s+proceed\s*\[y/n\]", buffer.lower()))

        try:
            # Send the initial command
            channel = self._connection.remote_conn
            channel.send(command + "\n")

            # State machine - wait for initial response (confirmation OR file-gather)
            state = "WAITING_FOR_INITIAL_RESPONSE"
            output_buffer = ""
            overall_start = time.time()
            overall_timeout = 600  # 10 minutes total
            prompt_timeout = 30   # 30 seconds per prompt
            prompt_wait_start = time.time()

            # Track what we've sent to avoid re-sending
            sent_initial_confirm = False
            sent_host = False
            sent_host_key_confirm = False
            sent_proceed_confirm = False
            sent_username = False
            sent_password = False
            sent_directory = False
            sent_final_confirm = False

            # Buffer cursor: tracks how much of output_buffer has been processed
            # This prevents re-detecting the same prompt from the same buffer
            buffer_processed = 0

            # Drain any immediate output without blocking
            def _drain_available():
                nonlocal output_buffer
                while channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                    output_buffer += chunk

            # Initial drain - don't wait if data already available
            _drain_available()
            _log_state_transition("WAITING_FOR_INITIAL_RESPONSE")

            while time.time() - overall_start < overall_timeout:
                data_available = channel.recv_ready()
                if data_available:
                    _drain_available()
                    prompt_wait_start = time.time()  # Reset prompt timeout on data

                    # Process accumulated buffer: keep re-processing as long as state changes
                    # This handles cases where one channel read contains multiple sequential events
                    state_changed = True
                    while state_changed:
                        state_changed = False
                        prev_state = state

                        # Only examine unprocessed portion of buffer
                        unprocessed = output_buffer[buffer_processed:]
                        
                        if state == "WAITING_FOR_INITIAL_RESPONSE":
                            # Check for initial CUCM overwrite confirmation
                            prompt_type = self._detect_prompt(unprocessed)
                            if prompt_type == "confirm":
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("INITIAL_CONFIRM_DETECTED", prompt_type, preview)
                                channel.send("y\n")
                                sent_initial_confirm = True
                                state = "WAITING_FOR_FILE_GATHER"
                                _log_state_transition("WAITING_FOR_FILE_GATHER")
                                buffer_processed = len(output_buffer)  # Consume all
                                state_changed = True
                            elif "gathering files info" in output_buffer.lower():
                                # File-gather output arrived without initial confirmation
                                _log_state_transition("FILE_GATHER_STARTED")
                                state = "WAITING_FOR_FILE_GATHER"
                                _log_state_transition("WAITING_FOR_FILE_GATHER")
                                buffer_processed = len(output_buffer)
                                state_changed = True
                        elif state == "WAITING_FOR_FILE_GATHER":
                            # Check for file-gathering phase completion
                            if _check_file_gather_complete(output_buffer):
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("FILE_GATHER_COMPLETE", preview=preview)
                                
                                # ENHANCED DIAGNOSTIC: Capture what CUCM sends after done.
                                # 1. Log complete accumulated buffer tail (max 1000 chars)
                                buffer_tail = _sanitize_preview(output_buffer, max_len=1000)
                                logger.info("POST_GATHER_BUFFER_TAIL: %s", buffer_tail)
                                
                                # 2. Log last 300 chars after standalone "done." marker
                                import re
                                done_match = re.search(r'(?s)(done\..*)$', output_buffer)
                                if done_match:
                                    after_done = done_match.group(1)
                                    after_done_preview = _sanitize_preview(after_done, max_len=300)
                                    logger.info("POST_GATHER_AFTER_DONE: %s", after_done_preview)
                                
                                # 3. Run _detect_prompt() against COMPLETE accumulated buffer
                                prompt_from_buffer = self._detect_prompt(output_buffer)
                                logger.info("POST_GATHER_PROMPT_FROM_BUFFER: %s", prompt_from_buffer if prompt_from_buffer else "none")
                                
                                # 4. Short non-blocking drain for any additional data
                                post_gather_buffer = ""
                                while channel.recv_ready():
                                    chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                                    post_gather_buffer += chunk
                                    output_buffer += chunk
                                
                                # 5. If additional data exists, log it
                                if post_gather_buffer:
                                    new_data_preview = _sanitize_preview(post_gather_buffer, max_len=500)
                                    logger.info("POST_GATHER_NEW_DATA: %s", new_data_preview)
                                    
                                    # 6. Run _detect_prompt() against newly received data
                                    prompt_from_new = self._detect_prompt(post_gather_buffer)
                                    logger.info("POST_GATHER_PROMPT_FROM_NEW_DATA: %s", prompt_from_new if prompt_from_new else "none")
                                
                                # Check for CUCM "proceed" confirmation after file-gather
                                if _check_proceed_confirm(output_buffer):
                                    _log_state_transition("WAITING_FOR_PROCEED_CONFIRM")
                                    state = "WAITING_FOR_PROCEED_CONFIRM"
                                else:
                                    state = "WAITING_FOR_HOST"
                                    _log_state_transition("WAITING_FOR_HOST")
                                buffer_processed = len(output_buffer)
                                state_changed = True
                            else:
                                # Still in file-gathering phase, log progress
                                if "gathering files info" in output_buffer.lower():
                                    _log_state_transition("FILE_GATHER_STARTED")
                                elif "get file:" in output_buffer.lower():
                                    pass
                        else:
                            # Detect current prompt for SFTP phase - only examine unprocessed portion
                            unprocessed = output_buffer[buffer_processed:]
                            prompt_type = self._detect_prompt(unprocessed)

                            if state == "WAITING_FOR_PROCEED_CONFIRM":
                                # Handle CUCM "Would you like to proceed [y/n]?" prompt
                                if prompt_type == "confirm" and not sent_proceed_confirm:
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("PROCEED_CONFIRM_DETECTED", prompt_type, preview)
                                    channel.send("y\n")
                                    sent_proceed_confirm = True
                                    state = "WAITING_FOR_HOST"
                                    _log_state_transition("WAITING_FOR_HOST")
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                            elif state == "WAITING_FOR_HOST":
                                if prompt_type == "host":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("HOST_PROMPT_DETECTED", prompt_type, preview)
                                    channel.send(sftp_host + "\n")
                                    sent_host = True
                                    state = "WAITING_FOR_CONFIRM"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                                elif prompt_type == "confirm" and not sent_host:
                                    # Sometimes host-key confirmation comes immediately
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("HOST_KEY_CONFIRM_DETECTED", prompt_type, preview)
                                    channel.send("y\n")
                                    sent_host_key_confirm = True
                                    buffer_processed = len(output_buffer)
                                    # Stay in WAITING_FOR_HOST, expect host prompt next
                            elif state == "WAITING_FOR_CONFIRM":
                                if prompt_type == "confirm":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("HOST_KEY_CONFIRM_DETECTED", prompt_type, preview)
                                    channel.send("y\n")
                                    sent_host_key_confirm = True
                                    state = "WAITING_FOR_USERNAME"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                                elif prompt_type == "username":
                                    # No confirmation needed, go straight to username
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("USERNAME_PROMPT_DETECTED", prompt_type, preview)
                                    state = "WAITING_FOR_USERNAME"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                            elif state == "WAITING_FOR_USERNAME":
                                if prompt_type == "username":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("USERNAME_PROMPT_DETECTED", prompt_type, preview)
                                    channel.send(sftp_username + "\n")
                                    sent_username = True
                                    state = "WAITING_FOR_PASSWORD"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                            elif state == "WAITING_FOR_PASSWORD":
                                if prompt_type == "password":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("PASSWORD_PROMPT_DETECTED", prompt_type, preview)
                                    channel.send(sftp_password + "\n")
                                    sent_password = True
                                    state = "WAITING_FOR_DIRECTORY"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                            elif state == "WAITING_FOR_DIRECTORY":
                                if prompt_type == "directory":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("DIRECTORY_PROMPT_DETECTED", prompt_type, preview)
                                    channel.send(sftp_remote_dir + "\n")
                                    sent_directory = True
                                    state = "WAITING_FOR_FINAL_CONFIRM"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                            elif state == "WAITING_FOR_FINAL_CONFIRM":
                                if prompt_type == "confirm":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("FINAL_CONFIRM_DETECTED", prompt_type, preview)
                                    channel.send("y\n")
                                    sent_final_confirm = True
                                    state = "TRANSFER_STARTED"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                                elif prompt_type == "admin":
                                    # No final confirmation, transfer starting
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("TRANSFER_STARTED", prompt_type, preview)
                                    state = "TRANSFER_STARTED"
                                    buffer_processed = len(output_buffer)
                                    state_changed = True
                            elif state == "TRANSFER_STARTED":
                                if prompt_type == "admin":
                                    preview = _sanitize_preview(output_buffer)
                                    _log_state_transition("TRANSFER_COMPLETE", prompt_type, preview)
                                    _log_state_transition("ADMIN_PROMPT_DETECTED", prompt_type, preview)
                                    logger.info("CUCM file-get completed: filename=%s", filename)
                                    return self._redact_secrets(output_buffer, secrets)

                else:
                    # No data available - check prompt timeout
                    if time.time() - prompt_wait_start > prompt_timeout:
                        # Log timeout state with sanitized buffer preview
                        preview = _sanitize_preview(output_buffer) if output_buffer else "(no output)"
                        logger.warning("PROMPT_TIMEOUT: state=%s waited=%ds preview=%s", state, prompt_timeout, preview)
                        raise CUCMTimeoutError(
                            f"CUCM file-get prompt timeout in state '{state}' after {prompt_timeout}s",
                            timeout_type="file_get_prompt",
                            timeout_value=prompt_timeout,
                        )
                    time.sleep(0.1)

            # If we get here, we timed out
            preview = _sanitize_preview(output_buffer) if output_buffer else "(no output)"
            logger.error("OVERALL_TIMEOUT: state=%s waited=%ds preview=%s", state, overall_timeout, preview)
            raise CUCMTimeoutError(
                f"CUCM file-get timed out after {overall_timeout}s in state '{state}'",
                timeout_type="file_get",
                timeout_value=overall_timeout,
            )

        except CUCMTimeoutError:
            raise
        except Exception as e:
            logger.error("CUCM file-get failed: filename=%s error=%s", filename, e)
            raise CUCMCommandError(
                f"CUCM file-get failed: {e}",
                command=command,
            ) from e


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