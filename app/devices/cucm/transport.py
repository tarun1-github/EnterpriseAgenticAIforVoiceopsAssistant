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
    prompt_timeout: int = 30


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
        sftp_port: int = 22,
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
                    timeout = getattr(self, "banner_timeout", 35) or 35

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

        Returns the prompt type: 'host', 'confirm', 'proceed_confirm', 'port', 'username', 'password', 'directory', 'admin', or None.
        """
        buffer_lower = buffer.lower()

        # Check for PROCEED_CONFIRM - exact live CUCM prompt (must check FIRST)
        if re.search(r"would\s+you\s+like\s+to\s+proceed\s*\[y/n\]", buffer_lower):
            return "proceed_confirm"

        # Check for host-key / initial confirmation (yes/no) prompt - must check BEFORE host prompt
        # Pattern: "Please answer 'y' for <yes> or 'n' for no:" or similar variations
        if re.search(r"please\s+answer.*[yn].*(yes|no)", buffer_lower) or \
           re.search(r"answer.*[yn].*(yes|no)", buffer_lower) or \
           re.search(r"\(y/n\)", buffer_lower) or \
           re.search(r"\[yes/no\]", buffer_lower) or \
           (re.search(r"are you sure", buffer_lower) and re.search(r"(yes|no)", buffer_lower)):
            return "confirm"

        # Check for SFTP port prompt
        if re.search(r"(?:sftp\s*(?:server\s*)?)?port\s*(?:\[[^\]]*\])?\s*:", buffer_lower):
            return "port"

        # Check for SFTP host prompt - various forms including "SFTP server IP:"
        if re.search(r"(?:sftp|ssh).*host", buffer_lower) or \
           re.search(r"remote.*host", buffer_lower) or \
           re.search(r"destination.*host", buffer_lower) or \
           re.search(r"server.*name", buffer_lower) or \
           re.search(r"sftp\s*(?:server\s*)?(?:ip|host)", buffer_lower):
            return "host"

        # Check for username prompt (including "User ID:", "Username:", "User name:", "Login name:", but not "User:")
        if re.search(r"(user|login).*name", buffer_lower) or \
           re.search(r"user\s*id", buffer_lower) or \
           re.search(r"username", buffer_lower):
            return "username"

        # Check for password prompt
        if re.search(r"password", buffer_lower) and not re.search(r"password.*again", buffer_lower):
            return "password"

        # Check for directory prompt (including "Download directory:")
        if re.search(r"(destination|remote|download).*dir", buffer_lower) or \
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
        sftp_port: int = 22,
    ) -> str:
        """Execute interactive CUCM 'file get' command for SFTP transfer.

        Stream-based state machine for CUCM 15 interactive file-get:
        1. Send 'file get ...' command
        2. WAITING_FOR_INITIAL_RESPONSE:
           - INITIAL_CONFIRM_DETECTED -> send 'y' -> WAITING_FOR_FILE_GATHER
           - OR FILE_GATHER_STARTED -> WAITING_FOR_FILE_GATHER
        3. WAITING_FOR_FILE_GATHER:
           - FILE_GATHER_COMPLETE ('done.' or file stats) -> WAITING_FOR_PROCEED_CONFIRM
        4. WAITING_FOR_PROCEED_CONFIRM:
           - PROCEED_CONFIRM_DETECTED ('Would you like to proceed [y/n]?') -> send 'y' -> WAITING_FOR_HOST
           - OR HOST_PROMPT_DETECTED (if proceed skipped) -> send host -> WAITING_FOR_CONFIRM
        5. WAITING_FOR_HOST:
           - HOST_PROMPT_DETECTED ('SFTP server IP:', 'SFTP host:', etc.) -> send host -> WAITING_FOR_CONFIRM
        6. WAITING_FOR_CONFIRM:
           - If port prompt ('SFTP server port [22]:'): send port -> continue
           - If host-key confirm required: HOST_KEY_CONFIRM_DETECTED -> send 'y' -> WAITING_FOR_USERNAME
           - If host-key confirm NOT required: USERNAME_PROMPT_DETECTED -> send username -> WAITING_FOR_PASSWORD
        7. WAITING_FOR_USERNAME:
           - If port prompt: send port -> continue
           - If host-key confirm: send 'y' -> continue
           - USERNAME_PROMPT_DETECTED ('User ID:', 'Username:', 'User:') -> send username -> WAITING_FOR_PASSWORD
        8. WAITING_FOR_PASSWORD:
           - PASSWORD_PROMPT_DETECTED -> send password -> WAITING_FOR_DIRECTORY
        9. WAITING_FOR_DIRECTORY:
           - DIRECTORY_PROMPT_DETECTED ('Download directory:', 'Destination directory:', etc.) -> send directory -> WAITING_FOR_FINAL_CONFIRM
        10. WAITING_FOR_FINAL_CONFIRM:
            - FINAL_CONFIRM_DETECTED -> send 'y' -> TRANSFER_STARTED
            - OR TRANSFER_STARTED (if no final confirm)
        11. TRANSFER_STARTED:
            - TRANSFER_COMPLETE / ADMIN_PROMPT_DETECTED ('admin:' prompt returned)

        All transitions consume the matched event by advancing `cursor` past the match,
        guaranteeing that already-processed input is never detected again.
        """
        if not self.is_connected():
            raise CUCMConnectionError("Not connected to CUCM")

        full_remote_path = f"{remote_path}/{filename}"
        command = f"file get {full_remote_path}"

        logger.info("FILE_GET_SENT: filename=%s sftp_host=%s sftp_port=%s", filename, sftp_host, sftp_port)

        # Secrets to redact from logs
        secrets = [sftp_password, self.config.password]
        if sftp_username:
            secrets.append(sftp_username)

        def _sanitize_preview(text: str, max_len: int = 200) -> str:
            """Return redacted preview of text, limited to max_len chars.
            
            Shows the tail (most recent output) if text exceeds max_len,
            ensuring prompt diagnostics reflect current state.
            """
            if not text:
                return ""
            sanitized = self._redact_secrets(text, secrets)
            sanitized = sanitized.replace("\n", "\\n").replace("\r", "\\r")
            if len(sanitized) > max_len:
                sanitized = "..." + sanitized[-max_len:]
            return sanitized

        def _log_state_transition(new_state: str, prompt_type: str = None, preview: str = None):
            """Log state transition with optional prompt info."""
            if prompt_type and preview:
                logger.info("STATE_TRANSITION: state=%s prompt=%s preview=%s", new_state, prompt_type, preview)
            elif prompt_type:
                logger.info("STATE_TRANSITION: state=%s prompt=%s", new_state, prompt_type)
            else:
                logger.info("STATE_TRANSITION: state=%s", new_state)

        # Comprehensive prompt regex patterns for Cisco CUCM 15 VOS interactive CLI:
        r_host_pattern = (
            r"(?!(?:sftp\s*(?:server\s*)?)?port\b)"
            r"(?:sftp\s*(?:server\s*)?(?:ip|host|name|fqdn)?|(?:remote|destination)\s*(?:host|server|ip)?|server\s*(?:name|ip)?|\bhost)"
            r"(?:[\s/]+(?!port\b)[a-z]+)*\s*(?:\[[^\]]*\])?\s*:"
        )
        r_port_pattern = r"(?:sftp\s*(?:server\s*)?)?port\s*(?:\[[^\]]*\])?\s*:"
        r_user_pattern = r"(?:user\s*(?:id|name)?|username|login\s*(?:name)?)\s*:|(?:^|\n)\s*user\s*:"
        r_pass_pattern = r"(?:enter\s+)?(?:sftp\s+)?password\s*:"
        r_dir_pattern = r"(?:(?:download|destination|remote)\s*)?dir(?:ectory)?\s*:|(?:^|\n)\s*path\s*:"
        r_proceed_pattern = r"would\s+you\s+like\s+to\s+proceed\s*(\[y/n\]|\(y/n\))\??|would\s+you\s+like\s+to\s+proceed"
        r_host_key_pattern = (
            r"are\s+you\s+sure\s+you\s+want\s+to\s+continue\s+connecting.*?(?:yes/no|\(yes/no\))|"
            r"authenticity\s+of\s+host.*?(?:yes/no|\(yes/no\))|"
            r"please\s+answer.*?[yn].*?(?:yes|no):?|"
            r"answer\s+['\"]?[yn]['\"]?.*?(?:yes|no):?|"
            r"\(yes/no\):?|\[yes/no\]:?|\(y/n\):?"
        )
        r_final_confirm_pattern = r"continue\?\s*\(y/n\):?|\(y/n\):?|\[yes/no\]:?|continue\s+connecting"

        try:
            channel = self._connection.remote_conn

            def _send_channel(data: str):
                if hasattr(channel, "sendall"):
                    try:
                        channel.sendall(data.encode("utf-8") if isinstance(data, str) else data)
                        return
                    except Exception:
                        pass
                channel.send(data)

            _send_channel(command + "\n")

            state = "WAITING_FOR_INITIAL_RESPONSE"
            output_buffer = ""
            cursor = 0
            overall_start = time.time()
            overall_timeout = 600  # 10 minutes total
            prompt_timeout = 30    # 30 seconds per prompt
            prompt_wait_start = time.time()

            # Drain any immediate output without blocking
            def _drain_available():
                nonlocal output_buffer
                while channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                    output_buffer += chunk

            _drain_available()
            _log_state_transition("WAITING_FOR_INITIAL_RESPONSE")

            while time.time() - overall_start < overall_timeout:
                if channel.recv_ready():
                    _drain_available()
                    prompt_wait_start = time.time()

                if cursor < len(output_buffer):
                    # Process accumulated buffer as a stream using cursor semantics
                    state_changed = True
                    max_transitions_per_drain = 20
                    transition_count = 0

                    while state_changed:
                        state_changed = False
                        transition_count += 1
                        if transition_count > max_transitions_per_drain:
                            logger.warning("Safety guard: exceeded max state transitions (%d) in single drain", max_transitions_per_drain)
                            break

                        unconsumed = output_buffer[cursor:]
                        if not unconsumed:
                            break

                        if state == "WAITING_FOR_INITIAL_RESPONSE":
                            # Check for initial CUCM overwrite confirmation prompt
                            m_init_confirm = re.search(r"please\s+answer.*?[yn].*?(?:yes|no):?", unconsumed, re.IGNORECASE) or \
                                             re.search(r"answer\s+['\"]?[yn]['\"]?.*?(?:yes|no):?", unconsumed, re.IGNORECASE)
                            m_gather_indicators = re.search(r"gathering\s+files\s+info", unconsumed, re.IGNORECASE) or \
                                                  re.search(r"get\s+file:", unconsumed, re.IGNORECASE) or \
                                                  re.search(r"\bdone\.", unconsumed) or \
                                                  re.search(r"would\s+you\s+like\s+to\s+proceed", unconsumed, re.IGNORECASE)

                            if m_init_confirm:
                                cursor += m_init_confirm.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("INITIAL_CONFIRM_DETECTED", "initial_confirm", preview)
                                _send_channel("y\n")
                                state = "WAITING_FOR_FILE_GATHER"
                                _log_state_transition("WAITING_FOR_FILE_GATHER")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_gather_indicators:
                                m_start = re.search(r"gathering\s+files\s+info", unconsumed, re.IGNORECASE)
                                if m_start:
                                    cursor += m_start.end()
                                    _log_state_transition("FILE_GATHER_STARTED", "gather_started", _sanitize_preview(output_buffer))
                                else:
                                    _log_state_transition("FILE_GATHER_STARTED")
                                state = "WAITING_FOR_FILE_GATHER"
                                _log_state_transition("WAITING_FOR_FILE_GATHER")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_FILE_GATHER":
                            # Check if file gather completed ('done.' line or file statistics)
                            m_done = re.search(r'(?:^|\n)\s*done\.\s*(?:\r?\n|$)', unconsumed) or \
                                     re.search(r'\bdone\.\s*', unconsumed)
                            m_proceed_early = re.search(r"would\s+you\s+like\s+to\s+proceed", unconsumed, re.IGNORECASE)
                            if m_done:
                                cursor += m_done.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("FILE_GATHER_COMPLETE", preview=preview)
                                state = "WAITING_FOR_PROCEED_CONFIRM"
                                _log_state_transition("WAITING_FOR_PROCEED_CONFIRM")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_proceed_early:
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("FILE_GATHER_COMPLETE", preview=preview)
                                state = "WAITING_FOR_PROCEED_CONFIRM"
                                _log_state_transition("WAITING_FOR_PROCEED_CONFIRM")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif "gathering files info" in unconsumed.lower():
                                m_start = re.search(r"gathering\s+files\s+info", unconsumed, re.IGNORECASE)
                                if m_start:
                                    cursor += m_start.end()
                                    _log_state_transition("FILE_GATHER_STARTED")
                                    state_changed = True
                                    prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_PROCEED_CONFIRM":
                            # Check for CUCM prompt: "Would you like to proceed [y/n]?"
                            m_proceed = re.search(r_proceed_pattern, unconsumed, re.IGNORECASE)
                            m_host_direct = re.search(r_host_pattern, unconsumed, re.IGNORECASE)
                            if m_proceed:
                                cursor += m_proceed.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("PROCEED_CONFIRM_DETECTED", "proceed_confirm", preview)
                                _send_channel("y\n")
                                state = "WAITING_FOR_HOST"
                                _log_state_transition("WAITING_FOR_HOST")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_host_direct:
                                # Proceed confirm was skipped by CUCM; host prompt arrived directly
                                cursor += m_host_direct.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("HOST_PROMPT_DETECTED", "host", preview)
                                _send_channel(sftp_host + "\n")
                                state = "WAITING_FOR_CONFIRM"
                                _log_state_transition("WAITING_FOR_CONFIRM")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_HOST":
                            m_host = re.search(r_host_pattern, unconsumed, re.IGNORECASE)
                            if m_host:
                                cursor += m_host.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("HOST_PROMPT_DETECTED", "host", preview)
                                _send_channel(sftp_host + "\n")
                                state = "WAITING_FOR_CONFIRM"
                                _log_state_transition("WAITING_FOR_CONFIRM")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_CONFIRM":
                            m_port = re.search(r_port_pattern, unconsumed, re.IGNORECASE)
                            m_host_key = re.search(r_host_key_pattern, unconsumed, re.IGNORECASE)
                            m_username = re.search(r_user_pattern, unconsumed, re.IGNORECASE)

                            if m_port:
                                cursor += m_port.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("PORT_PROMPT_DETECTED", "port", preview)
                                _send_channel(f"{sftp_port}\n")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_host_key:
                                cursor += m_host_key.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("HOST_KEY_CONFIRM_DETECTED", "confirm", preview)
                                _send_channel("y\n")
                                state = "WAITING_FOR_USERNAME"
                                _log_state_transition("WAITING_FOR_USERNAME")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_username:
                                cursor += m_username.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("USERNAME_PROMPT_DETECTED", "username", preview)
                                _send_channel(sftp_username + "\n")
                                state = "WAITING_FOR_PASSWORD"
                                _log_state_transition("WAITING_FOR_PASSWORD")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_USERNAME":
                            m_port = re.search(r_port_pattern, unconsumed, re.IGNORECASE)
                            m_host_key = re.search(r_host_key_pattern, unconsumed, re.IGNORECASE)
                            m_username = re.search(r_user_pattern, unconsumed, re.IGNORECASE)

                            if m_port:
                                cursor += m_port.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("PORT_PROMPT_DETECTED", "port", preview)
                                _send_channel(f"{sftp_port}\n")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_host_key:
                                cursor += m_host_key.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("HOST_KEY_CONFIRM_DETECTED", "confirm", preview)
                                _send_channel("y\n")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_username:
                                cursor += m_username.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("USERNAME_PROMPT_DETECTED", "username", preview)
                                _send_channel(sftp_username + "\n")
                                state = "WAITING_FOR_PASSWORD"
                                _log_state_transition("WAITING_FOR_PASSWORD")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_PASSWORD":
                            m_password = re.search(r_pass_pattern, unconsumed, re.IGNORECASE)
                            # Check that it's not "password again"
                            if m_password and not re.search(r"password\s+again", unconsumed[:m_password.end()], re.IGNORECASE):
                                cursor += m_password.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("PASSWORD_PROMPT_DETECTED", "password", preview)
                                _send_channel(sftp_password + "\n")
                                state = "WAITING_FOR_DIRECTORY"
                                _log_state_transition("WAITING_FOR_DIRECTORY")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_DIRECTORY":
                            m_dir = re.search(r_dir_pattern, unconsumed, re.IGNORECASE)
                            if m_dir:
                                cursor += m_dir.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("DIRECTORY_PROMPT_DETECTED", "directory", preview)
                                _send_channel(sftp_remote_dir + "\n")
                                state = "WAITING_FOR_FINAL_CONFIRM"
                                _log_state_transition("WAITING_FOR_FINAL_CONFIRM")
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "WAITING_FOR_FINAL_CONFIRM":
                            m_final_confirm = re.search(r_final_confirm_pattern, unconsumed, re.IGNORECASE)
                            m_admin = re.search(r"\badmin:\s*$", output_buffer.rstrip())
                            if m_final_confirm:
                                cursor += m_final_confirm.end()
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("FINAL_CONFIRM_DETECTED", "confirm", preview)
                                _send_channel("y\n")
                                state = "TRANSFER_STARTED"
                                _log_state_transition("TRANSFER_STARTED")
                                state_changed = True
                                prompt_wait_start = time.time()
                            elif m_admin or re.search(r"transfer", unconsumed, re.IGNORECASE):
                                _log_state_transition("TRANSFER_STARTED")
                                state = "TRANSFER_STARTED"
                                state_changed = True
                                prompt_wait_start = time.time()

                        elif state == "TRANSFER_STARTED":
                            m_admin = re.search(r"\badmin:\s*$", output_buffer.rstrip())
                            if m_admin:
                                preview = _sanitize_preview(output_buffer)
                                _log_state_transition("TRANSFER_COMPLETE", "admin", preview)
                                _log_state_transition("ADMIN_PROMPT_DETECTED", "admin", preview)
                                logger.info("CUCM file-get completed: filename=%s", filename)
                                return self._redact_secrets(output_buffer, secrets)

                        # If admin prompt appears at any point after command output received, command finished or aborted
                        if ("\n" in output_buffer.strip()) and re.search(r"\badmin:\s*$", output_buffer.rstrip()):
                            preview = _sanitize_preview(output_buffer)
                            _log_state_transition("TRANSFER_COMPLETE", "admin", preview)
                            _log_state_transition("ADMIN_PROMPT_DETECTED", "admin", preview)
                            logger.info("CUCM file-get completed (admin prompt returned): filename=%s", filename)
                            return self._redact_secrets(output_buffer, secrets)

                # After processing any available buffer transitions:
                # If still waiting for next prompt, check prompt timeout and sleep
                if time.time() - prompt_wait_start > prompt_timeout:
                    preview = _sanitize_preview(output_buffer) if output_buffer else "(no output)"
                    logger.warning("PROMPT_TIMEOUT: state=%s waited=%ds preview=%s", state, prompt_timeout, preview)
                    raise CUCMTimeoutError(
                        f"CUCM file-get prompt timeout in state '{state}' after {prompt_timeout}s",
                        timeout_type="file_get_prompt",
                        timeout_value=prompt_timeout,
                    )
                time.sleep(0.02)

            # Overall timeout
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