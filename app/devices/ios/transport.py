"""Cisco IOS / IOS-XE Voice Gateway Netmiko transport."""

from typing import Optional
from pydantic import SecretStr
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger("devices.ios.transport")


class IOSVoiceGatewayTransport:
    """Dedicated Netmiko SSH transport for Cisco IOS / IOS-XE Voice Gateways."""

    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
    ):
        settings = get_settings()
        self.host = host or settings.gateway_host or "127.0.0.1"
        self.username = username or settings.gateway_username or "admin"
        if password is not None:
            self.password = password
        elif settings.gateway_password:
            self.password = settings.gateway_password.get_secret_value()
        else:
            self.password = ""
        self.port = port or settings.gateway_ssh_port or 22
        self.timeout = timeout
        self._connection = None

    def connect(self) -> None:
        """Establish SSH connection to Cisco IOS gateway."""
        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise RuntimeError("Netmiko library is required for Cisco IOS connections")

        logger.info("Connecting to Cisco IOS Gateway at %s:%d", self.host, self.port)
        device_params = {
            "device_type": "cisco_ios",
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "conn_timeout": self.timeout,
            "banner_timeout": 15,
            "auth_timeout": 15,
        }
        self._connection = ConnectHandler(**device_params)
        logger.info("Connected to Cisco IOS Gateway at %s", self.host)

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception as e:
                logger.warning("Error disconnecting from IOS gateway: %s", e)
            finally:
                self._connection = None
                logger.info("Disconnected from Cisco IOS Gateway")

    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connection is not None and self._connection.is_alive()

    def send_command(self, command: str, timeout: Optional[int] = None) -> str:
        """Send a CLI command to Cisco IOS gateway and return output."""
        if not self._connection or not self.is_connected():
            self.connect()

        cmd_timeout = timeout or self.timeout
        logger.info("Executing IOS command: %s (timeout=%ds)", command, cmd_timeout)
        output = self._connection.send_command(
            command,
            read_timeout=cmd_timeout,
        )
        return output

    def __enter__(self) -> "IOSVoiceGatewayTransport":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
