"""Application configuration using Pydantic Settings."""

import os
from functools import lru_cache
from typing import Literal, Optional
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General App Configuration
    app_name: str = "VoiceOps AI"
    app_env: str = Field(default="development", description="Environment: development, test, production")
    log_level: str = Field(default="INFO", description="Logging level: DEBUG, INFO, WARNING, ERROR")

    # LLM Provider Abstraction
    llm_provider: Literal["openai", "gemini", "ollama"] = Field(
        default="openai",
        description="Active LLM provider: openai, gemini, or ollama",
    )
    llm_model: str = Field(
        default="gpt-4o",
        description="Target model identifier (e.g. gpt-4o, gemini-1.5-pro, llama3)",
    )
    openai_api_key: Optional[SecretStr] = Field(
        default=None,
        description="OpenAI API secret key",
    )
    gemini_api_key: Optional[SecretStr] = Field(
        default=None,
        description="Google Gemini API secret key",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama local endpoint URL",
    )

    # Cisco CUCM 15.0 (Reserved for future live connectivity)
    cucm_host: Optional[str] = Field(default=None, description="CUCM Publisher IP or FQDN")
    cucm_port: int = Field(default=8443, description="AXL/RIS port")
    cucm_username: Optional[str] = Field(default=None, description="CUCM Application user")
    cucm_password: Optional[SecretStr] = Field(default=None, description="CUCM Application password")
    cucm_verify_ssl: bool = Field(default=False, description="Verify CUCM TLS certificate")

    # Cisco CUCM SSH/CLI Configuration (for trace collection)
    cucm_ssh_port: int = Field(default=22, description="CUCM SSH port")
    cucm_ssh_timeout: int = Field(default=30, description="SSH connection timeout (seconds)")
    cucm_command_timeout: int = Field(default=60, description="CLI command execution timeout (seconds)")
    cucm_prompt_timeout: int = Field(default=15, description="Prompt detection timeout (seconds)")

    # Cisco Voice Gateway (Reserved for future live integration)
    gateway_host: Optional[str] = Field(default=None, description="Voice Gateway IP or FQDN")
    gateway_username: Optional[str] = Field(default=None, description="Gateway SSH user")
    gateway_password: Optional[SecretStr] = Field(default=None, description="Gateway SSH password")
    gateway_ssh_port: int = Field(default=22, description="Gateway SSH port")

    def is_provider_configured(self) -> bool:
        """Check if the currently selected LLM provider has necessary credentials."""
        if self.llm_provider == "openai":
            return bool(self.openai_api_key and self.openai_api_key.get_secret_value())
        elif self.llm_provider == "gemini":
            return bool(self.gemini_api_key and self.gemini_api_key.get_secret_value())
        elif self.llm_provider == "ollama":
            return bool(self.ollama_base_url)
        return False


@lru_cache
def get_settings() -> Settings:
    """Return cached instance of application settings."""
    return Settings()
