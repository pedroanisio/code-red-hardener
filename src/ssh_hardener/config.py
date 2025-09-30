"""Configuration management for SSH Hardener."""

import os
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SSHConfig(BaseSettings):
    """SSH configuration settings."""

    port: int = Field(default=2222, ge=1, le=65535, description="SSH port number")
    admin_users: List[str] = Field(
        default_factory=list, description="List of admin usernames"
    )
    max_auth_tries: int = Field(default=3, ge=1, le=10)
    max_sessions: int = Field(default=10, ge=1, le=100)
    client_alive_interval: int = Field(default=300, ge=0)
    client_alive_count_max: int = Field(default=2, ge=0)
    login_grace_time: int = Field(default=60, ge=10)
    permit_root_login: bool = Field(default=False)
    password_authentication: bool = Field(default=False)
    pubkey_authentication: bool = Field(default=True)
    x11_forwarding: bool = Field(default=False)

    model_config = SettingsConfigDict(
        env_prefix="SSH_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @field_validator("admin_users", mode="before")
    @classmethod
    def parse_admin_users(cls, v: object) -> List[str]:
        """Parse admin users from comma-separated string or list."""
        if isinstance(v, str):
            return [u.strip() for u in v.split(",") if u.strip()]
        if isinstance(v, list):
            return [str(u).strip() for u in v if str(u).strip()]
        return []


class SecurityConfig(BaseSettings):
    """Security feature configuration."""

    enable_fail2ban: bool = Field(default=True)
    enable_firewall: bool = Field(default=True)
    fail2ban_bantime: int = Field(default=3600, ge=60)
    fail2ban_findtime: int = Field(default=600, ge=60)
    fail2ban_maxretry: int = Field(default=3, ge=1)

    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        env_file=".env",
        env_file_encoding="utf-8",
    )


class BackupConfig(BaseSettings):
    """Backup configuration."""

    directory: Path = Field(default=Path("/root/security_backups"))

    model_config = SettingsConfigDict(
        env_prefix="BACKUP_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    def __init__(self, **data: object) -> None:
        """Initialize backup configuration."""
        super().__init__(**data)
        # Use user home if not root
        if os.geteuid() != 0:
            self.directory = Path.home() / "security_backups"


class LoggingConfig(BaseSettings):
    """Logging configuration."""

    level: str = Field(default="INFO")
    file: Optional[Path] = Field(default=None)

    model_config = SettingsConfigDict(
        env_prefix="LOG_",
        env_file=".env",
        env_file_encoding="utf-8",
    )


class HardenerConfig(BaseSettings):
    """Main configuration container."""

    ssh: SSHConfig = Field(default_factory=SSHConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    backup: BackupConfig = Field(default_factory=BackupConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    @classmethod
    def from_env(cls) -> "HardenerConfig":
        """Create configuration from environment variables."""
        return cls(
            ssh=SSHConfig(),
            security=SecurityConfig(),
            backup=BackupConfig(),
            logging=LoggingConfig(),
        )

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues: List[str] = []

        if not self.ssh.admin_users:
            issues.append("No admin users configured")

        if self.ssh.port < 1024 and os.geteuid() != 0:
            issues.append(f"Port {self.ssh.port} requires root privileges")

        if not self.ssh.password_authentication and not self.ssh.pubkey_authentication:
            issues.append("All authentication methods disabled")

        return issues