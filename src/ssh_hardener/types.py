"""Type definitions for SSH Hardener."""

from enum import Enum
from typing import NamedTuple


class InitSystem(str, Enum):
    """Supported init systems."""

    SYSTEMD = "systemd"
    SYSVINIT = "sysvinit"
    UPSTART = "upstart"
    OPENRC = "openrc"
    UNKNOWN = "unknown"


class FirewallType(str, Enum):
    """Supported firewall types."""

    UFW = "ufw"
    FIREWALLD = "firewalld"
    IPTABLES = "iptables"
    NONE = "none"


class PackageManager(str, Enum):
    """Supported package managers."""

    APT = "apt"
    YUM = "yum"
    DNF = "dnf"
    ZYPPER = "zypper"
    PACMAN = "pacman"
    NONE = "none"


class CommandResult(NamedTuple):
    """Result of command execution."""

    success: bool
    stdout: str
    stderr: str
    return_code: int = 0


class RollbackPoint(NamedTuple):
    """Backup information for rollback."""

    original_path: str
    backup_path: str
    timestamp: str