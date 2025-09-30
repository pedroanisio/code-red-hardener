"""System information detection for SSH Hardener."""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ssh_hardener.exceptions import SystemRequirementError
from ssh_hardener.types import CommandResult, FirewallType, InitSystem, PackageManager


class SystemInfo:
    """Detect and store system capabilities."""

    def __init__(self) -> None:
        """Initialize system information detection."""
        self.distro = self._detect_distro()
        self.package_manager = self._detect_package_manager()
        self.init_system = self._detect_init_system()
        self.firewall_type = self._detect_firewall()
        self.is_root = os.geteuid() == 0
        self.has_sudo = self._check_sudo()
        self.can_be_root = self.is_root or self.has_sudo

    def _detect_distro(self) -> str:
        """Detect Linux distribution."""
        os_release = Path("/etc/os-release")
        if not os_release.exists():
            return "unknown"

        with open(os_release) as f:
            for line in f:
                if line.startswith("ID="):
                    return line.split("=")[1].strip().strip('"').lower()
        return "unknown"

    def _detect_package_manager(self) -> PackageManager:
        """Detect available package manager."""
        managers = {
            "apt": PackageManager.APT,
            "yum": PackageManager.YUM,
            "dnf": PackageManager.DNF,
            "zypper": PackageManager.ZYPPER,
            "pacman": PackageManager.PACMAN,
        }

        for cmd, pm_type in managers.items():
            if self._command_exists(cmd):
                return pm_type

        return PackageManager.NONE

    def _detect_init_system(self) -> InitSystem:
        """Detect init system."""
        checks = [
            ("systemctl --version", InitSystem.SYSTEMD),
            ("service --version", InitSystem.SYSVINIT),
            ("initctl --version", InitSystem.UPSTART),
            ("rc-service --version", InitSystem.OPENRC),
        ]

        for cmd, system in checks:
            result = self._run_command(cmd, check=False)
            if result.success:
                return system

        return InitSystem.UNKNOWN

    def _detect_firewall(self) -> FirewallType:
        """Detect available firewall tool."""
        if self._command_exists("ufw"):
            return FirewallType.UFW
        if self._command_exists("firewall-cmd"):
            return FirewallType.FIREWALLD
        if self._command_exists("iptables"):
            return FirewallType.IPTABLES
        return FirewallType.NONE

    def _check_sudo(self) -> bool:
        """Check if current user can use sudo."""
        if self.is_root:
            return True

        if not self._command_exists("sudo"):
            return False

        result = self._run_command("sudo -n true 2>/dev/null", check=False)
        return result.success

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists."""
        result = self._run_command(f"which {command}", check=False)
        return result.success

    def _run_command(
        self, cmd: str, check: bool = True, timeout: int = 10
    ) -> CommandResult:
        """Execute shell command and return result."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(False, "", "Command timed out", -1)
        except Exception as e:
            return CommandResult(False, "", str(e), -1)

    def get_package_install_command(self, package: str) -> str:
        """Get package installation command for this system."""
        commands = {
            PackageManager.APT: f"apt-get install -y {package}",
            PackageManager.YUM: f"yum install -y {package}",
            PackageManager.DNF: f"dnf install -y {package}",
            PackageManager.ZYPPER: f"zypper install -y {package}",
            PackageManager.PACMAN: f"pacman -S --noconfirm {package}",
        }
        return commands.get(self.package_manager, "")

    def get_service_command(self, service: str, action: str) -> str:
        """Get service control command for this init system."""
        if self.init_system == InitSystem.SYSTEMD:
            return f"systemctl {action} {service}"
        elif self.init_system == InitSystem.SYSVINIT:
            if action == "enable":
                return f"chkconfig {service} on"
            return f"service {service} {action}"
        elif self.init_system == InitSystem.UPSTART:
            if action == "enable":
                return "true"  # Upstart handles automatically
            return f"{action} {service}"
        elif self.init_system == InitSystem.OPENRC:
            if action == "enable":
                return f"rc-update add {service}"
            return f"rc-service {service} {action}"
        return ""

    def check_requirements(self) -> List[str]:
        """Check if system meets minimum requirements."""
        issues: List[str] = []

        if not self.can_be_root:
            issues.append("No root access available (need root or sudo)")

        if self.package_manager == PackageManager.NONE:
            issues.append("No supported package manager found")

        if not Path("/etc/ssh/sshd_config").exists():
            issues.append("SSH config not found at /etc/ssh/sshd_config")

        if self.init_system == InitSystem.UNKNOWN:
            issues.append("Cannot detect init system")

        return issues

    def to_dict(self) -> Dict[str, str]:
        """Convert system info to dictionary."""
        return {
            "distro": self.distro,
            "package_manager": self.package_manager.value,
            "init_system": self.init_system.value,
            "firewall": self.firewall_type.value,
            "is_root": str(self.is_root),
            "has_sudo": str(self.has_sudo),
        }