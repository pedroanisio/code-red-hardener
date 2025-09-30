"""Main SSH hardening implementation."""

import json
import os
import pwd
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import structlog

    HAS_STRUCTLOG = True
    logger = structlog.get_logger()
    
    def log_info(message: str, **kwargs) -> None:
        logger.info(message, **kwargs)
    
    def log_warning(message: str, **kwargs) -> None:
        logger.warning(message, **kwargs)
    
    def log_error(message: str, **kwargs) -> None:
        logger.error(message, **kwargs)
        
except ImportError:
    import logging

    HAS_STRUCTLOG = False
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)
    
    def log_info(message: str, **kwargs) -> None:
        if kwargs:
            message = f"{message} - " + ", ".join(f"{k}={v}" for k, v in kwargs.items())
        logger.info(message)
    
    def log_warning(message: str, **kwargs) -> None:
        if kwargs:
            message = f"{message} - " + ", ".join(f"{k}={v}" for k, v in kwargs.items())
        logger.warning(message)
    
    def log_error(message: str, **kwargs) -> None:
        if kwargs:
            message = f"{message} - " + ", ".join(f"{k}={v}" for k, v in kwargs.items())
        logger.error(message)

from ssh_hardener.config import HardenerConfig
from ssh_hardener.exceptions import (
    ConfigurationError,
    HardenerError,
    RollbackError,
    ServiceControlError,
    ValidationError,
)
from ssh_hardener.system_info import SystemInfo
from ssh_hardener.types import FirewallType, InitSystem
from ssh_hardener.utils.command import CommandExecutor
from ssh_hardener.utils.file import FileManager
from ssh_hardener.utils.validation import Validator


class SSHHardener:
    """Main SSH hardening orchestrator."""

    def __init__(
        self, config: HardenerConfig, dry_run: bool = False, verbose: bool = False
    ) -> None:
        """Initialize SSH hardener.

        Args:
            config: Configuration object
            dry_run: If True, only simulate changes
            verbose: Enable verbose logging
        """
        self.config = config
        self.dry_run = dry_run
        self.verbose = verbose

        # Initialize components
        self.system = SystemInfo()
        self.executor = CommandExecutor(
            use_sudo=not self.system.is_root, dry_run=dry_run
        )
        self.file_manager = FileManager(config.backup.directory)
        self.validator = Validator()

        # State
        self.ssh_service_name: Optional[str] = None
        self.current_ssh_port = 22
        self.state_file = config.backup.directory / ".ssh_hardener_state.json"

    def preflight_checks(self) -> bool:
        """Run comprehensive preflight safety checks.

        Returns:
            True if all checks pass

        Raises:
            ConfigurationError: If configuration is invalid
            ValidationError: If validation fails
        """
        logger.info("Starting preflight checks")
        issues: List[str] = []
        warnings: List[str] = []

        # System requirements
        sys_issues = self.system.check_requirements()
        issues.extend(sys_issues)

        # Configuration validation
        config_issues = self.config.validate_config()
        issues.extend(config_issues)

        # Port validation
        try:
            self.validator.validate_port(self.config.ssh.port)
        except ValidationError as e:
            issues.append(str(e))

        if not self.validator.check_port_available(self.config.ssh.port):
            current_port = self._get_current_ssh_port()
            if self.config.ssh.port != current_port:
                issues.append(f"Port {self.config.ssh.port} is already in use")

        # User validation
        user_errors = self.validator.validate_users(self.config.ssh.admin_users)
        issues.extend(user_errors)

        # Check SSH keys for existing users
        users_with_keys = []
        for username in self.config.ssh.admin_users:
            if self.validator.validate_user_exists(username):
                if not self.validator.validate_ssh_keys(username):
                    warnings.append(f"User {username} has no valid SSH keys")
                else:
                    users_with_keys.append(username)

        # Ensure at least one user has keys
        if not users_with_keys and self.config.ssh.admin_users:
            if not self.config.ssh.password_authentication:
                issues.append("No admin users have SSH keys - will be locked out!")

        # Check connection info
        conn_info = self._get_connection_info()
        if (
            conn_info["is_ssh"]
            and conn_info["auth_method"] == "password"
            and not self.config.ssh.password_authentication
        ):
            issues.append("Currently using password auth - will be locked out!")

        # Display results
        if warnings and self.verbose:
            for warning in warnings:
                log_warning("preflight_warning", warning=warning)

        if issues:
            for issue in issues:
                log_error("preflight_issue", issue=issue)
            return False

        log_info("Preflight checks passed", warnings=len(warnings))
        return True

    def run(self) -> None:
        """Execute SSH hardening process.

        Raises:
            HardenerError: If hardening process fails
        """
        log_info(
            "Starting SSH hardening",
            port=self.config.ssh.port,
            users=self.config.ssh.admin_users,
        )

        try:
            # Run preflight checks
            if not self.preflight_checks():
                raise ConfigurationError("Preflight checks failed")

            # Save state
            self._save_state()

            # Execute hardening steps
            self._setup_admin_users()
            self._update_ssh_config()

            if self.config.security.enable_fail2ban:
                self._setup_fail2ban()

            if self.config.security.enable_firewall:
                self._setup_firewall()

            # Restart SSH service
            self._restart_ssh_service()

            # Test and commit
            if not self.dry_run:
                if not self._test_and_commit():
                    log_warning("Connection test failed, rolling back")
                    self.rollback()
                    return

            log_info("SSH hardening completed successfully")

        except KeyboardInterrupt:
            log_warning("Interrupted by user, rolling back")
            self.rollback()
            raise

        except Exception as e:
            log_error("Hardening failed", error=str(e))
            self.rollback()
            raise HardenerError(f"Hardening failed: {e}") from e

    def rollback(self) -> None:
        """Rollback all changes.

        Raises:
            RollbackError: If rollback fails
        """
        log_info("Rolling back changes")

        try:
            restored = self.file_manager.rollback_all()
            log_info("Files restored", count=len(restored))

            # Restart SSH with original config
            self._restart_ssh_service()

        except Exception as e:
            raise RollbackError(f"Rollback failed: {e}") from e

    def _setup_admin_users(self) -> None:
        """Create and configure admin users."""
        log_info("Setting up admin users")

        for username in self.config.ssh.admin_users:
            if self.validator.validate_user_exists(username):
                log_info("User exists", user=username)
                continue

            # Create user
            cmd = f"useradd -m -s /bin/bash {username}"
            result = self.executor.execute(cmd, needs_root=True, check=False)

            if result.success:
                log_info("User created", user=username)
            else:
                log_error("User creation failed", user=username, error=result.stderr)
                continue

            # Add to sudo/wheel group
            sudo_group = "sudo" if self.system.distro in ["debian", "ubuntu"] else "wheel"
            self.executor.execute(
                f"usermod -aG {sudo_group} {username}", needs_root=True
            )

            # Setup SSH directory
            user_info = pwd.getpwnam(username)
            ssh_dir = Path(user_info.pw_dir) / ".ssh"
            ssh_dir.mkdir(parents=True, exist_ok=True)

            auth_keys = ssh_dir / "authorized_keys"
            auth_keys.touch(exist_ok=True)

            # Set permissions
            self.executor.execute(
                f"chown -R {username}:{username} {ssh_dir}", needs_root=True
            )
            self.executor.execute(f"chmod 700 {ssh_dir}", needs_root=True)
            self.executor.execute(f"chmod 600 {auth_keys}", needs_root=True)

    def _update_ssh_config(self) -> None:
        """Update SSH configuration with security settings."""
        log_info("Updating SSH configuration")

        ssh_config = Path("/etc/ssh/sshd_config")
        ssh_config_d = Path("/etc/ssh/sshd_config.d")

        # Backup main config
        self.file_manager.backup_file(ssh_config)

        # Determine config file to modify
        config_file = ssh_config
        if ssh_config_d.exists():
            config_file = ssh_config_d / "99-hardening.conf"
            log_info("Using drop-in config", file=str(config_file))

        if config_file != ssh_config and config_file.exists():
            self.file_manager.backup_file(config_file)

        # Build settings
        settings: Dict[str, str] = {
            "Port": str(self.config.ssh.port),
            "PermitRootLogin": "yes" if self.config.ssh.permit_root_login else "no",
            "PasswordAuthentication": "yes"
            if self.config.ssh.password_authentication
            else "no",
            "PubkeyAuthentication": "yes"
            if self.config.ssh.pubkey_authentication
            else "no",
            "PermitEmptyPasswords": "no",
            "MaxAuthTries": str(self.config.ssh.max_auth_tries),
            "MaxSessions": str(self.config.ssh.max_sessions),
            "ClientAliveInterval": str(self.config.ssh.client_alive_interval),
            "ClientAliveCountMax": str(self.config.ssh.client_alive_count_max),
            "LoginGraceTime": str(self.config.ssh.login_grace_time),
            "X11Forwarding": "yes" if self.config.ssh.x11_forwarding else "no",
            "ChallengeResponseAuthentication": "no",
            "UsePAM": "yes",
        }

        if self.config.ssh.admin_users:
            settings["AllowUsers"] = " ".join(self.config.ssh.admin_users)

        # Write configuration
        self._write_ssh_config(config_file, settings)

        # Validate config
        self._validate_ssh_config()

    def _write_ssh_config(self, config_file: Path, settings: Dict[str, str]) -> None:
        """Write SSH configuration file.

        Args:
            config_file: Path to config file
            settings: Dictionary of settings to apply
        """
        content = [
            "# SSH Hardening Configuration",
            f"# Generated: {datetime.now().isoformat()}",
            "# DO NOT EDIT MANUALLY - Generated by ssh-hardener",
            "",
        ]

        for key, value in settings.items():
            content.append(f"{key} {value}")

        self.file_manager.write_file(config_file, "\n".join(content) + "\n")

    def _validate_ssh_config(self) -> None:
        """Validate SSH configuration syntax.

        Raises:
            ValidationError: If configuration is invalid
        """
        for sshd_cmd in ["sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd"]:
            if self.executor.check_command_available(sshd_cmd):
                result = self.executor.execute(
                    f"{sshd_cmd} -t", needs_root=True, check=False
                )
                if not result.success:
                    raise ValidationError(f"Invalid SSH config: {result.stderr}")
                log_info("SSH configuration validated")
                return

        log_warning("Cannot validate SSH config - sshd not found")

    def _setup_fail2ban(self) -> None:
        """Configure fail2ban for SSH protection."""
        log_info("Setting up fail2ban")

        # Install if needed
        if not self.executor.check_command_available("fail2ban-client"):
            self._install_package("fail2ban")

        jail_config = Path("/etc/fail2ban/jail.local")
        if jail_config.exists():
            self.file_manager.backup_file(jail_config)

        jail_content = f"""[DEFAULT]
bantime = {self.config.security.fail2ban_bantime}
findtime = {self.config.security.fail2ban_findtime}
maxretry = {self.config.security.fail2ban_maxretry}
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = {self.config.ssh.port}
filter = sshd
logpath = /var/log/auth.log /var/log/secure
maxretry = {self.config.security.fail2ban_maxretry}
"""

        self.file_manager.write_file(jail_config, jail_content)

        # Restart fail2ban
        self._control_service("fail2ban", "restart")
        self._control_service("fail2ban", "enable")

        log_info("Fail2ban configured")

    def _setup_firewall(self) -> None:
        """Configure firewall rules."""
        log_info("Setting up firewall")

        current_port = self._get_current_ssh_port()

        if self.system.firewall_type == FirewallType.UFW:
            self._setup_ufw(current_port)
        elif self.system.firewall_type == FirewallType.FIREWALLD:
            self._setup_firewalld(current_port)
        elif self.system.firewall_type == FirewallType.IPTABLES:
            self._setup_iptables(current_port)
        else:
            # Try to install appropriate firewall
            self._install_firewall()

    def _setup_ufw(self, current_port: int) -> None:
        """Configure UFW firewall."""
        commands = [
            "ufw default deny incoming",
            "ufw default allow outgoing",
            f"ufw allow {current_port}/tcp comment 'SSH-current'",
            f"ufw limit {self.config.ssh.port}/tcp comment 'SSH-hardened'",
        ]

        for cmd in commands:
            self.executor.execute(cmd, needs_root=True)

        # Enable UFW
        result = self.executor.execute("ufw status", needs_root=True, check=False)
        if "inactive" in result.stdout.lower():
            self.executor.execute("ufw --force enable", needs_root=True)
        else:
            self.executor.execute("ufw reload", needs_root=True)

    def _setup_firewalld(self, current_port: int) -> None:
        """Configure firewalld."""
        commands = [
            f"firewall-cmd --permanent --add-port={current_port}/tcp",
            f"firewall-cmd --permanent --add-port={self.config.ssh.port}/tcp",
            "firewall-cmd --reload",
        ]

        for cmd in commands:
            self.executor.execute(cmd, needs_root=True)

    def _setup_iptables(self, current_port: int) -> None:
        """Configure iptables."""
        commands = [
            f"iptables -A INPUT -p tcp --dport {current_port} -j ACCEPT",
            f"iptables -A INPUT -p tcp --dport {self.config.ssh.port} -j ACCEPT",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A INPUT -i lo -j ACCEPT",
        ]

        for cmd in commands:
            self.executor.execute(cmd, needs_root=True)

        # Try to save rules
        for save_cmd in [
            "iptables-save > /etc/iptables/rules.v4",
            "service iptables save",
            "/sbin/iptables-save > /etc/sysconfig/iptables",
        ]:
            result = self.executor.execute(save_cmd, needs_root=True, check=False)
            if result.success:
                break

    def _install_firewall(self) -> None:
        """Install appropriate firewall tool."""
        if self.system.distro in ["centos", "rhel", "fedora", "rocky", "almalinux"]:
            if self._install_package("firewalld"):
                self._control_service("firewalld", "start")
                self._control_service("firewalld", "enable")
                self.system.firewall_type = FirewallType.FIREWALLD
        else:
            if self._install_package("ufw"):
                self.system.firewall_type = FirewallType.UFW

    def _install_package(self, package: str) -> bool:
        """Install package using system package manager.

        Args:
            package: Package name to install

        Returns:
            True if installation succeeded
        """
        cmd = self.system.get_package_install_command(package)
        if not cmd:
            log_error("No package manager available")
            return False

        result = self.executor.execute(cmd, needs_root=True, check=False, timeout=300)
        return result.success

    def _control_service(self, service: str, action: str) -> None:
        """Control system service.

        Args:
            service: Service name
            action: Action to perform (start, stop, restart, enable)

        Raises:
            ServiceControlError: If service control fails
        """
        cmd = self.system.get_service_command(service, action)
        if not cmd:
            raise ServiceControlError(f"Cannot control service on {self.system.init_system}")

        result = self.executor.execute(cmd, needs_root=True, check=False)
        if not result.success:
            raise ServiceControlError(f"Service {action} failed: {result.stderr}")

    def _restart_ssh_service(self) -> None:
        """Restart SSH service."""
        service_name = self._get_ssh_service_name()
        if not service_name:
            log_warning("SSH service not found")
            return

        self._control_service(service_name, "restart")
        time.sleep(2)  # Give service time to start

    def _get_ssh_service_name(self) -> Optional[str]:
        """Detect SSH service name.

        Returns:
            SSH service name or None if not found
        """
        if self.ssh_service_name:
            return self.ssh_service_name

        for name in ["sshd", "ssh", "openssh"]:
            cmd = self.system.get_service_command(name, "status")
            result = self.executor.execute(cmd, check=False)
            if result.success or "loaded" in result.stdout.lower():
                self.ssh_service_name = name
                return name

        return None

    def _get_current_ssh_port(self) -> int:
        """Get current SSH port from configuration.

        Returns:
            Current SSH port number
        """
        patterns = [
            "grep -E '^[[:space:]]*Port' /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}'",
            "grep -E '^Port' /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}'",
        ]

        for pattern in patterns:
            result = self.executor.execute(pattern, check=False)
            if result.success and result.stdout.strip().isdigit():
                return int(result.stdout.strip())

        return 22

    def _get_connection_info(self) -> Dict[str, str]:
        """Get current SSH connection information.

        Returns:
            Dictionary with connection details
        """
        return {
            "is_ssh": "SSH_CONNECTION" in os.environ or "SSH_CLIENT" in os.environ,
            "connection": os.environ.get("SSH_CONNECTION", ""),
            "auth_method": "unknown",
        }

    def _get_server_ip(self) -> str:
        """Get server's primary IP address.

        Returns:
            IP address string
        """
        methods = [
            "ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K\\S+'",
            "hostname -I 2>/dev/null | awk '{print $1}'",
        ]

        for method in methods:
            result = self.executor.execute(method, check=False)
            if result.success and result.stdout.strip():
                return result.stdout.strip()

        return "your-server-ip"

    def _test_and_commit(self) -> bool:
        """Test new configuration before committing.

        Returns:
            True if test succeeded
        """
        print("\n" + "=" * 60)
        print("⚠️  CRITICAL: CONNECTION TEST REQUIRED")
        print("=" * 60)

        server_ip = self._get_server_ip()
        test_user = self.config.ssh.admin_users[0] if self.config.ssh.admin_users else "admin"

        print(
            f"""
Before proceeding, you MUST test the new configuration:

1. Keep THIS terminal open
2. Open a NEW terminal window
3. Test SSH connection:
   ssh -p {self.config.ssh.port} {test_user}@{server_ip}

4. Verify you can:
   - Connect successfully
   - Run sudo commands

DO NOT close this terminal until verified!
"""
        )

        while True:
            response = input("\nConnection test result (success/failed/skip): ").lower()

            if response == "success":
                self._cleanup_old_port()
                if self.state_file.exists():
                    self.state_file.unlink()
                return True

            elif response == "failed":
                return False

            elif response == "skip":
                log_warning("Connection test skipped - RISKY!")
                return True

    def _cleanup_old_port(self) -> None:
        """Remove old SSH port from firewall if different."""
        current_port = self._get_current_ssh_port()
        if current_port == self.config.ssh.port:
            return

        if self.system.firewall_type == FirewallType.UFW:
            self.executor.execute(
                f"ufw delete allow {current_port}/tcp", needs_root=True, check=False
            )
        elif self.system.firewall_type == FirewallType.FIREWALLD:
            self.executor.execute(
                f"firewall-cmd --permanent --remove-port={current_port}/tcp",
                needs_root=True,
                check=False,
            )
            self.executor.execute("firewall-cmd --reload", needs_root=True, check=False)

    def _save_state(self) -> None:
        """Save current state for recovery."""
        state = {
            "original_port": self._get_current_ssh_port(),
            "new_port": self.config.ssh.port,
            "timestamp": datetime.now().isoformat(),
            "admin_users": self.config.ssh.admin_users,
        }

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)