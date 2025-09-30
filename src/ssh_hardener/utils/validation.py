"""Input validation utilities."""

import pwd
import socket
from pathlib import Path
from typing import List

from ssh_hardener.exceptions import ValidationError


class Validator:
    """Validate inputs and system state."""

    @staticmethod
    def validate_port(port: int) -> None:
        """Validate port number.
        
        Args:
            port: Port number to validate
            
        Raises:
            ValidationError: If port is invalid
        """
        if not (1 <= port <= 65535):
            raise ValidationError(f"Invalid port: {port}. Must be between 1-65535")

    @staticmethod
    def validate_user_exists(username: str) -> bool:
        """Check if user exists on system.
        
        Args:
            username: Username to check
            
        Returns:
            True if user exists, False otherwise
        """
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            return False

    @staticmethod
    def validate_users(usernames: List[str]) -> List[str]:
        """Validate list of usernames.
        
        Args:
            usernames: List of usernames to validate
            
        Returns:
            List of validation error messages
        """
        errors: List[str] = []

        if not usernames:
            errors.append("No users specified")
            return errors

        for username in usernames:
            if not username or not username.strip():
                errors.append("Empty username found")
                continue

            if len(username) > 32:
                errors.append(f"Username too long: {username}")

            # Basic username validation
            if not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
                errors.append(f"Invalid username format: {username}")

        return errors

    @staticmethod
    def check_port_available(port: int) -> bool:
        """Check if port is available.
        
        Args:
            port: Port number to check
            
        Returns:
            True if port is available, False if in use
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("127.0.0.1", port))
                return result != 0
        except Exception:
            return False

    @staticmethod
    def validate_ssh_keys(username: str) -> bool:
        """Check if user has valid SSH keys.
        
        Args:
            username: Username to check
            
        Returns:
            True if user has valid SSH keys
        """
        try:
            user_info = pwd.getpwnam(username)
            auth_keys = Path(user_info.pw_dir) / ".ssh" / "authorized_keys"

            if not auth_keys.exists() or auth_keys.stat().st_size == 0:
                return False

            content = auth_keys.read_text()
            valid_key_types = ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2", "ssh-dss"]

            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    if any(line.startswith(kt) for kt in valid_key_types):
                        return True

            return False

        except (KeyError, OSError):
            return False

    @staticmethod
    def validate_path_writable(path: Path) -> bool:
        """Check if path is writable.
        
        Args:
            path: Path to check
            
        Returns:
            True if path is writable
        """
        try:
            if path.exists():
                return path.is_file() and os.access(path, os.W_OK)
            else:
                # Check parent directory
                parent = path.parent
                return parent.exists() and os.access(parent, os.W_OK)
        except Exception:
            return False