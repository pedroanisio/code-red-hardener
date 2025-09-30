"""Tests for configuration module."""

import pytest
from ssh_hardener.config import HardenerConfig, SSHConfig
from ssh_hardener.exceptions import ValidationError


def test_ssh_config_defaults():
    """Test SSH config default values."""
    config = SSHConfig()
    assert config.port == 2222
    assert config.max_auth_tries == 3
    assert not config.password_authentication
    assert config.pubkey_authentication


def test_ssh_config_validation():
    """Test SSH config validation."""
    config = HardenerConfig.from_env()
    config.ssh.admin_users = []
    
    issues = config.validate_config()
    assert "No admin users configured" in issues


def test_parse_admin_users():
    """Test admin users parsing from string."""
    config = SSHConfig(admin_users="user1,user2, user3")
    assert config.admin_users == ["user1", "user2", "user3"]