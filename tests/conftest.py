"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
from ssh_hardener.config import HardenerConfig


@pytest.fixture
def test_config() -> HardenerConfig:
    """Create test configuration."""
    config = HardenerConfig.from_env()
    config.ssh.port = 2222
    config.ssh.admin_users = ["testuser"]
    return config


@pytest.fixture
def temp_backup_dir(tmp_path: Path) -> Path:
    """Create temporary backup directory."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    return backup_dir