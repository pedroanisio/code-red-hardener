"""Tests for system info module."""

import pytest
from ssh_hardener.system_info import SystemInfo
from ssh_hardener.types import PackageManager, InitSystem


def test_system_info_initialization():
    """Test system info detection."""
    system = SystemInfo()
    
    assert isinstance(system.distro, str)
    assert isinstance(system.package_manager, PackageManager)
    assert isinstance(system.init_system, InitSystem)
    assert isinstance(system.is_root, bool)
    assert isinstance(system.has_sudo, bool)


def test_check_requirements():
    """Test requirements checking."""
    system = SystemInfo()
    issues = system.check_requirements()
    
    assert isinstance(issues, list)
    # All items should be strings
    for issue in issues:
        assert isinstance(issue, str)


def test_to_dict():
    """Test conversion to dictionary."""
    system = SystemInfo()
    data = system.to_dict()
    
    assert isinstance(data, dict)
    assert "distro" in data
    assert "package_manager" in data
    assert "init_system" in data
    assert "is_root" in data
    assert "has_sudo" in data