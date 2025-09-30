"""Tests for system info module."""

import pytest
from ssh_hardener.system_info import SystemInfo
from ssh_hardener.types import PackageManager, InitSystem


def test_system_info_initialization():
    """Test system info detection."""
    system = SystemInfo()
    
    assert isinstance(system.distro, str)
    assert isinstance(system.package_manager, PackageManager)
    assert isins

=== FILE: README.md ===
# SSH Hardener - Universal Linux

Production-grade SSH hardening automation for all major Linux distributions.

## Features

- **Universal Linux Support**: Debian, Ubuntu, RHEL, CentOS, Fedora, Arch, SUSE
- **Smart Detection**: Auto-detects package managers, init systems, and firewall tools
- **Safety First**: Pre-flight checks, rollback capability, connection testing
- **Zero Dependencies**: Works without external packages (optional structured logging)
- **Production Ready**: Comprehensive error handling and logging

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ssh-hardener.git
cd ssh-hardener

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Optional: Install with enhanced logging
pip install -e ".[logging]"
```

## Configuration

Create `.env` file:

```bash
cp .env.example .env
# Edit .env with your settings
```

Or configure via `config.yaml`:

```yaml
ssh:
  port: 2222
  admin_users:
    - admin1
    - admin2

security:
  max_auth_tries: 3
  client_alive_interval: 300
  login_grace_time: 60

backup:
  directory: /root/security_backups
```

## Usage

### Basic Usage

```bash
# Run with configuration file
sudo ssh-hardener --config config.yaml

# Run with environment variables
export SSH_PORT=2222
export SSH_ADMIN_USERS="admin1,admin2"
sudo ssh-hardener

# Run with command-line arguments
sudo ssh-hardener --port 2222 --users admin1,admin2
```

### Advanced Options

```bash
# Dry run (check without applying)
sudo ssh-hardener --dry-run

# Skip specific steps
sudo ssh-hardener --skip-fail2ban --skip-firewall

# Custom backup directory
sudo ssh-hardener --backup-dir /custom/backup/path

# Verbose logging
sudo ssh-hardener --verbose

# Quiet mode
sudo ssh-hardener --quiet
```

## Safety Features

1. **Pre-flight Checks**: Validates system requirements before making changes
2. **Automatic Backups**: All configuration files backed up before modification
3. **Connection Testing**: Requires verification before committing changes
4. **Rollback Capability**: Automatic restoration on failure
5. **State Tracking**: Saves progress for recovery

## Requirements

- Python 3.8+
- Root access or sudo privileges
- Supported Linux distribution

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run linting
ruff check src/
mypy src/

# Format code
black src/
isort src/

# Run security checks
bandit -r src/
safety check

# Run tests
pytest

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

## Architecture

```
src/ssh_hardener/
├── __init__.py           # Package initialization
├── main.py               # CLI entry point
├── config.py             # Configuration management
├── types.py              # Type definitions
├── exceptions.py         # Custom exceptions
├── system_info.py        # System detection
├── hardener.py           # Main hardening logic
└── utils/
    ├── __init__.py
    ├── command.py        # Command execution
    ├── file.py           # File operations
    └── validation.py     # Input validation
```

## Security Considerations

- Never stores credentials in code
- Validates all user inputs
- Uses secure defaults
- Minimal privilege escalation
- Comprehensive logging for audit trails

## License

MIT License - See LICENSE file

## Contributing

1. Fork the repository
2. Create feature branch
3. Follow code standards (PEP 8, type hints, docstrings)
4. Add tests for new features
5. Run linting and tests
6. Submit pull request

## Support

- Issues: https://github.com/yourusername/ssh-hardener/issues
- Documentation: https://ssh-hardener.readthedocs.io