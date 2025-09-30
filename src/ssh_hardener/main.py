"""CLI entry point for SSH Hardener."""

import argparse
import sys
from pathlib import Path
from typing import NoReturn, Optional

from ssh_hardener import __version__
from ssh_hardener.config import HardenerConfig
from ssh_hardener.exceptions import HardenerError
from ssh_hardener.hardener import SSHHardener


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="SSH Hardener - Universal Linux SSH security automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with config file
  sudo ssh-hardener --config config.yaml

  # Run with CLI arguments
  sudo ssh-hardener --port 2222 --users admin1,admin2

  # Dry run
  sudo ssh-hardener --dry-run

Environment variables:
  SSH_PORT              - SSH port number
  SSH_ADMIN_USERS       - Comma-separated list of admin users
  ENABLE_FAIL2BAN       - Enable fail2ban (true/false)
  ENABLE_FIREWALL       - Enable firewall (true/false)

See README.md for full documentation.
        """,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file (YAML)",
    )

    parser.add_argument(
        "--port",
        type=int,
        help="SSH port number (overrides config/env)",
    )

    parser.add_argument(
        "--users",
        type=str,
        help="Comma-separated list of admin users (overrides config/env)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate changes without applying them",
    )

    parser.add_argument(
        "--skip-fail2ban",
        action="store_true",
        help="Skip fail2ban configuration",
    )

    parser.add_argument(
        "--skip-firewall",
        action="store_true",
        help="Skip firewall configuration",
    )

    parser.add_argument(
        "--backup-dir",
        type=Path,
        help="Custom backup directory",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )

    return parser.parse_args()


def load_config(args: argparse.Namespace) -> HardenerConfig:
    """Load configuration from various sources.

    Args:
        args: Parsed command-line arguments

    Returns:
        Configuration object
    """
    # Start with environment-based config
    config = HardenerConfig.from_env()

    # Apply CLI overrides
    if args.port:
        config.ssh.port = args.port

    if args.users:
        config.ssh.admin_users = [u.strip() for u in args.users.split(",")]

    if args.skip_fail2ban:
        config.security.enable_fail2ban = False

    if args.skip_firewall:
        config.security.enable_firewall = False

    if args.backup_dir:
        config.backup.directory = args.backup_dir

    return config


def main() -> NoReturn:
    """Main entry point for CLI.

    Raises:
        SystemExit: Always exits with appropriate code
    """
    args = parse_args()

    # Basic sanity checks
    if not sys.platform.startswith("linux"):
        print("Error: This tool only supports Linux systems", file=sys.stderr)
        sys.exit(1)

    try:
        # Load configuration
        config = load_config(args)

        # Display header
        if not args.quiet:
            print("╔══════════════════════════════════════╗")
            print("║  SSH HARDENER - UNIVERSAL LINUX     ║")
            print(f"║  Version {__version__:<26} ║")
            print("╚══════════════════════════════════════╝\n")

            if args.dry_run:
                print("🔍 DRY RUN MODE - No changes will be applied\n")

        # Create and run hardener
        hardener = SSHHardener(config, dry_run=args.dry_run, verbose=args.verbose)

        # Confirm before proceeding
        if not args.dry_run and not args.quiet:
            print(f"\n📋 Configuration Summary:")
            print(f"  SSH Port: {config.ssh.port}")
            print(f"  Admin Users: {', '.join(config.ssh.admin_users)}")
            print(f"  Fail2ban: {'Enabled' if config.security.enable_fail2ban else 'Disabled'}")
            print(f"  Firewall: {'Enabled' if config.security.enable_firewall else 'Disabled'}")
            print(f"  Backup Directory: {config.backup.directory}\n")

            response = input("Proceed with hardening? (yes/no): ")
            if response.lower() != "yes":
                print("Aborted.")
                sys.exit(0)

        # Run hardening
        hardener.run()

        if not args.quiet:
            print("\n╔══════════════════════════════════════╗")
            print("║      ✅ HARDENING COMPLETE!         ║")
            print("╚══════════════════════════════════════╝")
            print(f"\n📌 Important Reminders:")
            print(f"  • SSH now runs on port {config.ssh.port}")
            print(f"  • Only these users can SSH: {', '.join(config.ssh.admin_users)}")
            print(f"  • Password authentication: {'Enabled' if config.ssh.password_authentication else 'Disabled'}")
            print(f"  • Root login: {'Enabled' if config.ssh.permit_root_login else 'Disabled'}")
            print(f"  • Backups saved in: {config.backup.directory}\n")

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user", file=sys.stderr)
        sys.exit(130)

    except HardenerError as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()