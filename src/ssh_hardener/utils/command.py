"""Command execution utilities."""

import subprocess
from typing import Optional

from ssh_hardener.exceptions import CommandExecutionError
from ssh_hardener.types import CommandResult


class CommandExecutor:
    """Execute system commands with proper error handling."""

    def __init__(self, use_sudo: bool = False, dry_run: bool = False) -> None:
        """Initialize command executor.
        
        Args:
            use_sudo: Whether to prepend sudo to commands requiring root
            dry_run: If True, only log commands without executing
        """
        self.use_sudo = use_sudo
        self.dry_run = dry_run

    def execute(
        self,
        cmd: str,
        needs_root: bool = False,
        check: bool = True,
        timeout: int = 30,
    ) -> CommandResult:
        """Execute command with optional sudo.
        
        Args:
            cmd: Command to execute
            needs_root: Whether command requires root privileges
            check: Whether to raise exception on failure
            timeout: Command timeout in seconds
            
        Returns:
            CommandResult with execution details
            
        Raises:
            CommandExecutionError: If command fails and check=True
        """
        if needs_root and self.use_sudo:
            cmd = f"sudo {cmd}"

        if self.dry_run:
            return CommandResult(True, f"[DRY RUN] {cmd}", "", 0)

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            cmd_result = CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
            )

            if check and not cmd_result.success:
                raise CommandExecutionError(
                    f"Command failed: {cmd}\nError: {result.stderr}"
                )

            return cmd_result

        except subprocess.TimeoutExpired as e:
            error_msg = f"Command timed out after {timeout}s: {cmd}"
            if check:
                raise CommandExecutionError(error_msg) from e
            return CommandResult(False, "", error_msg, -1)

        except Exception as e:
            error_msg = f"Command execution failed: {cmd}\nError: {str(e)}"
            if check:
                raise CommandExecutionError(error_msg) from e
            return CommandResult(False, "", error_msg, -1)

    def check_command_available(self, command: str) -> bool:
        """Check if command is available on system."""
        result = self.execute(f"which {command}", check=False)
        return result.success