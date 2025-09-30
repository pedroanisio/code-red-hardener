"""File management utilities."""

import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ssh_hardener.types import RollbackPoint


class FileManager:
    """Manage file operations with backup and rollback."""

    def __init__(self, backup_dir: Path) -> None:
        """Initialize file manager.
        
        Args:
            backup_dir: Directory for storing backups
        """
        self.backup_dir = backup_dir
        self.rollback_points: List[RollbackPoint] = []
        self._ensure_backup_dir()

    def _ensure_backup_dir(self) -> None:
        """Create backup directory if it doesn't exist."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def backup_file(self, filepath: Path) -> Optional[Path]:
        """Create timestamped backup of file.
        
        Args:
            filepath: Path to file to backup
            
        Returns:
            Path to backup file or None if source doesn't exist
        """
        if not filepath.exists():
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"{filepath.name}.{timestamp}"

        shutil.copy2(filepath, backup_path)

        self.rollback_points.append(
            RollbackPoint(
                original_path=str(filepath),
                backup_path=str(backup_path),
                timestamp=timestamp,
            )
        )

        return backup_path

    def restore_file(self, backup_path: Path, original_path: Path) -> None:
        """Restore file from backup.
        
        Args:
            backup_path: Path to backup file
            original_path: Path where file should be restored
        """
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        shutil.copy2(backup_path, original_path)

    def rollback_all(self) -> List[str]:
        """Rollback all changes using saved backup points.
        
        Returns:
            List of restored file paths
        """
        restored: List[str] = []

        for point in reversed(self.rollback_points):
            try:
                self.restore_file(
                    Path(point.backup_path),
                    Path(point.original_path),
                )
                restored.append(point.original_path)
            except Exception:
                continue

        return restored

    def read_file(self, filepath: Path) -> str:
        """Read file content.
        
        Args:
            filepath: Path to file
            
        Returns:
            File content as string
        """
        with open(filepath) as f:
            return f.read()

    def write_file(self, filepath: Path, content: str) -> None:
        """Write content to file.
        
        Args:
            filepath: Path to file
            content: Content to write
        """
        with open(filepath, "w") as f:
            f.write(content)

    def append_file(self, filepath: Path, content: str) -> None:
        """Append content to file.
        
        Args:
            filepath: Path to file
            content: Content to append
        """
        with open(filepath, "a") as f:
            f.write(content)