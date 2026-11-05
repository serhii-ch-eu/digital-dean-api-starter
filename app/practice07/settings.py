"""Local single-process lab profile; not a universal retention policy."""
from dataclasses import dataclass
from pathlib import Path
import os
from app.db.connection import PROJECT_ROOT


@dataclass(frozen=True)
class LogSettings:
    path: Path = PROJECT_ROOT / "var" / "logs" / "security.jsonl"
    max_bytes: int = 1_048_576
    backup_count: int = 3

    def __post_init__(self):
        if not isinstance(self.path, Path):
            raise TypeError("log path must be a local Path")
        if type(self.max_bytes) is not int or self.max_bytes < 1:
            raise ValueError("positive rotation limit required")
        if type(self.backup_count) is not int or not 1 <= self.backup_count <= 10:
            raise ValueError("backup count must be between 1 and 10")


def get_log_settings() -> LogSettings:
    """Trusted local configuration, never an HTTP parameter."""
    value = os.environ.get("DEAN_SECURITY_LOG_PATH")
    return LogSettings(path=Path(value)) if value else LogSettings()
