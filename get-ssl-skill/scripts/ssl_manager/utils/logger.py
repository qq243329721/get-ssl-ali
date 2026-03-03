"""Structured logging utility."""

from __future__ import annotations

import sys
from datetime import datetime


class Logger:
    """Simple structured logger with step tracking."""

    def __init__(self, verbose: bool = False):
        self._verbose = verbose
        self._step = 0
        self._total_steps = 0

    def set_total_steps(self, total: int) -> None:
        """Set total step count for progress display."""
        self._total_steps = total
        self._step = 0

    def step(self, msg: str) -> None:
        """Log a numbered step."""
        self._step += 1
        prefix = f"[{self._step}/{self._total_steps}]" if self._total_steps else f"[{self._step}]"
        self._print(f"{prefix} {msg}")

    def info(self, msg: str) -> None:
        """Log info message."""
        self._print(f"[INFO] {msg}")

    def success(self, msg: str) -> None:
        """Log success message."""
        self._print(f"[OK] {msg}")

    def warn(self, msg: str) -> None:
        """Log warning message."""
        self._print(f"[WARN] {msg}", file=sys.stderr)

    def error(self, msg: str) -> None:
        """Log error message."""
        self._print(f"[ERROR] {msg}", file=sys.stderr)

    def debug(self, msg: str) -> None:
        """Log debug message (only in verbose mode)."""
        if self._verbose:
            self._print(f"[DEBUG] {msg}")

    def _print(self, msg: str, file=None) -> None:
        """Print with timestamp."""
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{ts} {msg}", file=file or sys.stdout, flush=True)


# Module-level singleton
log = Logger()
