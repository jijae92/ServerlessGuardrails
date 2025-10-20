"""Severity definitions for scanner findings."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Enumerate the supported severity levels for findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def exit_priority(self) -> int:
        """Return an integer ranking to drive exit code decisions."""

        ordering = {
            Severity.CRITICAL: 3,
            Severity.HIGH: 2,
            Severity.MEDIUM: 1,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        return ordering[self]
