"""Rule registry for scanner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from scanner.result import Finding, ScanResult


class Rule(Protocol):
    """Protocol implemented by all rule evaluators."""

    name: str

    def scan(self, context: "ScanContext", result: ScanResult) -> None:
        """Analyze the provided context and append findings to ``result``."""


@dataclass
class ScanContext:
    """Bundle inputs shared across rules."""

    template: dict
    source_paths: Iterable[str]
