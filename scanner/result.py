"""Core result data structures for the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Sequence, Tuple

from .severity import Severity

SEVERITY_ORDER: Sequence[Severity] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


@dataclass
class Finding:
    """Capture a single rule evaluation result."""

    id: str
    title: str
    resource: str
    path: str
    severity: Severity
    rule: str
    recommendation: str

    def to_dict(self) -> Dict[str, str]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class Summary:
    """Aggregate finding counts by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def increment(self, severity: Severity) -> None:
        attr = severity.value.lower()
        setattr(self, attr, getattr(self, attr) + 1)

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

    def as_rows(self) -> List[Tuple[str, int]]:
        """Return severity/count pairs ordered for reporting."""

        return [(severity.value, getattr(self, severity.value.lower())) for severity in SEVERITY_ORDER]

    @property
    def total(self) -> int:
        return sum(getattr(self, severity.value.lower()) for severity in SEVERITY_ORDER)


@dataclass
class ScanResult:
    """Bundle scan summary and findings list."""

    summary: Summary = field(default_factory=Summary)
    findings: List[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.summary.critical == 0 and self.summary.high == 0 and self.summary.medium == 0

    def add_finding(self, finding: Finding) -> None:
        self.summary.increment(finding.severity)
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, object]:
        return {
            "summary": self.summary.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "passed": self.passed,
        }

    def exit_code(self) -> int:
        if self.summary.critical > 0 or self.summary.high > 0:
            return 2
        if self.summary.medium > 0:
            return 1
        return 0

    def top_findings(self, limit: int = 5) -> List[Finding]:
        """Return findings ordered by severity ranking."""

        severity_rank = {severity: idx for idx, severity in enumerate(SEVERITY_ORDER)}
        ordered = sorted(
            self.findings,
            key=lambda finding: (severity_rank[finding.severity], finding.id),
        )
        return ordered[:limit]


def format_summary_table(result: ScanResult, max_findings: int = 5) -> str:
    """Create a human-readable summary table for console output."""

    lines: List[str] = []
    lines.append("Scan Summary")
    lines.append("=" * 40)
    header = f"{'Severity':<10} | {'Count':>5}"
    lines.append(header)
    lines.append("-" * len(header))
    for severity, count in result.summary.as_rows():
        lines.append(f"{severity:<10} | {count:>5}")
    lines.append("-" * len(header))
    status = "PASS" if result.passed else "FAIL"
    lines.append(f"Status    : {status}")
    lines.append(f"Findings  : {result.summary.total}")

    findings = result.top_findings(max_findings)
    if findings:
        lines.append("")
        lines.append("Top Findings")
        lines.append("-" * 40)
        for finding in findings:
            lines.append(
                f"[{finding.severity.value}] {finding.id} {finding.title} ({finding.rule}) -> {finding.resource}"
            )
            lines.append(f"  Location: {finding.path}")
    return "\n".join(lines)
