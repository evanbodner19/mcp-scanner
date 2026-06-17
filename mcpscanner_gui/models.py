"""Pure data models shared across the GUI layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

SEVERITY_ORDER: dict[str, int] = {
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "SAFE": 0,
    "UNKNOWN": 0,
}


class ScanType(str, Enum):
    REMOTE = "remote"
    FILES = "files"


@dataclass
class FindingView:
    analyzer: str
    severity: str
    summary: str
    threat_category: str


def highest_severity(findings: list[FindingView]) -> str:
    """Return the worst severity among findings, or ``"SAFE"`` if none."""
    worst = "SAFE"
    for f in findings:
        if SEVERITY_ORDER.get(f.severity.upper(), 0) > SEVERITY_ORDER[worst]:
            worst = f.severity.upper()
    return worst


@dataclass
class ScanItem:
    name: str
    status: str
    is_safe: bool
    findings: list[FindingView] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        return highest_severity(self.findings)


@dataclass
class ScanRequest:
    scan_type: ScanType
    target: str
    analyzers: list[str]
    keys: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None


@dataclass
class ScanOutcome:
    ok: bool
    items: list[ScanItem] = field(default_factory=list)
    error: str | None = None
