"""Shared, serializable scan results. Evidence must never contain secret values."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from bastionbloom import __version__


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    remediation: str
    confidence: str = "high"


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    evidence: str
    subject: str = ""
    service: str | None = None
    related: list[str] = field(default_factory=list)
    is_new: bool = True

    @property
    def fingerprint(self) -> str:
        # Subjects encode identities rather than line numbers so moving code does
        # not automatically re-open findings. Raw secrets are never used here.
        identity = self.subject or f"line:{self.line}"
        payload = f"{self.rule.id}\0{self.path}\0{identity}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "category": self.rule.category,
            "severity": self.rule.severity.value,
            "confidence": self.rule.confidence,
            "title": self.rule.title,
            "description": self.rule.description,
            "remediation": self.rule.remediation,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "service": self.service,
            "fingerprint": self.fingerprint,
            "related": self.related,
            "is_new": self.is_new,
        }


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    duration_seconds: float = 0
    baseline_applied: bool = False
    resolved_count: int = 0
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def new_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.is_new]

    def fails_threshold(self, severity: Severity) -> bool:
        return any(f.rule.severity.rank <= severity.rank for f in self.new_findings)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "tool": {"name": "bastionbloom", "version": __version__},
            "target": self.target,
            "generated_at": self.generated_at,
            "summary": {
                "scanned_files": self.scanned_files,
                "skipped_files": self.skipped_files,
                "duration_seconds": round(self.duration_seconds, 3),
                "findings": len(self.findings),
                "new_findings": len(self.new_findings),
                "resolved_findings": self.resolved_count,
                "baseline_applied": self.baseline_applied,
                "complete": not self.warnings,
                "by_severity": {
                    s.value: sum(f.rule.severity == s for f in self.findings) for s in Severity
                },
            },
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.findings],
        }
