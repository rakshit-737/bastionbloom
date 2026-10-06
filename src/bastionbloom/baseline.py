"""Portable baselines with no source snippets or credential values."""

import json
import re
from pathlib import Path

from bastionbloom.models import ScanResult, Severity
from bastionbloom.output import write_text

FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")


def load_baseline(path: Path) -> dict[str, Severity]:
    try:
        with path.open("rb") as handle:
            content = handle.read(8 * 1024 * 1024 + 1)
        if len(content) > 8 * 1024 * 1024:
            raise ValueError("Oversized baseline")
        data = json.loads(content)
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
            raise ValueError("Invalid baseline schema")
        if data["schema_version"] != 1 or not isinstance(data.get("findings"), list):
            raise ValueError("Unsupported baseline")
        result = {}
        for row in data["findings"]:
            if not isinstance(row, dict) or not isinstance(row.get("fingerprint"), str):
                raise ValueError("Invalid baseline finding")
            if not FINGERPRINT.fullmatch(row["fingerprint"]):
                raise ValueError("Invalid fingerprint")
            result[row["fingerprint"]] = Severity(row["severity"])
        return result
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        # JSON errors may contain user-controlled content; keep errors generic.
        raise ValueError("Baseline could not be read or has an invalid schema") from error


def apply_baseline(result: ScanResult, baseline: dict[str, Severity]) -> None:
    result.baseline_applied = True
    for finding in result.findings:
        previous = baseline.get(finding.fingerprint)
        finding.is_new = previous is None or finding.rule.severity.rank < previous.rank
    present = {finding.fingerprint for finding in result.findings}
    # A partial scan cannot establish that old findings have really disappeared.
    result.resolved_count = len(baseline.keys() - present) if not result.warnings else 0


def save_baseline(result: ScanResult, path: Path) -> None:
    if result.warnings:
        raise ValueError("Cannot create a baseline from an incomplete scan")
    data = {
        "schema_version": 1,
        "generated_at": result.generated_at,
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule.id,
                "path": finding.path,
                "severity": finding.rule.severity.value,
            }
            for finding in result.findings
        ],
    }
    write_text(path, json.dumps(data, indent=2) + "\n")
