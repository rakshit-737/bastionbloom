"""Connect risks only within the same file and service to avoid false chains."""

from collections import defaultdict

from bastionbloom.models import Finding
from bastionbloom.rules import RULES

CHAINS = {
    "COR001": {"DKR006", "DKR007"},
    "COR002": {"DKR005", "DKR002"},
    "COR003": {"DKR001", "DKR003"},
}


def correlate(findings: list[Finding]) -> list[Finding]:
    grouped = defaultdict(list)
    for finding in findings:
        if finding.service is not None:
            grouped[(finding.path, finding.service)].append(finding)
    chains = []
    for (path, service), group in grouped.items():
        available = {finding.rule.id for finding in group}
        for code, required in CHAINS.items():
            if not required.issubset(available):
                continue
            sources = [finding for finding in group if finding.rule.id in required]
            chains.append(Finding(
                RULES[code], path, min(finding.line for finding in sources),
                "Connected checks: " + " + ".join(sorted(required)),
                subject=f"service:{service}", service=service,
                related=sorted({finding.fingerprint for finding in sources}),
            ))
    return chains
