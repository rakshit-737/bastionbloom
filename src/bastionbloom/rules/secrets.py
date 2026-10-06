"""Offline pattern-based secret detection; no raw values escape this module."""

import hashlib
import re

from bastionbloom.models import Finding
from bastionbloom.rules import RULES

PATTERNS = [
    ("SEC001", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("SEC002", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b"
    )),
    ("SEC003", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("SEC004", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,200}\b")),
]
CREDENTIAL_NAME = re.compile(
    r"(?:password|passwd|(?:^|_)pwd(?:$|_)|api_?key|access_token|auth_token|client_secret|secret_key)",
    re.IGNORECASE,
)
ASSIGNMENT = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)[\"']?\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,#;\r\n}\]]+)"
)


def is_literal_credential(name: str, value: object) -> bool:
    if not CREDENTIAL_NAME.search(name) or name.lower().endswith(("_file", "_path")):
        return False
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip().strip("\"'")
    if not text or text.lower() in {"null", "none", "true", "false", "redacted"}:
        return False
    if text.startswith(("$", "<", "os.", "process.", "secrets.", "getenv(", "environ[")):
        return False
    if text.lower().startswith(("your_", "your-", "replace_", "replace-")):
        return False
    return True


def scan_secrets(path: str, text: str) -> list[Finding]:
    findings = []
    covered: list[tuple[int, int]] = []
    for code, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value_hash = hashlib.sha256(match.group().encode()).hexdigest()
            findings.append(Finding(
                RULES[code], path, text.count("\n", 0, match.start()) + 1,
                "Matched credential material: [REDACTED]", subject=value_hash,
            ))
            covered.append(match.span())
    for match in ASSIGNMENT.finditer(text):
        name, value = match.group("name", "value")
        if not is_literal_credential(name, value):
            continue
        start, end = match.span("value")
        if any(start <= a and b <= end for a, b in covered):
            continue
        value_hash = hashlib.sha256(value.strip("\"'").encode()).hexdigest()
        findings.append(Finding(
            RULES["SEC005"], path, text.count("\n", 0, match.start()) + 1,
            f"{name} = [REDACTED]", subject=f"{name}:{value_hash}",
        ))
    return findings
