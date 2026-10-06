"""Test detection boundaries and that sensitive values never reach findings."""

import json

import pytest

from bastionbloom.rules.secrets import scan_secrets


@pytest.mark.parametrize("code,value", [
    ("SEC001", "-----BEGIN " + "PRIVATE KEY-----"),
    ("SEC002", "ghp_" + "A" * 36),
    ("SEC002", "github_pat_" + "B" * 60),
    ("SEC003", "AKIA" + "C" * 16),
    ("SEC004", "xoxb-" + "1234567890-" * 3),
])
def test_known_formats_are_detected_without_exposing_values(code, value):
    findings = scan_secrets("settings.txt", "# setup\n" + value)
    assert [finding.rule.id for finding in findings] == [code]
    assert findings[0].line == 2
    assert value not in json.dumps([finding.to_dict() for finding in findings])
    assert value not in repr(findings)


def test_literal_json_credential_has_redacted_evidence():
    sensitive = "local-test-only-value"
    findings = scan_secrets("config.json", json.dumps({"client_secret": sensitive}))
    assert len(findings) == 1
    assert findings[0].evidence == "client_secret = [REDACTED]"
    assert sensitive not in json.dumps(findings[0].to_dict())


@pytest.mark.parametrize("assignment", [
    'password = os.getenv("DB_PASSWORD")',
    "api_key = process.env.API_KEY",
    "password: ${DB_PASSWORD}",
    "client_secret: <runtime-secret>",
    "MYSQL_PASSWORD_FILE: /run/secrets/database",
    "password: null",
    "password = read_secret()",
    "WEAK_PASSWORDS = {\"\", \"password\"}",
])
def test_runtime_references_and_code_are_not_reported_as_literals(assignment):
    assert scan_secrets("settings.py", assignment) == []


def test_specific_token_does_not_duplicate_generic_assignment():
    value = "ghp_" + "D" * 36
    findings = scan_secrets(".env", f"ACCESS_TOKEN={value}")
    assert [finding.rule.id for finding in findings] == ["SEC002"]


def test_credential_fingerprint_survives_line_moves_but_detects_rotation():
    first = scan_secrets("config.yml", 'password: "local-test-value-1"')[0]
    moved = scan_secrets("config.yml", '\n\npassword: "local-test-value-1"')[0]
    rotated = scan_secrets("config.yml", 'password: "local-test-value-2"')[0]
    assert first.fingerprint == moved.fingerprint
    assert first.fingerprint != rotated.fingerprint
