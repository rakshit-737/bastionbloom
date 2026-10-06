"""Verify realistic deployment risks, network boundaries, and stage inheritance."""

import json

import pytest

from bastionbloom.correlation import correlate
from bastionbloom.rules.docker import scan_compose, scan_dockerfile
from bastionbloom.yaml_support import load_document


def compose(text, path="compose.yaml"):
    return scan_compose(path, load_document(text))


def codes(findings):
    return {finding.rule.id for finding in findings}


def test_exposed_database_and_weak_auth_form_connected_risk():
    findings = compose("""services:
  database:
    image: postgres:17
    ports: ["5432:5432"]
    environment:
      POSTGRES_PASSWORD: ""
""")
    assert {"DKR005", "DKR006", "DKR007"} <= codes(findings)
    chains = correlate(findings)
    assert codes(chains) == {"COR001"}
    assert chains[0].service == "database"
    assert set(chains[0].related) <= {finding.fingerprint for finding in findings}
    assert next(f.line for f in findings if f.rule.id == "DKR007") == 6


@pytest.mark.parametrize("port", [
    '"127.0.0.1:5432:5432"',
    '"[::1]:5432:5432"',
    '{target: 5432, published: "5432", host_ip: "127.0.0.1"}',
    '{target: 5432, published: "5432", host_ip: "::1"}',
])
def test_loopback_publication_does_not_claim_public_exposure(port):
    findings = compose(f"services:\n  db:\n    image: postgres:17\n    ports: [{port}]\n")
    assert not {"DKR005", "DKR006"} & codes(findings)


def test_host_control_combinations_and_long_syntax():
    findings = compose("""services:
  management:
    image: nginx:1.27
    privileged: true
    ports:
      - target: 80
        published: "8080"
        host_ip: "0.0.0.0"
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        read_only: true
      - /:/host:ro
""")
    assert {"DKR001", "DKR002", "DKR003", "DKR005"} <= codes(findings)
    assert codes(correlate(findings)) == {"COR002", "COR003"}


def test_correlation_never_connects_different_services_or_files():
    public = compose('services:\n  db:\n    image: postgres:17\n    ports: ["5432:5432"]')
    other_service = compose('services:\n  other:\n    environment: {POSTGRES_PASSWORD: ""}')
    other_file = compose(
        'services:\n  db:\n    environment: {POSTGRES_PASSWORD: ""}', "compose.other.yml",
    )
    assert correlate(public + other_service + other_file) == []


def test_list_environment_values_are_redacted():
    sensitive = "local-test-only-credential"
    findings = compose(
        f"services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD={sensitive}\n"
    )
    assert "DKR008" in codes(findings)
    assert sensitive not in json.dumps([finding.to_dict() for finding in findings])


def test_runtime_secret_files_are_not_hardcoded_credentials():
    findings = compose("""services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/database
      ANOTHER_PASSWORD: ${RUNTIME_PASSWORD}
""")
    assert not {"DKR007", "DKR008"} & codes(findings)


def test_non_root_build_stage_does_not_hide_root_final_stage():
    text = "FROM python:3.12 AS build\nUSER 1000\nFROM python:3.12\nCOPY --from=build /x /x\n"
    findings = scan_dockerfile("Dockerfile", text)
    assert codes(findings) == {"DKR009"}
    assert findings[0].line == 3


def test_inherited_stage_user_and_explicit_final_user_are_respected():
    inherited = "FROM python:3.12 AS base\nUSER 1000\nFROM base AS final\n"
    explicit = "FROM python:3.12\nUSER 1000:1000\n"
    assert scan_dockerfile("Dockerfile", inherited) == []
    assert scan_dockerfile("Dockerfile", explicit) == []


def test_remote_add_latest_and_explicit_root_are_found():
    findings = scan_dockerfile(
        "Dockerfile", "FROM alpine:latest\nADD https://example.invalid/app /app\nUSER 0:1000\n",
    )
    assert codes(findings) == {"DKR009", "DKR010", "DKR011"}
