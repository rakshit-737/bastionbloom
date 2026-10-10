"""Static Docker Compose and Dockerfile checks; containers are never executed."""

from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import re

from bastionbloom.models import Finding
from bastionbloom.rules import RULES
from bastionbloom.rules.secrets import is_literal_credential
from bastionbloom.yaml_support import Document

DATABASE_IMAGES = {
    "postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb",
    "mssql", "mssql-server", "cockroach", "cockroachdb", "cassandra", "elasticsearch",
}
DATABASE_PORTS = {"5432", "3306", "6379", "27017", "1433", "9042", "9200", "26257"}
WEAK_PASSWORDS = {"", "password", "postgres", "mysql", "root", "admin", "changeme", "123456"}
SENSITIVE_PATHS = {"/", "/etc", "/proc", "/sys", "/dev", "/root", "/var/run", "/run"}


def _enabled(value: object) -> bool:
    return str(value).lower() in {"true", "yes", "1", "on"}


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _port(value: object) -> tuple[str, str] | None:
    if isinstance(value, dict):
        if "target" not in value or value.get("published") in (None, ""):
            return None
        return str(value.get("host_ip", "0.0.0.0")), str(value["target"])
    if not isinstance(value, (str, int)):
        return None
    parts = str(value).split("/")[0].rsplit(":", 2)
    if len(parts) == 3:
        return parts[0], parts[-1]
    return "0.0.0.0", parts[-1]


def _environment(value: object) -> dict:
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    if isinstance(value, list):
        result = {}
        for entry in value:
            if isinstance(entry, str) and "=" in entry:
                key, content = entry.split("=", 1)
                result[key] = content
        return result
    return {}


def _image_issue(image: str) -> str | None:
    if "$" in image:
        return "dynamic"
    if "@sha256:" in image:
        return None
    name = image.rsplit("/", 1)[-1]
    return "mutable" if ":" not in name or name.rsplit(":", 1)[-1] == "latest" else None


def _normalized_source(source: str) -> str:
    if not source.startswith("/"):
        return source
    return posixpath.normpath(source)


def _sensitive_source(source: str) -> bool:
    normalized = _normalized_source(source)
    if normalized == "/":
        return True
    return any(
        normalized == root or normalized.startswith(root.rstrip("/") + "/")
        for root in SENSITIVE_PATHS
        if root != "/"
    )


def _credential_identity(key: str, value: object) -> str:
    normalized = str(value).strip().strip("\"'")
    return f"{key}:{hashlib.sha256(normalized.encode()).hexdigest()}"


def scan_compose(path: str, document: Document) -> list[Finding]:
    findings = []
    services = document.data.get("services", {})
    if not isinstance(services, dict):
        raise ValueError("Invalid Compose services")
    for name, service in services.items():
        if not isinstance(name, str) or not isinstance(service, dict):
            raise ValueError("Invalid Compose service")

        def add(code: str, evidence: str, *keys, identity: str = "", service_name=name):
            findings.append(Finding(
                RULES[code], path, document.line("services", service_name, *keys), evidence,
                subject=f"service:{service_name}:{identity}", service=service_name,
            ))

        if _enabled(service.get("privileged", False)):
            add("DKR001", "privileged mode enabled", "privileged")
        if service.get("network_mode") == "host":
            add("DKR004", "network_mode: host", "network_mode")
        image = str(service.get("image", ""))
        image_name = image.rsplit("/", 1)[-1].split(":")[0].split("@")[0].lower()
        if image:
            image_issue = _image_issue(image)
            if image_issue == "dynamic":
                add("DKR010", "Image reference is dynamic and cannot be verified", "image")
            elif image_issue == "mutable":
                add("DKR010", "Image has no version or uses latest", "image")
        volumes = service.get("volumes") or []
        if not isinstance(volumes, list):
            raise ValueError("Invalid Compose volumes")
        for index, volume in enumerate(volumes):
            if isinstance(volume, str):
                source = volume.split(":", 1)[0].rstrip("/") or "/"
            elif isinstance(volume, dict) and volume.get("type") == "bind":
                source = str(volume.get("source", "")).rstrip("/") or "/"
            else:
                continue
            source = _normalized_source(source)
            if source in {"/var/run/docker.sock", "/run/docker.sock"}:
                add("DKR002", "Docker daemon socket is bind-mounted", "volumes", index)
            if _sensitive_source(source):
                add("DKR003", "Sensitive host directory is bind-mounted", "volumes", index)
        ports = service.get("ports") or []
        if not isinstance(ports, list):
            raise ValueError("Invalid Compose ports")
        for index, value in enumerate(ports):
            port = _port(value)
            if port is None or _loopback(port[0]):
                continue
            add("DKR005", "Published port is not restricted to loopback", "ports", index)
            if image_name in DATABASE_IMAGES or port[1] in DATABASE_PORTS:
                add("DKR006", "Database is published beyond loopback", "ports", index)
        env = _environment(service.get("environment"))
        for key, value in env.items():
            upper = key.upper()
            insecure = (
                upper in {"POSTGRES_HOST_AUTH_METHOD", "PGHOSTAUTHMETHOD"}
                and str(value).lower() == "trust"
            ) or (
                upper in {"MYSQL_ALLOW_EMPTY_PASSWORD", "ALLOW_EMPTY_PASSWORD"}
                and _enabled(value)
            ) or (
                "PASSWORD" in upper and value is not None
                and str(value).strip().lower() in WEAK_PASSWORDS
            )
            if insecure:
                add("DKR007", f"{key}: unsafe authentication setting [REDACTED]",
                    "environment", key, identity=key)
            if is_literal_credential(key, value):
                add(
                    "DKR008", f"{key} = [REDACTED]", "environment", key,
                    identity=_credential_identity(key, value),
                )
    return findings


def scan_dockerfile(path: str, text: str) -> list[Finding]:
    findings = []
    stages: dict[str, bool] = {}
    non_root = False
    last_from_line = 1
    current_stage = ""
    user_line = 0
    instructions = []
    pending = ""
    start = 1
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if not pending:
            start = number
        pending += line.rstrip("\\") + " "
        if line.endswith("\\"):
            continue
        instructions.append((start, pending.strip()))
        pending = ""
    for number, instruction in instructions:
        command, _, arguments = instruction.partition(" ")
        command = command.upper()
        if command == "FROM":
            if current_stage:
                stages[current_stage] = non_root
            tokens = [t for t in arguments.split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            non_root = stages.get(image.lower(), False)
            current_stage = tokens[-1].lower() if len(tokens) >= 3 else ""
            last_from_line, user_line = number, 0
            image_issue = _image_issue(image)
            if image.lower() not in stages and image_issue:
                findings.append(Finding(
                    RULES["DKR010"], path, number,
                    "Base image reference is dynamic and cannot be verified"
                    if image_issue == "dynamic" else "Base image is unversioned or uses latest",
                    subject=f"stage:{current_stage or number}",
                ))
        elif command == "USER":
            user = arguments.split(":", 1)[0].strip()
            non_root = bool(user) and user not in {"0", "root"} and "$" not in user
            user_line = number
        elif command == "ADD" and re.search(r"https?://", arguments, re.IGNORECASE):
            findings.append(Finding(
                RULES["DKR011"], path, number, "ADD downloads a remote resource",
            ))
    if any(command.upper().startswith("FROM ") for _, command in instructions) and not non_root:
        findings.append(Finding(
            RULES["DKR009"], path, user_line or last_from_line,
            "Final stage has no declared non-root USER (base-image defaults are not inspected)",
            subject="final-stage-user",
        ))
    return findings
