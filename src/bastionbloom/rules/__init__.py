"""Rule registry shared by detectors, reports, and the rule-list command."""

from bastionbloom.models import Rule, Severity


def _rule(code, category, severity, title, description, remediation):
    confidence = "medium" if code in {"SEC003", "SEC005", "DKR009", "ACT001", "ACT005"} else "high"
    return Rule(code, category, Severity(severity), title, description, remediation, confidence)


RULES = {
    rule.id: rule
    for rule in [
        _rule(
            "SEC001", "secrets", "critical", "Private key material",
            "A private-key header is present in a source file.",
            "Remove the key from source and history, rotate it, and use a secret store.",
        ),
        _rule(
            "SEC002", "secrets", "high", "GitHub access token",
            "A value matches a GitHub token format; validity is not checked online.",
            "Revoke the token, remove it from history, and use scoped runtime credentials.",
        ),
        _rule(
            "SEC003", "secrets", "medium", "AWS access key identifier",
            "An AWS access key ID may reveal an accidentally committed credential pair.",
            "Inspect the associated secret key and rotate the pair if exposed. Prefer IAM roles.",
        ),
        _rule(
            "SEC004", "secrets", "high", "Slack access token",
            "A value matches a Slack token format; validity is not checked online.",
            "Revoke the token and inject a replacement from a secret store.",
        ),
        _rule(
            "SEC005", "secrets", "high", "Hardcoded credential",
            "A credential-like assignment contains a literal value rather than a reference.",
            "Move the value to a secret store or runtime environment and rotate exposed values.",
        ),
        _rule(
            "DKR001", "docker", "high", "Privileged container",
            "Privileged mode grants a container extensive host capabilities.",
            "Disable privileged mode and grant only the capabilities the service needs.",
        ),
        _rule(
            "DKR002", "docker", "critical", "Docker socket mounted",
            "Docker daemon access can provide host control, even via a read-only socket mount.",
            "Remove the socket mount or use a tightly restricted socket proxy.",
        ),
        _rule(
            "DKR003", "docker", "high", "Sensitive host filesystem mounted",
            "A host root or sensitive system directory is bind-mounted into a container.",
            "Use a dedicated data directory with the minimum necessary read/write access.",
        ),
        _rule(
            "DKR004", "docker", "medium", "Host networking enabled",
            "Host networking removes the container's network namespace isolation.",
            "Use a dedicated bridge network and publish only required ports.",
        ),
        _rule(
            "DKR005", "docker", "medium", "Port published beyond loopback",
            "A service port is published to all interfaces or another non-loopback address.",
            "Bind local services to 127.0.0.1 or ::1 and restrict public access with a firewall.",
        ),
        _rule(
            "DKR006", "docker", "high", "Database port published beyond loopback",
            "A database service or well-known database port is published beyond loopback.",
            "Keep the database on an internal network or bind administrative access to loopback.",
        ),
        _rule(
            "DKR007", "docker", "high", "Database authentication weakened",
            "A database permits empty passwords, trust authentication, or a known weak password.",
            "Require strong authentication and inject credentials from a secret store.",
        ),
        _rule(
            "DKR008", "docker", "high", "Credential embedded in container environment",
            "A service environment variable contains a literal credential.",
            "Use Compose secrets or runtime credential injection instead of committed literals.",
        ),
        _rule(
            "DKR009", "docker", "medium", "Final Docker stage runs as root",
            "The final image explicitly selects root or never declares a non-root USER.",
            "Set a non-root USER in the final stage. Verify the base image's default user.",
        ),
        _rule(
            "DKR010", "docker", "low", "Mutable or dynamic container image reference",
            "An image uses latest, has no explicit tag/digest, or is supplied dynamically, "
            "so the scanner cannot verify what will run.",
            "Pin an approved version; use a sha256 image digest for reproducible deployments "
            "and validate any image supplied through a variable.",
        ),
        _rule(
            "DKR011", "docker", "medium", "Remote Dockerfile ADD",
            "ADD fetches a remote resource during the image build.",
            "Verify download checksums or COPY a verified local artifact.",
        ),
        _rule(
            "ACT001", "actions", "high", "Broad workflow token permissions",
            "A workflow or job grants write-all or write access to repository, identity, or "
            "deployment scopes.",
            "Use contents: read at workflow level and grant narrow job-level writes as needed.",
        ),
        _rule(
            "ACT002", "actions", "medium", "Action not pinned to a commit",
            "A remote action uses a mutable tag, branch, or unpinned container image.",
            "Pin remote actions to a full 40-character commit SHA or containers to sha256 digests.",
        ),
        _rule(
            "ACT003", "actions", "high", "Untrusted expression interpolated into shell",
            "Attacker-controlled event data is interpolated directly into a run script.",
            "Pass event data through an environment variable and quote it in the shell script.",
        ),
        _rule(
            "ACT004", "actions", "critical", "Untrusted checkout in pull_request_target",
            "A privileged pull_request_target workflow checks out pull-request-controlled code.",
            "Use pull_request for untrusted builds; isolate privileged metadata-only operations.",
        ),
        _rule(
            "ACT005", "actions", "high", "Self-hosted runner handles pull requests",
            "Pull-request workflows can run untrusted code on a persistent self-hosted runner.",
            "Use isolated ephemeral runners for pull requests; protect privileged runner groups.",
        ),
        _rule(
            "COR001", "correlation", "critical", "Exposed database with unsafe authentication",
            "The same Compose service publishes a database and weakens its authentication.",
            "Restrict network exposure, enforce strong authentication, and rotate credentials.",
        ),
        _rule(
            "COR002", "correlation", "critical", "Exposed service can control Docker",
            "The same service publishes a non-loopback port and mounts the Docker socket.",
            "Remove daemon access and restrict the service's published ports.",
        ),
        _rule(
            "COR003", "correlation", "critical", "Privileged service mounts sensitive host paths",
            "The same service combines privileged execution with access to sensitive host files.",
            "Remove privileged mode and sensitive bind mounts; isolate the required workload.",
        ),
    ]
}
