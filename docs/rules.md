# Security rule catalog

Severity is the priority for review. Confidence describes the static indicator:
**high** means a recognizable format or explicit configuration; **medium**
means a heuristic or a condition that requires additional context. Neither
means that an incident or exploitation has been verified.

Run `bastionbloom rules --details` for remediation guidance from the rule registry.

## Credentials

| ID | Severity | Confidence | Detects |
| --- | --- | --- | --- |
| SEC001 | Critical | High | PEM/OpenSSH private-key headers, including encrypted private keys |
| SEC002 | High | High | GitHub classic and fine-grained token formats |
| SEC003 | Medium | Medium | AWS AKIA/ASIA access key identifiers |
| SEC004 | High | High | Recognizable Slack token formats |
| SEC005 | High | Medium | Credential-like names assigned literal values |

SEC005 recognizes password, passwd, pwd, API key, access/auth token, client
secret, and secret-key names. Environment/secret-store references, obvious
placeholder references, and `_FILE`/`_PATH` settings are skipped. Common source
code files require a quoted literal so function calls and variables are not
mistaken for credentials. This is pattern matching, not a language parser or
entropy detector. AWS key identifiers alone cannot authenticate.

No online validation is performed. Actual credential values and source lines
are not included in evidence. Rotation changes credential fingerprints, while
moving an identical value to another line within the same file does not.

## Docker

| ID | Severity | Confidence | Detects |
| --- | --- | --- | --- |
| DKR001 | High | High | Compose privileged mode |
| DKR002 | Critical | High | Bind mounts of the Docker daemon socket |
| DKR003 | High | High | Sensitive host/root filesystem bind mounts |
| DKR004 | Medium | High | Compose host networking |
| DKR005 | Medium | High | Published non-loopback service ports |
| DKR006 | High | High | Non-loopback publication of known database services/ports |
| DKR007 | High | High | Empty/known weak passwords and explicit trust/empty-password settings |
| DKR008 | High | High | Literal credentials in Compose environment settings |
| DKR009 | Medium | Medium | Final Dockerfile stage with no declared non-root user, or explicit root |
| DKR010 | Low | High | Image references without versions, using `latest`, or supplied dynamically |
| DKR011 | Medium | High | Dockerfile `ADD` of an HTTP(S) resource |

Short and long Compose port/volume syntax and mapping/list environment syntax
are supported. Loopback checks recognize IPv4 and bracketed IPv6. Read-only
Docker socket mounts remain dangerous because filesystem read-only flags do
not restrict Docker API operations over the socket.

Public publication is a configuration indicator: host firewalls are not
inspected. Variables and override-file combinations are not expanded. Base
images are not pulled; DKR009 honors declared/inherited Dockerfile stage users
but cannot establish the user supplied by an external base image. A fixed
version tag avoids DKR010; dynamic variables are reported because their final
image cannot be verified, and image digest verification is not performed.

## GitHub Actions

| ID | Severity | Confidence | Detects |
| --- | --- | --- | --- |
| ACT001 | High | Medium | `write-all` or explicit writes to repository, identity, or deployment scopes |
| ACT002 | Medium | High | Remote actions/reusable workflows without full commit pins; mutable container actions |
| ACT003 | High | High | Known attacker-influenced event fields interpolated directly into `run` scripts |
| ACT004 | Critical | High | `pull_request_target` plus an official checkout of PR-controlled head code |
| ACT005 | High | Medium | Pull-request jobs explicitly selecting self-hosted runner labels |

The checked write scopes are actions, attestations, checks, contents, deployments,
discussions, id-token, issues, models, packages, pages, pull-requests,
security-events, and statuses. Some workflows legitimately require these
permissions; review their scope and exposure. `security-events: write` is allowed
when the job uploads SARIF. `id-token: write` can mint cloud identity tokens and
should receive the same scrutiny as repository writes. `pages: write` and
`id-token: write` are allowed together for a job that uses
`actions/deploy-pages`. Local actions are exempt from commit-pinning checks.
Container actions require sha256 digests.

ACT003 recognizes common issue/PR titles, bodies, head refs/labels, comments,
reviews, discussions, and commit messages. Passing these fields through an
environment variable avoids direct expression injection; shell quoting is
still the workflow author's responsibility. Conditional job execution,
repository policies, custom checkout actions, dynamic runner expressions, and
downloaded reusable-workflow internals are not evaluated.

## Connected risks

| ID | Severity | Confidence | Required checks in the same file and service |
| --- | --- | --- | --- |
| COR001 | Critical | High | DKR006 + DKR007: exposed database with unsafe authentication |
| COR002 | Critical | High | DKR005 + DKR002: exposed service with Docker daemon access |
| COR003 | Critical | High | DKR001 + DKR003: privileged service with sensitive host mounts |

Correlations reference source finding fingerprints. Risks are never connected
across different services or files. Disabling a required source rule disables
the corresponding correlation. These are deployment risk combinations rather
than reconstructed exploit chains or proof of internet reachability.

## Coverage and errors

The working tree is inspected; Git history, remote repositories, CVE databases,
containers, and live network services are outside the scanner's scope.
Intentionally ignored files, pruned directories, and binary/oversized/non-UTF-8
files are outside coverage. Inaccessible files and unparseable structured
configurations produce an incomplete scan and exit code `2`. Secret matching
still runs on readable text even when structured parsing fails.
