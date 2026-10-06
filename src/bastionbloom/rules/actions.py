"""GitHub Actions checks with no execution or remote action downloads."""

import re

from bastionbloom.models import Finding
from bastionbloom.rules import RULES
from bastionbloom.yaml_support import Document

COMMIT = re.compile(r"^[a-fA-F0-9]{40}$")
DIGEST = re.compile(r"@sha256:[a-fA-F0-9]{64}$")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
UNTRUSTED = re.compile(
    r"github\.head_ref|github\.event\.(?:issue|pull_request)\.(?:title|body|head\.(?:ref|label))"
    r"|github\.event\.(?:comment|review|discussion)\.(?:body|title)"
    r"|github\.event\.(?:head_commit\.message|commits)"
)
PR_HEAD = re.compile(r"github\.event\.pull_request\.(?:head\.|merge_commit_sha)")
WRITE_SCOPES = {"contents", "actions", "packages", "deployments", "security-events"}


def _unpinned(action: str) -> bool:
    if action.startswith("./"):
        return False
    if action.startswith("docker://"):
        return DIGEST.search(action) is None
    return "@" not in action or COMMIT.fullmatch(action.rsplit("@", 1)[-1]) is None


def scan_actions(path: str, document: Document) -> list[Finding]:
    findings = []
    trigger = document.data.get("on", {})
    if isinstance(trigger, str):
        events = {trigger}
    elif isinstance(trigger, (dict, list)):
        events = set(key for key in trigger if isinstance(key, str))
    else:
        events = set()
    privileged_pr = "pull_request_target" in events

    def add(code, evidence, *keys, identity=""):
        findings.append(Finding(
            RULES[code], path, document.line(*keys), evidence,
            subject=identity or "/".join(str(key) for key in keys),
        ))

    def permissions(value, *keys):
        if value == "write-all" or (
            isinstance(value, dict)
            and any(value.get(scope) == "write" for scope in WRITE_SCOPES)
        ):
            add("ACT001", "Token can write to sensitive repository scopes", *keys)

    permissions(document.data.get("permissions"), "permissions")
    jobs = document.data.get("jobs", {})
    if not isinstance(jobs, dict):
        raise ValueError("Invalid workflow jobs")
    for job_name, job in jobs.items():
        if not isinstance(job_name, str) or not isinstance(job, dict):
            raise ValueError("Invalid workflow job")
        prefix = ("jobs", job_name)
        permissions(job.get("permissions"), *prefix, "permissions")
        if isinstance(job.get("uses"), str) and _unpinned(job["uses"]):
            add("ACT002", "Reusable workflow reference is not commit-pinned", *prefix, "uses")
        runners = job.get("runs-on", [])
        if isinstance(runners, dict):
            runners = runners.get("labels", [])
        if isinstance(runners, str):
            runners = [runners]
        if isinstance(runners, list) and "self-hosted" in runners and (
            privileged_pr or "pull_request" in events
        ):
            add("ACT005", "Pull-request job selects a self-hosted runner", *prefix, "runs-on")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError("Invalid workflow steps")
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError("Invalid workflow step")
            step_path = (*prefix, "steps", index)
            action = step.get("uses", "")
            if isinstance(action, str) and action and _unpinned(action):
                add("ACT002", "Remote action reference is not commit/digest-pinned",
                    *step_path, "uses")
            script = step.get("run", "")
            if isinstance(script, str) and any(
                UNTRUSTED.search(match.group(1)) for match in EXPRESSION.finditer(script)
            ):
                add("ACT003", "Untrusted event expression appears directly in a shell script",
                    *step_path, "run")
            arguments = step.get("with", {})
            if not isinstance(arguments, dict):
                continue
            if privileged_pr and isinstance(action, str) and (
                action.lower().split("@", 1)[0] == "actions/checkout"
            ) and any(
                PR_HEAD.search(str(arguments.get(key, ""))) for key in ("ref", "repository")
            ):
                add("ACT004", "Privileged workflow checks out pull-request-controlled code",
                    *step_path, "with")
    return findings
