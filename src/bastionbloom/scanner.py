"""Bounded local filesystem scanning with ignore rules and symlink avoidance."""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from pathspec import GitIgnoreSpec

from bastionbloom.correlation import correlate
from bastionbloom.models import ScanResult
from bastionbloom.rules import RULES
from bastionbloom.rules.actions import scan_actions
from bastionbloom.rules.docker import scan_compose, scan_dockerfile
from bastionbloom.rules.secrets import scan_secrets
from bastionbloom.yaml_support import load_document

SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", "dist", "build",
}
DEFAULT_EXCLUDES = ("security-report.*", "bastionbloom-baseline.json", "*.sarif")


@dataclass(frozen=True)
class ScanOptions:
    max_file_bytes: int = 1024 * 1024
    respect_gitignore: bool = True
    exclude: tuple[str, ...] = ()
    exclude_rules: frozenset[str] = frozenset()
    show_full_path: bool = False


def _read_text_with_reason(path: Path, limit: int) -> tuple[str | None, str | None]:
    # O_NONBLOCK prevents accidentally opening a FIFO from hanging the scan;
    # O_NOFOLLOW protects against a final-component symlink swap on Linux.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if path.is_symlink():
        return None, "symlink"
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            return None, "special" if not stat.S_ISREG(metadata.st_mode) else "oversized"
        content = handle.read(limit + 1)
    if len(content) > limit or b"\0" in content:
        return None, "oversized" if len(content) > limit else "binary"
    try:
        return content.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, "non-utf8"


def _read_text(path: Path, limit: int) -> str | None:
    """Read a bounded UTF-8 text file, retaining the old small helper API."""
    text, _ = _read_text_with_reason(path, limit)
    return text


def _display_target(root: Path, show_full_path: bool) -> str:
    if show_full_path:
        return str(root)
    try:
        return root.relative_to(Path.cwd().resolve()).as_posix() or "."
    except ValueError:
        return root.name or "."


def scan(target: Path | str, options: ScanOptions | None = None) -> ScanResult:
    options = options or ScanOptions()
    root = Path(target).resolve()
    if not root.is_dir():
        raise ValueError("Scan target must be an existing directory")
    if options.max_file_bytes < 1:
        raise ValueError("File size limit must be positive")
    if options.exclude_rules - RULES.keys():
        raise ValueError("Unknown rule ID in exclusions")
    result = ScanResult(_display_target(root, options.show_full_path))
    started = time.perf_counter()

    def ignore_file(path: Path) -> list[str]:
        if not path.exists() or path.is_symlink():
            return []
        try:
            text, _ = _read_text_with_reason(path, options.max_file_bytes)
            if text is None:
                raise ValueError("Unreadable ignore file")
            return text.splitlines()
        except (OSError, ValueError):
            result.warnings.append(f"{path.relative_to(root)}: ignore file could not be read")
            return []

    overrides = GitIgnoreSpec.from_lines([
        *DEFAULT_EXCLUDES, *ignore_file(root / ".bastionbloomignore"), *options.exclude,
    ])
    specifications: dict[Path, list[tuple[Path, GitIgnoreSpec]]] = {}

    def ignored(path: Path, specs, directory=False):
        suffix = "/" if directory else ""
        ignore = False
        for base, specification in specs:
            decision = specification.check_file(path.relative_to(base).as_posix() + suffix)
            if decision.include is not None:
                ignore = decision.include
        override = overrides.check_file(path.relative_to(root).as_posix() + suffix)
        return override.include if override.include is not None else ignore

    def walk_error(error):
        result.warnings.append("A directory could not be read; scan coverage is incomplete")

    for directory, directories, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        current = Path(directory)
        specs = list(specifications.get(current.parent, []))
        if options.respect_gitignore:
            lines = ignore_file(current / ".gitignore")
            if lines:
                specs.append((current, GitIgnoreSpec.from_lines(lines)))
        specifications[current] = specs
        directories[:] = sorted(
            name for name in directories
            if name not in SKIP_DIRECTORIES
            and not (current / name).is_symlink()
            and not ignored(current / name, specs, directory=True)
        )
        for filename in sorted(filenames):
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if filename in {".gitignore", ".bastionbloomignore"} or ignored(path, specs):
                result.skipped_files += 1
                continue
            try:
                text, reason = _read_text_with_reason(path, options.max_file_bytes)
            except OSError:
                result.warnings.append(f"{relative}: file could not be read")
                result.skipped_files += 1
                continue
            if text is None:
                result.skipped_files += 1
                if reason in {"oversized", "non-utf8"}:
                    result.coverage_gaps.append(relative)
                    result.warnings.append(
                        f"{relative}: {reason} file was skipped; scan coverage is incomplete"
                    )
                continue
            result.scanned_files += 1
            result.findings.extend(scan_secrets(relative, text))
            lower_name = filename.lower()
            is_compose = lower_name.endswith((".yml", ".yaml")) and (
                lower_name.startswith(("compose.", "docker-compose."))
            )
            is_workflow = (
                ".github/workflows/" in relative and lower_name.endswith((".yml", ".yaml"))
            )
            try:
                if is_compose:
                    result.findings.extend(scan_compose(relative, load_document(text)))
                elif is_workflow:
                    result.findings.extend(scan_actions(relative, load_document(text)))
                elif lower_name == "dockerfile" or lower_name.startswith("dockerfile."):
                    result.findings.extend(scan_dockerfile(relative, text))
            except (yaml.YAMLError, ValueError, TypeError, RecursionError):
                # Parser errors may include source snippets, so never print them.
                result.warnings.append(f"{relative}: configuration could not be fully parsed")
    result.findings = [
        finding for finding in result.findings if finding.rule.id not in options.exclude_rules
    ]
    result.findings.extend(correlate(result.findings))
    unique = {
        finding.fingerprint: finding for finding in result.findings
        if finding.rule.id not in options.exclude_rules
    }
    result.findings = sorted(
        unique.values(), key=lambda f: (f.rule.severity.rank, f.path, f.line, f.rule.id)
    )
    result.duration_seconds = time.perf_counter() - started
    return result
