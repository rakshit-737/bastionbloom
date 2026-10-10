"""Verify scan coverage, file boundaries, ignore precedence, and error privacy."""

import json
import os

import pytest

from bastionbloom.scanner import ScanOptions, scan


def test_external_symlinks_binary_large_files_and_fifo_are_skipped(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text('password="local-test-only-secret"')
    (root / "link.txt").symlink_to(outside)
    (root / "directory-link").symlink_to(tmp_path, target_is_directory=True)
    (root / "binary.bin").write_bytes(b"\0password=hidden")
    (root / "large.txt").write_text("x" * 300)
    (root / "normal.txt").write_text("nothing sensitive")
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "named-pipe")
    result = scan(root, ScanOptions(max_file_bytes=200))
    assert result.findings == []
    assert result.scanned_files == 1
    assert result.skipped_files >= 3
    assert any("large.txt" in warning for warning in result.warnings)
    assert result.to_dict()["summary"]["complete"] is False


def test_nested_gitignore_and_explicit_reinclusion(tmp_path):
    (tmp_path / ".gitignore").write_text("*.env\n")
    (tmp_path / ".bastionbloomignore").write_text("!keep.env\n")
    (tmp_path / "keep.env").write_text("API_KEY=local-test-value-keep")
    (tmp_path / "drop.env").write_text("API_KEY=local-test-value-drop")
    nested = tmp_path / "service"
    nested.mkdir()
    (nested / ".gitignore").write_text("config.txt\n")
    (nested / "config.txt").write_text("API_KEY=local-test-value-nested")
    result = scan(tmp_path)
    assert {f.path for f in result.findings} == {"keep.env"}
    included = scan(tmp_path, ScanOptions(respect_gitignore=False))
    assert {f.path for f in included.findings} == {"keep.env", "drop.env", "service/config.txt"}


def test_extra_excludes_and_builtin_dependency_pruning(tmp_path):
    dependencies = tmp_path / "node_modules"
    dependencies.mkdir()
    (dependencies / "config.txt").write_text("API_KEY=local-test-dependency-value")
    (tmp_path / "config.txt").write_text("API_KEY=local-test-project-value")
    result = scan(tmp_path, ScanOptions(exclude=("config.txt",)))
    assert result.findings == []
    assert result.scanned_files == 0


def test_generated_report_formats_are_not_scanned_as_source(tmp_path):
    (tmp_path / "results.sarif").write_text('password: "local-test-sarif-report-value"')
    result = scan(tmp_path)
    assert result.findings == []
    assert result.scanned_files == 0


def test_malformed_yaml_keeps_secret_findings_but_redacts_parse_errors(tmp_path):
    sensitive = "local-test-private-value"
    (tmp_path / "compose.yml").write_text(f'password: "{sensitive}"\nservices: [broken')
    result = scan(tmp_path)
    assert result.warnings
    assert "SEC005" in {finding.rule.id for finding in result.findings}
    assert result.to_dict()["summary"]["complete"] is False
    assert sensitive not in json.dumps(result.to_dict())


def test_yaml_alias_cycles_do_not_crash_scanner(tmp_path):
    (tmp_path / "compose.yaml").write_text("services: &cycle {service: *cycle}\n")
    result = scan(tmp_path)
    assert result.scanned_files == 1


def test_excluding_source_rule_removes_dependent_correlations(tmp_path):
    (tmp_path / "compose.yaml").write_text(
        'services:\n  db:\n    image: postgres:17\n    ports: ["5432:5432"]\n'
        '    environment: {POSTGRES_PASSWORD: ""}\n'
    )
    result = scan(tmp_path, ScanOptions(exclude_rules=frozenset({"DKR007"})))
    assert not {"DKR007", "COR001"} & {finding.rule.id for finding in result.findings}


def test_invalid_target_and_unknown_excluded_rule_fail_explicitly(tmp_path):
    with pytest.raises(ValueError, match="existing directory"):
        scan(tmp_path / "missing")
    with pytest.raises(ValueError, match="Unknown rule"):
        scan(tmp_path, ScanOptions(exclude_rules=frozenset({"TYPO001"})))
