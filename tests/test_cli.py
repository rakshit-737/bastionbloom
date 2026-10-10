"""End-to-end checks for reports, baselines, credential privacy, and CI behavior."""

import json
import re

import pytest
from typer.testing import CliRunner

from bastionbloom.baseline import apply_baseline, load_baseline, save_baseline
from bastionbloom.cli import app
from bastionbloom.models import Severity
from bastionbloom.output import write_text
from bastionbloom.reports import render_html, render_sarif
from bastionbloom.scanner import scan

runner = CliRunner()


def test_json_output_is_clean_redacted_and_uses_threshold_exit_codes(tmp_path):
    sensitive = "local-test-cli-private-value"
    (tmp_path / "config.yml").write_text(f'password: "{sensitive}"')
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["summary"]["new_findings"] == 1
    assert sensitive not in result.output
    critical = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert critical.exit_code == 0
    details = runner.invoke(app, ["scan", str(tmp_path), "--details", "--fail-on", "none"])
    assert details.exit_code == 0
    assert "Fix:" in details.stdout
    assert sensitive not in details.output


def test_baseline_round_trip_new_and_resolved_findings(tmp_path):
    config = tmp_path / "config.yml"
    config.write_text('password: "local-test-baseline-value"')
    baseline = tmp_path / "accepted.json"
    created = runner.invoke(app, ["baseline", str(tmp_path), "-o", str(baseline)])
    assert created.exit_code == 0
    assert "local-test-baseline-value" not in baseline.read_text()
    existing = runner.invoke(app, [
        "scan", str(tmp_path), "--baseline", str(baseline), "--format", "json",
    ])
    assert existing.exit_code == 0
    report = json.loads(existing.stdout)
    assert report["summary"]["new_findings"] == 0
    assert report["findings"][0]["is_new"] is False
    config.write_text('password: "local-test-new-value"')
    changed = runner.invoke(app, [
        "scan", str(tmp_path), "--baseline", str(baseline), "--format", "json",
    ])
    assert changed.exit_code == 1
    assert json.loads(changed.stdout)["summary"]["resolved_findings"] == 1


def test_baseline_severity_escalation_reopens_finding(tmp_path):
    (tmp_path / "config.yml").write_text('password: "local-test-baseline-value"')
    result = scan(tmp_path)
    apply_baseline(result, {result.findings[0].fingerprint: Severity.low})
    assert result.findings[0].is_new
    assert result.fails_threshold(Severity.high)


def test_incomplete_scan_fails_even_with_threshold_disabled_and_cannot_baseline(tmp_path):
    (tmp_path / "compose.yaml").write_text("services: [broken")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "none", "-f", "json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["summary"]["complete"] is False
    path = tmp_path / "accepted.json"
    created = runner.invoke(app, ["baseline", str(tmp_path), "-o", str(path)])
    assert created.exit_code == 2
    assert not path.exists()


def test_baseline_does_not_claim_findings_resolved_after_coverage_gap(tmp_path):
    config = tmp_path / "config.yml"
    config.write_text('password: "local-test-baseline-value"')
    baseline = tmp_path / "accepted.json"
    assert runner.invoke(app, ["baseline", str(tmp_path), "-o", str(baseline)]).exit_code == 0
    config.write_text("x" * 2048)
    result = runner.invoke(app, [
        "scan", str(tmp_path), "--max-file-kb", "1", "--baseline", str(baseline),
        "--format", "json", "--fail-on", "none",
    ])
    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["summary"]["resolved_findings"] == 0
    assert report["summary"]["coverage_gaps"] == 1


def test_invalid_baseline_error_does_not_echo_its_content(tmp_path):
    path = tmp_path / "bad.json"
    sensitive = "local-test-malformed-private-value"
    path.write_text(sensitive)
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", str(path)])
    assert result.exit_code == 2
    assert sensitive not in result.output
    assert "invalid schema" in result.output


def test_output_file_and_baseline_are_excluded_from_scan(tmp_path):
    output = tmp_path / "custom-report.json"
    output.write_text('password: "local-test-old-report-content"')
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "-o", str(output)])
    assert result.exit_code == 0
    assert json.loads(output.read_text())["summary"]["findings"] == 0


def test_report_cannot_overwrite_input_baseline(tmp_path):
    baseline = tmp_path / "accepted.json"
    save_baseline(scan(tmp_path), baseline)
    original = baseline.read_bytes()
    result = runner.invoke(app, [
        "scan", str(tmp_path), "--baseline", str(baseline), "-o", str(baseline),
    ])
    assert result.exit_code == 2
    assert baseline.read_bytes() == original


def test_html_escapes_untrusted_paths_and_uses_nonce_csp(tmp_path):
    (tmp_path / '<script>alert("test")<.txt').write_text("API_KEY=local-test-html-value")
    result = scan(tmp_path)
    report = render_html(result)
    assert '<script>alert("test")' not in report
    assert "&lt;script&gt;" in report
    assert "local-test-html-value" not in report
    nonce = re.search(r'<script nonce="([a-f0-9]+)">', report).group(1)
    assert f"script-src 'nonce-{nonce}'" in report
    assert "<script src=" not in report
    assert "<link " not in report
    assert str(tmp_path) not in report
    assert "No baseline supplied" in report


def test_html_command_writes_rendered_report(tmp_path):
    output = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "html", "-o", str(output)])
    assert result.exit_code == 0
    assert "BastionBloom" in output.read_text()
    assert "{{ report" not in output.read_text()


def test_full_path_display_is_explicitly_opt_in(tmp_path):
    hidden = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    visible = runner.invoke(app, [
        "scan", str(tmp_path), "--format", "json", "--show-full-path",
    ])
    assert str(tmp_path) not in hidden.stdout
    assert str(tmp_path) in visible.stdout


def test_sarif_output_is_valid_and_safe_for_code_scanning(tmp_path):
    sensitive = "local-test-sarif-secret"
    (tmp_path / "config.yml").write_text(f'password: "{sensitive}"')
    output = tmp_path / "results.sarif"
    result = runner.invoke(app, [
        "--no-banner", "scan", str(tmp_path), "--format", "sarif", "--output", str(output),
        "--fail-on", "none",
    ])
    assert result.exit_code == 0
    document = json.loads(output.read_text())
    run = document["runs"][0]
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "BastionBloom"
    assert run["results"][0]["ruleId"] == "SEC005"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert run["results"][0]["message"]["text"].endswith("[REDACTED]")
    assert run["results"][0]["properties"]["status"] == "unbaselined"
    assert sensitive not in output.read_text()


def test_sarif_correlation_links_include_source_lines(tmp_path):
    (tmp_path / "compose.yaml").write_text(
        "services:\n"
        "  database:\n"
        "    image: postgres:17\n"
        "    ports: [\"5432:5432\"]\n"
        "    environment: {POSTGRES_PASSWORD: \"\"}\n"
    )
    document = json.loads(render_sarif(scan(tmp_path)))
    correlation = next(
        entry for entry in document["runs"][0]["results"] if entry["ruleId"] == "COR001"
    )

    related = correlation["relatedLocations"]
    assert {location["message"]["text"] for location in related} == {
        "Database port published beyond loopback",
        "Database authentication weakened",
    }
    assert {location["physicalLocation"]["region"]["startLine"] for location in related} == {
        4, 5,
    }


def test_version_rule_list_and_unknown_rule_error(tmp_path):
    assert runner.invoke(app, ["--version"]).exit_code == 0
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "COR001" in result.stdout
    invalid = runner.invoke(app, ["scan", str(tmp_path), "--exclude-rule", "TYPO001"])
    assert invalid.exit_code == 2


@pytest.mark.parametrize("content", [
    "[]", '{"schema_version": true, "findings": []}',
    '{"schema_version": 1, "findings": [{"fingerprint": "bad", "severity": "high"}]}',
])
def test_malformed_baseline_schema_is_rejected(tmp_path, content):
    path = tmp_path / "baseline.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        load_baseline(path)


def test_failed_atomic_write_preserves_previous_report(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text("previous-report")

    def fail_replace(*arguments):
        raise OSError("simulated write failure")

    monkeypatch.setattr("bastionbloom.output.os.replace", fail_replace)
    with pytest.raises(OSError):
        write_text(path, "replacement-report")
    assert path.read_text() == "previous-report"
    assert list(tmp_path.iterdir()) == [path]
