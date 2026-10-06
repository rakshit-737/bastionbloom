"""Keep the shipped before-and-after demonstrations accurate as rules evolve."""

from pathlib import Path

from bastionbloom.reports import render_html, render_json
from bastionbloom.scanner import scan

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_vulnerable_example_has_all_risk_families_and_three_chains():
    result = scan(EXAMPLES / "vulnerable")
    assert result.warnings == []
    assert {f.rule.category for f in result.findings} == {
        "secrets", "docker", "actions", "correlation",
    }
    assert {f.rule.id for f in result.findings if f.rule.category == "correlation"} == {
        "COR001", "COR002", "COR003",
    }
    for report in (render_json(result), render_html(result)):
        assert "demo-only-not-a-real-key" not in report
        assert "demo-only-not-a-real-password" not in report


def test_hardened_example_is_clean_including_nested_workflow():
    result = scan(EXAMPLES / "hardened")
    assert result.warnings == []
    assert result.scanned_files == 3
    assert result.findings == []
