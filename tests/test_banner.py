"""Protect terminal output contracts without adding decoration to machine reports."""

import json

import pytest
from typer.testing import CliRunner

from bastionbloom.banner import BannerStyle, render_startup
from bastionbloom.cli import app

runner = CliRunner()


@pytest.mark.parametrize("style", list(BannerStyle))
def test_raw_art_exports_are_ascii_aligned_and_fit_normal_terminals(style):
    result = runner.invoke(app, ["banner", "--style", style.value])
    assert result.exit_code == 0
    assert result.stdout.isascii()
    assert "\x1b" not in result.stdout
    lines = result.stdout.splitlines()
    assert {len(line) for line in lines} == {76}
    assert lines[0].startswith("+") and lines[-1].endswith("+")
    assert len(lines) >= 7


def test_three_styles_have_distinct_visual_identities():
    exports = {runner.invoke(app, ["banner", "--style", s.value]).stdout for s in BannerStyle}
    assert len(exports) == 3


def test_startup_includes_version_tagline_and_clean_separator():
    result = runner.invoke(app, ["banner", "--startup"])
    assert result.exit_code == 0
    assert "BastionBloom v0.1.0\n" in result.stdout
    assert "Local security auditing. Connected risks. Actionable fixes." in result.stdout
    assert result.stdout.splitlines()[-1] == "-" * 76


def test_narrow_terminal_fallback_stays_readable():
    output = render_startup(terminal_width=60)
    assert "BastionBloom v0.1.0" in output
    assert max(map(len, output.splitlines())) <= 60
    assert "|__]" not in output


def test_banner_is_shown_for_text_and_can_be_disabled(tmp_path):
    shown = runner.invoke(app, ["scan", str(tmp_path)])
    hidden = runner.invoke(app, ["--no-banner", "scan", str(tmp_path)])
    assert shown.exit_code == hidden.exit_code == 0
    assert "BastionBloom v0.1.0" in shown.stdout
    assert "BastionBloom v0.1.0" not in hidden.stdout
    assert "No findings detected" in hidden.stdout


@pytest.mark.parametrize("style", list(BannerStyle))
def test_selected_banner_never_pollutes_json_or_html_stdout(tmp_path, style):
    prefix = ["--banner-style", style.value, "scan", str(tmp_path)]
    machine = runner.invoke(app, [*prefix, "--format", "json"])
    html = runner.invoke(app, [*prefix, "--format", "html"])
    assert machine.exit_code == html.exit_code == 0
    assert json.loads(machine.stdout)["summary"]["findings"] == 0
    assert html.stdout.startswith("<!doctype html>")
    assert "BastionBloom v0.1.0" not in html.stdout
