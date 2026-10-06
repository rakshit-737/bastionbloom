"""Render redacted results for humans and automation."""

import json
import secrets
from io import StringIO

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console
from rich.table import Table
from rich.text import Text

from bastionbloom.models import ScanResult, Severity

COLORS = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "cyan"}


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"


def render_html(result: ScanResult) -> str:
    environment = Environment(
        loader=PackageLoader("bastionbloom", "templates"),
        autoescape=select_autoescape(default=True),
    )
    return environment.get_template("report.html").render(
        report=result.to_dict(), severities=[s.value for s in Severity],
        nonce=secrets.token_hex(16),
    )


def print_console(result: ScanResult, console: Console, details: bool = False) -> None:
    console.print("BastionBloom · local security scan", style="bold green")
    console.print(f"Target: {result.target}", markup=False, highlight=False)
    console.print(
        f"{result.scanned_files} files scanned · {result.skipped_files} skipped · "
        f"{len(result.findings)} findings · {len(result.new_findings)} new · "
        f"{result.duration_seconds:.2f}s"
    )
    if result.baseline_applied:
        console.print(f"Baseline: {result.resolved_count} previous findings resolved")
    if result.findings:
        table = Table(expand=True)
        for label in ("Severity", "Rule", "Location", "Finding", "Status"):
            table.add_column(label, overflow="fold")
        for finding in result.findings:
            severity = finding.rule.severity.value
            table.add_row(
                Text(severity.upper(), style=COLORS.get(severity, "white")),
                finding.rule.id, Text(f"{finding.path}:{finding.line}"),
                finding.rule.title, "new" if finding.is_new else "existing",
            )
        console.print(table)
    else:
        console.print("No findings detected in the scanned files.", style="green")
    if details:
        for finding in result.findings:
            console.print(
                f"\n{finding.rule.id} · {finding.path}:{finding.line}",
                style="bold", markup=False, highlight=False,
            )
            console.print(finding.rule.description, markup=False, highlight=False)
            console.print(finding.evidence, markup=False, highlight=False)
            console.print(f"Fix: {finding.rule.remediation}", markup=False, highlight=False)
    for warning in result.warnings:
        console.print(f"Incomplete scan: {warning}", style="yellow", markup=False, highlight=False)


def render_text(result: ScanResult, details: bool = False) -> str:
    stream = StringIO()
    print_console(result, Console(file=stream, width=120, color_system=None), details)
    return stream.getvalue()
