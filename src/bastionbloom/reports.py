"""Render redacted results for humans and automation."""

import json
import secrets
from io import StringIO

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console
from rich.table import Table
from rich.text import Text

from bastionbloom import __version__
from bastionbloom.models import ScanResult, Severity

COLORS = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "cyan"}


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"


def render_sarif(result: ScanResult) -> str:
    """Render SARIF 2.1.0 without copying secrets into the code-scanning log."""
    rules = []
    rule_indexes = {}
    findings_by_fingerprint = {finding.fingerprint: finding for finding in result.findings}
    unique_rules = {finding.rule.id: finding for finding in result.findings}.values()
    for index, finding in enumerate(unique_rules):
        rule_indexes[finding.rule.id] = index
        rules.append({
            "id": finding.rule.id,
            "name": finding.rule.title,
            "shortDescription": {"text": finding.rule.title},
            "fullDescription": {"text": finding.rule.description},
            "help": {"text": finding.rule.remediation},
            "properties": {
                "category": finding.rule.category,
                "confidence": finding.rule.confidence,
                "severity": finding.rule.severity.value,
            },
        })
    level = {"critical": "error", "high": "error", "medium": "warning"}
    results = []
    for finding in result.findings:
        result_entry = {
            "ruleId": finding.rule.id,
            "ruleIndex": rule_indexes[finding.rule.id],
            "level": level.get(finding.rule.severity.value, "note"),
            "message": {"text": f"{finding.rule.title}: {finding.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": max(1, finding.line)},
                }
            }],
            "fingerprints": {"bastionbloom/v1": finding.fingerprint},
            "properties": {
                "category": finding.rule.category,
                "confidence": finding.rule.confidence,
                "isNew": finding.is_new,
                "service": finding.service,
            },
        }
        if finding.related:
            related_locations = []
            for index, fingerprint in enumerate(finding.related):
                related = findings_by_fingerprint.get(fingerprint)
                if related is None:
                    continue
                related_locations.append({
                    "id": index,
                    "message": {"text": related.rule.title},
                    "physicalLocation": {
                        "artifactLocation": {"uri": related.path},
                        "region": {"startLine": max(1, related.line)},
                    },
                })
            if related_locations:
                result_entry["relatedLocations"] = related_locations
        results.append(result_entry)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BastionBloom",
                    "informationUri": "https://github.com/rakshit-737/bastionbloom",
                    "semanticVersion": __version__,
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {"target": result.target, "complete": not result.warnings},
        }],
    }
    return json.dumps(document, indent=2) + "\n"


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
