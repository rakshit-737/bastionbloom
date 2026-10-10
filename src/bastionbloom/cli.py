"""BastionBloom command-line interface and predictable CI exit codes."""

from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bastionbloom import __version__
from bastionbloom.banner import BannerStyle, render_art, render_startup
from bastionbloom.baseline import apply_baseline, load_baseline, save_baseline
from bastionbloom.models import Severity
from bastionbloom.output import write_text
from bastionbloom.reports import (
    print_console,
    render_html,
    render_json,
    render_sarif,
    render_text,
)
from bastionbloom.rules import RULES
from bastionbloom.scanner import ScanOptions
from bastionbloom.scanner import scan as run_scan

app = typer.Typer(
    name="bastionbloom", no_args_is_help=True, invoke_without_command=True,
    help="Local-first security scanning: secrets, Docker, workflows, and connected risks.",
    pretty_exceptions_enable=False,
)
console = Console(markup=False, highlight=False)
errors = Console(stderr=True, markup=False, highlight=False)


class Format(StrEnum):
    text = "text"
    json = "json"
    html = "html"
    sarif = "sarif"


class Threshold(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    none = "none"


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", is_eager=True),
    banner_style: BannerStyle = typer.Option(BannerStyle.premium, "--banner-style"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide the startup banner."),
):
    if version:
        typer.echo(f"BastionBloom {__version__}")
        raise typer.Exit()
    ctx.obj = {"banner_style": banner_style, "no_banner": no_banner}


def _startup(ctx: typer.Context) -> None:
    settings = ctx.obj or {}
    if not settings.get("no_banner", False):
        console.print(render_startup(
            settings.get("banner_style", BannerStyle.premium), terminal_width=console.width,
        ), style="cyan", markup=False, highlight=False)


def _options(
    target, exclude, exclude_rule, no_gitignore, max_file_kb, artifacts=(),
    show_full_path=False,
):
    patterns = list(exclude or [])
    root = target.resolve()
    for artifact in artifacts:
        if artifact is not None:
            try:
                patterns.append("/" + artifact.absolute().relative_to(root).as_posix())
            except ValueError:
                pass
    return ScanOptions(
        max_file_bytes=max_file_kb * 1024, respect_gitignore=not no_gitignore,
        exclude=tuple(patterns), exclude_rules=frozenset(exclude_rule or []),
        show_full_path=show_full_path,
    )


def _error(message):
    errors.print(f"Error: {message}", style="red")
    raise typer.Exit(2)


@app.command("scan")
def scan_command(
    ctx: typer.Context,
    target: Path = typer.Argument(Path("."), exists=True, file_okay=False, readable=True),
    format: Format = typer.Option(Format.text, "--format", "-f", help="Report format."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to a file."),
    baseline: Path | None = typer.Option(None, "--baseline", help="Compare an existing baseline."),
    fail_on: Threshold = typer.Option(Threshold.high, help="Fail on new findings at this level."),
    details: bool = typer.Option(False, "--details", help="Include explanations in text output."),
    no_gitignore: bool = typer.Option(False, "--no-gitignore", help="Include gitignored files."),
    exclude: list[str] | None = typer.Option(None, help="Additional ignore glob; repeatable."),
    exclude_rule: list[str] | None = typer.Option(None, help="Disable a rule ID; repeatable."),
    max_file_kb: int = typer.Option(1024, min=1, help="Maximum scanned file size in KiB."),
    show_full_path: bool = typer.Option(
        False, "--show-full-path", help="Include the absolute scan target in reports."
    ),
):
    """Scan a project. Exit 0: threshold passed; 1: new risks; 2: incomplete scan/error."""
    if output is not None and baseline is not None and output.resolve() == baseline.resolve():
        _error("Report output must differ from the input baseline")
    if format == Format.text or output is not None:
        _startup(ctx)
    try:
        previous = load_baseline(baseline) if baseline else None
        result = run_scan(target, _options(
            target, exclude, exclude_rule, no_gitignore, max_file_kb, (output, baseline),
            show_full_path,
        ))
        if previous is not None:
            apply_baseline(result, previous)
        if format == Format.json:
            report = render_json(result)
        elif format == Format.html:
            report = render_html(result)
        elif format == Format.sarif:
            report = render_sarif(result)
        else:
            report = render_text(result, details)
        if output:
            write_text(output, report)
            print_console(result, console, details)
            console.print(f"Report written to {output}")
        elif format == Format.text:
            print_console(result, console, details)
        else:
            typer.echo(report, nl=False)
    except ValueError as error:
        _error(str(error))
    except OSError:
        _error("Unable to read scan inputs or write the report; check paths and permissions")
    if not result.complete:
        raise typer.Exit(2)
    if fail_on != Threshold.none and result.fails_threshold(Severity(fail_on.value)):
        raise typer.Exit(1)


@app.command("baseline")
def baseline_command(
    ctx: typer.Context,
    target: Path = typer.Argument(Path("."), exists=True, file_okay=False, readable=True),
    output: Path = typer.Option(Path("bastionbloom-baseline.json"), "--output", "-o"),
    no_gitignore: bool = typer.Option(False, "--no-gitignore"),
    exclude: list[str] | None = typer.Option(None),
    exclude_rule: list[str] | None = typer.Option(None),
    max_file_kb: int = typer.Option(1024, min=1),
    show_full_path: bool = typer.Option(
        False, "--show-full-path", help="Include the absolute scan target in the baseline output."
    ),
):
    """Record current findings for later comparison; existing risks stay visible."""
    _startup(ctx)
    try:
        result = run_scan(target, _options(
            target, exclude, exclude_rule, no_gitignore, max_file_kb, (output,),
            show_full_path,
        ))
        print_console(result, console)
        save_baseline(result, output)
        console.print(f"Baseline written to {output}")
    except ValueError as error:
        _error(str(error))
    except OSError:
        _error("Unable to read scan inputs or write the baseline; check paths and permissions")


@app.command("rules")
def rules_command(ctx: typer.Context, details: bool = typer.Option(False, "--details")):
    """List all supported checks and optionally their remediation guidance."""
    _startup(ctx)
    table = Table(title="BastionBloom security rules")
    for name in ("ID", "Category", "Severity", "Check"):
        table.add_column(name)
    for rule in RULES.values():
        table.add_row(rule.id, rule.category, rule.severity.value, rule.title)
    console.print(table)
    if details:
        for rule in RULES.values():
            console.print(f"\n{rule.id}: {rule.description}")
            console.print(f"Fix: {rule.remediation}")


@app.command("banner")
def banner_command(
    style: BannerStyle = typer.Option(BannerStyle.premium, "--style"),
    startup: bool = typer.Option(False, "--startup", help="Include version and tagline."),
):
    """Print a raw ASCII banner for copy/paste; no ANSI escapes or terminal wrapping."""
    typer.echo(render_startup(style) if startup else render_art(style))
