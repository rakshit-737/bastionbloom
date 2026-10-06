"""Generate the public demo from real scanner output after each MkDocs build."""

from pathlib import Path

from bastionbloom.output import write_text
from bastionbloom.reports import render_html, render_json
from bastionbloom.scanner import scan

ROOT = Path(__file__).resolve().parents[1]


def on_post_build(config, **kwargs) -> None:
    result = scan(ROOT / "examples" / "vulnerable")
    if result.warnings:
        raise RuntimeError("Cannot publish an incomplete demonstration scan")
    # Publish a useful relative label rather than a CI worker's absolute path.
    result.target = "examples/vulnerable"
    html = render_html(result)
    data = render_json(result)
    for literal in ("demo-only-not-a-real-key", "demo-only-not-a-real-password"):
        if literal in html or literal in data:
            raise RuntimeError("Demo credential redaction failed")
    destination = Path(config["site_dir"]) / "demo-report"
    destination.mkdir(parents=True, exist_ok=True)
    write_text(destination / "index.html", html)
    write_text(destination / "report.json", data)
