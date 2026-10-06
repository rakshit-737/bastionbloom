"""Capture real CLI output and the real HTML report for the documentation.

Install with `pip install -e '.[screenshots]'` and `playwright install chromium`.
Each invocation can generate one screenshot so assets can be committed individually.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from io import StringIO
from pathlib import Path

from playwright.sync_api import sync_playwright
from rich.console import Console
from rich.terminal_theme import MONOKAI
from rich.text import Text

from bastionbloom.reports import render_html
from bastionbloom.scanner import scan

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "docs" / "assets" / "screenshots"
DEMO_NAMES = ("cli-vulnerable", "cli-hardened", "html-dashboard")
TERMINAL_SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><style>
* {box-sizing:border-box} body {margin:0;background:#080f1a;color:#e5edf7}
main {width:1200px;margin:0 auto;padding:30px;font:14px system-ui,sans-serif}
.eyebrow {color:#5ee3bd;letter-spacing:.18em;font-size:12px;font-weight:800}
h1 {font-size:27px;margin:10px 0 24px;letter-spacing:-.03em}
.terminal {border:1px solid #30415a;border-radius:14px;overflow:hidden;background:#0d1623}
.bar {background:#182538;height:45px;display:flex;align-items:center;gap:9px;padding:0 18px}
.dot {width:10px;height:10px;border-radius:50%;background:#fb7185}
.dot:nth-child(2) {background:#facc15} .dot:nth-child(3) {background:#5ee3bd}
.bar span:last-child {margin-left:15px;color:#a8b8cf;font-size:12px}
.output {padding:24px;max-height:740px;overflow:hidden}
pre {margin:0;font:14px/1.35 "DejaVu Sans Mono",monospace;white-space:pre}
.prompt {color:#5ee3bd;margin-bottom:18px}
footer {color:#8fa6c1;margin-top:17px;font-size:12px}
</style></head><body><main class="capture">
<div class="eyebrow">BASTIONBLOOM / WORKING DEMO</div>
<h1>__TITLE__</h1><div class="terminal"><div class="bar">
<span class="dot"></span><span class="dot"></span><span class="dot"></span>
<span>bastionbloom - local security audit</span></div><div class="output">
<pre class="prompt">$ bastionbloom scan examples/__EXAMPLE__ --fail-on none</pre>
<pre>__OUTPUT__</pre></div></div>
<footer>Captured from the actual CLI. Synthetic example configurations only.</footer>
</main></body></html>"""


def terminal_document(example: str) -> str:
    environment = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": "112", "TERM": "xterm-256color"}
    environment.pop("NO_COLOR", None)
    command = [sys.executable, "-m", "bastionbloom", "scan", f"examples/{example}",
               "--fail-on", "none"]
    output = subprocess.run(
        command, cwd=ROOT, env=environment, capture_output=True, text=True, check=True,
    ).stdout
    console = Console(file=StringIO(), record=True, width=112, force_terminal=True)
    console.print(Text.from_ansi(output), end="")
    markup = console.export_html(inline_styles=True, code_format="{code}", theme=MONOKAI)
    title = "Connect the clues. Prioritize the risk." if example == "vulnerable" else (
        "Hardened configuration. A clean scan."
    )
    return TERMINAL_SHELL.replace("__TITLE__", title).replace(
        "__EXAMPLE__", example,
    ).replace("__OUTPUT__", markup)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=(*DEMO_NAMES, "all"), default="all")
    parser.add_argument("--browser-executable", type=Path, help="Use an existing Chromium binary")
    options = parser.parse_args()
    selected = DEMO_NAMES if options.only == "all" else (options.only,)
    DESTINATION.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bastionbloom-captures-") as temporary:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=(
                    str(options.browser_executable) if options.browser_executable else None
                ),
            )
            page = browser.new_page(viewport={"width": 1280, "height": 1040}, device_scale_factor=1)
            for name in selected:
                document = Path(temporary) / f"{name}.html"
                if name == "html-dashboard":
                    result = scan(ROOT / "examples" / "vulnerable")
                    result.target = "examples/vulnerable"
                    document.write_text(render_html(result), encoding="utf-8")
                else:
                    document.write_text(
                        terminal_document(name.removeprefix("cli-")), encoding="utf-8",
                    )
                page.goto(document.as_uri(), wait_until="networkidle")
                page.evaluate("document.fonts.ready")
                destination = DESTINATION / f"{name}.png"
                if name == "html-dashboard":
                    assert page.locator("#findings article").count() == len(result.findings)
                    page.screenshot(path=str(destination), full_page=False)
                else:
                    page.locator(".capture").screenshot(path=str(destination))
                print(f"Captured {destination.relative_to(ROOT)}")
            browser.close()


if __name__ == "__main__":
    main()
