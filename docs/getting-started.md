# Getting started

## Install on Linux

BastionBloom requires Python **3.11+**. Clone the repository and install the CLI
inside a virtual environment:

```bash
git clone https://github.com/rakshit-737/bastionbloom.git
cd bastionbloom
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
bastionbloom --version
```

Use `python -m pip install -e '.[dev]'` instead if you want to edit the scanner
and run its tests. `python -m bastionbloom` is an equivalent entry point.

## Run a clean first scan

```bash
bastionbloom scan examples/hardened --fail-on low
```

The hardened fixture includes a non-root Dockerfile, an internal database with
runtime secret injection, and a commit-pinned, read-only pull-request workflow.
The current rules produce **zero findings** for this example.

![Clean scan of the hardened example](assets/screenshots/cli-hardened.png)

## Inspect the vulnerable example

```bash
bastionbloom scan examples/vulnerable --details
```

Expect **23 findings**, including three connected-risk checks. The default
high-severity threshold returns exit code `1` for this scan. The fixture's
credential strings are synthetic, and no containers or example workflows run.

## Generate a dashboard

```bash
bastionbloom scan examples/vulnerable --format html --output security-report.html --fail-on none
```

Open `security-report.html` in a browser. It works offline and includes search,
severity/status filters, redacted evidence, and recommended fixes.

## Scan your project

```bash
bastionbloom scan /path/to/your/project --details
```

Nested `.gitignore` files are respected by default. To include gitignored files
such as `.env`, add `--no-gitignore`. Dependency/VCS/build directories remain
pruned, and files above the default **1 MiB** limit are skipped.

Continue with the [CLI guide](cli.md) for thresholds, exclusions, and baselines,
or the [demo walkthrough](demo.md) to inspect the connected findings.
