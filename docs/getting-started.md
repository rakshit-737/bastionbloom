# Getting started

## 1. Install the CLI

BastionBloom requires Python **3.11 or newer** and Git. The commands below make
a production-only install in a virtual environment; development and docs
dependencies are not needed for a first scan.

### macOS/Linux

```bash
git clone https://github.com/rakshit-737/bastionbloom.git
cd bastionbloom
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
bastionbloom --version
```

### Windows PowerShell

```powershell
git clone https://github.com/rakshit-737/bastionbloom.git
Set-Location bastionbloom
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
bastionbloom --version
```

If PowerShell blocks the activation script, allow it for the current session and
run the activation line again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

For scanner development, use `python -m pip install -e '.[dev]'` instead. The
equivalent module entry point is `python -m bastionbloom`.

## 2. Run a clean first scan

From the repository root, scan the shipped hardened fixture:

```text
bastionbloom scan examples/hardened --fail-on low
```

It should exit `0` with **zero findings**. The fixture includes a non-root
Dockerfile, an internal database with runtime secret injection, and a
commit-pinned, read-only pull-request workflow. BastionBloom reads files only;
it does not execute project code, launch containers, or contact services.

![Clean scan of the hardened example](assets/screenshots/cli-hardened.png)

## 3. Scan your project

Change to the directory you want to review, then scan `.`:

### macOS/Linux

```bash
cd /path/to/your/project
bastionbloom scan . --details
```

### Windows PowerShell

```powershell
Set-Location C:\path\to\your\project
bastionbloom scan . --details
```

Nested `.gitignore` files are respected by default. To include gitignored files
such as `.env`, add `--no-gitignore`. Dependency/VCS/build directories remain
pruned, and files above the default **1 MiB** limit are skipped.

## 4. Inspect a report

```text
bastionbloom scan examples/vulnerable --format html --output security-report.html --fail-on none
```

Open `security-report.html` in a browser. It works offline and includes priority
connected risks, redacted evidence, recommended fixes, and searchable filters.
With no baseline, findings are marked **unbaselined**/**to review**; that means
they need review, not that they are regressions. The filters can be cleared and
their URL state can be copied when sharing a report. See the [demo walkthrough](demo.md)
for the full report path and the [CLI guide](cli.md) for baselines and thresholds.

## Optional: inspect the vulnerable example

```text
bastionbloom scan examples/vulnerable --details
```

Expect **23 findings**, including three connected-risk checks. The default
high-severity threshold returns exit code `1`; the fixture's credential strings
are synthetic, and no containers or example workflows run.
