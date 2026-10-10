# Development

## Development setup

From a repository checkout:

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,docs]'
```

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e '.[dev,docs]'
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process
ExecutionPolicy Bypass` and retry the activation line.

## Project checks

```bash
ruff check .
pytest
bastionbloom --no-banner scan . --fail-on low
python -m pip wheel --no-deps --wheel-dir dist .
```

The tests cover credential privacy, deployment/workflow detection boundaries,
safe YAML parsing, filesystem coverage, baselines, CI exit codes, shipped
examples, and machine-readable output. GitHub Actions checks Python 3.11–3.14.

The root `.bastionbloomignore` excludes intentional test/vulnerable fixtures
from repository self-scans. Scanning `examples/vulnerable` directly includes
the entire demonstration.

## Preview the documentation

```bash
mkdocs serve
```

Open `http://127.0.0.1:8000/`. The documentation hook generates the interactive
demo report from the real scanner after each build, including local previews.

For a production-style build:

```bash
mkdocs build --strict
python -m http.server 8000 --directory site
```

`site/` is generated output and is ignored by Git. The strict build checks
navigation and Markdown links. Static assets are bundled locally; the site
does not load Google Fonts or analytics.

## Reproduce demo screenshots

```bash
python -m pip install -e '.[screenshots]'
playwright install chromium
python scripts/capture_demos.py --only cli-vulnerable
python scripts/capture_demos.py --only cli-hardened
python scripts/capture_demos.py --only html-dashboard
```

The capture script runs actual CLI commands, renders their ANSI output in a
terminal-styled frame, and captures the actual HTML dashboard in Chromium.
It writes PNG files to `docs/assets/screenshots/`. Use
`--browser-executable /path/to/chromium` to reuse an installed browser.

When a rule changes the demonstration results, refresh screenshots and the
documented finding counts together. Each image is small enough to serve
directly from the repository and documentation site.

## GitHub Pages deployment

`.github/workflows/docs.yml` builds the documentation on pull requests and
publishes successful `main` builds through GitHub's official Pages actions.
The build job has read-only repository access. Only the deployment job receives
Pages publishing and OIDC permissions.

The deployed site is [rakshit-737.github.io/bastionbloom](https://rakshit-737.github.io/bastionbloom/).
The scanner-generated report lives at `/bastionbloom/demo-report/`.

## GitHub Code Scanning

The repository's `code-scanning.yml` workflow scans the repository and uploads
`bastionbloom.sarif` to GitHub Code Scanning on pushes to `main`. Generated SARIF
files are excluded from recursive scans, and the workflow grants only the
`security-events: write` permission required by the upload step.

For another repository, install BastionBloom and use the same two-step pattern:

```yaml
- run: bastionbloom --no-banner scan . --format sarif --output bastionbloom.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@<full-commit-sha>
  with:
    sarif_file: bastionbloom.sarif
```
