# CLI guide

## Commands

| Command | Purpose |
| --- | --- |
| `scan [TARGET]` | Scan a local directory; defaults to the current directory |
| `baseline [TARGET]` | Record the current findings for later comparisons |
| `rules --details` | List all checks with explanation and remediation |
| `banner --style STYLE` | Export exact raw ASCII artwork |

Use `bastionbloom --help` or `bastionbloom scan --help` for the current options.

## Scan options

| Option | Default | Purpose |
| --- | --- | --- |
| `--format`, `-f` | `text` | Select `text`, `json`, `html`, or `sarif` |
| `--output`, `-o` | stdout | Save the report to a file |
| `--baseline` | none | Compare an existing baseline |
| `--fail-on` | `high` | Fail for new findings at this severity or higher |
| `--details` | off | Include explanations and fixes in terminal output |
| `--no-gitignore` | off | Include gitignored files |
| `--exclude` | none | Add an ignore glob; repeatable |
| `--exclude-rule` | none | Disable a known rule ID; repeatable |
| `--max-file-kb` | `1024` | Set the per-file limit in KiB |

JSON and HTML emitted directly to stdout never contain a startup banner. When
writing a report to a file, a terminal summary is displayed separately.

### SARIF for code scanning

SARIF 2.1.0 maps severity to Code Scanning levels, includes stable fingerprints,
source locations, rule metadata, and redacted messages. Connected-risk findings
also include related locations for each contributing check, including its rule
title and source line:

```bash
bastionbloom scan . --format sarif --output bastionbloom.sarif --fail-on none
```

The file can be uploaded with GitHub's `upload-sarif` action or consumed by
other SARIF-compatible CI systems. SARIF still includes all findings when a
baseline is supplied; `isNew` is included as a result property so integrations
can decide how to present accepted findings.

## Baseline comparison

```bash
bastionbloom baseline . --output bastionbloom-baseline.json
bastionbloom scan . --baseline bastionbloom-baseline.json --fail-on high
```

Existing findings stay visible. Only new findings or findings whose severity
has increased fail the threshold. Credential fingerprints survive line moves
but change when the credential value changes. Relative paths make baselines
portable between checkouts.

Keep exclusions and size limits consistent across scans. Incomplete scans
cannot create baselines and do not claim that old findings have been resolved.

## Exclusions

Create `.bastionbloomignore` at the scan root using gitignore syntax:

```gitignore
generated/
*.min.js
!important.min.js
```

```bash
bastionbloom scan . --exclude 'vendor/' --exclude '*.map'
bastionbloom scan . --exclude-rule SEC005
```

Custom ignore rules override gitignore decisions, and CLI globs have the
highest precedence. Built-in dependency, build, and VCS pruning always applies.
Disabling a source rule prevents correlations that require it.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No new findings meet the chosen threshold |
| `1` | New findings meet or exceed the chosen threshold |
| `2` | Invalid input, failed output, or incomplete scan coverage |

Thresholds are `critical`, `high`, `medium`, `low`, `info`, or `none`.
`--fail-on none` disables finding-based failure; scan errors still return `2`.

## Terminal identity

Global options belong **before** the command:

```bash
bastionbloom --banner-style minimal scan .
bastionbloom --banner-style aggressive scan .
bastionbloom --banner-style premium scan .
bastionbloom --no-banner scan .
```

The [banner gallery](banners.md) includes all three raw ASCII designs.
