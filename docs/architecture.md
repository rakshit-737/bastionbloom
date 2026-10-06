# Architecture

BastionBloom is a local static scanner. Its data pipeline keeps detection,
risk correlation, baseline comparison, and rendering separate.

```text
Local directory
      |
      v
Ignore rules + bounded regular-file reads
      |
      +--> Credential pattern checks
      +--> Dockerfile / Compose checks
      +--> GitHub Actions checks
      |
      v
Service-scoped connected-risk checks
      |
      v
Stable identities + deduplication + severity ordering
      |
      v
Optional baseline comparison
      |
      +--> Terminal summary
      +--> JSON report
      +--> Offline HTML dashboard
```

## Modules

| Module | Responsibility |
| --- | --- |
| `scanner.py` | Traverse included files, enforce bounds, dispatch checks, and report incomplete coverage |
| `yaml_support.py` | Safely load bounded YAML with source locations and correct GitHub Actions `on` handling |
| `rules/secrets.py` | Detect credential formats and emit redacted evidence |
| `rules/docker.py` | Inspect Compose settings and Dockerfile stage/user declarations |
| `rules/actions.py` | Inspect workflow permissions, action references, and untrusted-input patterns |
| `correlation.py` | Connect checks only within the same file and service |
| `models.py` | Represent findings, severity, confidence, fingerprints, and scan summaries |
| `baseline.py` | Load/save portable snapshots and identify new/resolved/escalated findings |
| `reports.py` | Render terminal, structured JSON, and escaped HTML outputs |
| `output.py` | Write reports atomically |
| `cli.py` / `banner.py` | Expose commands, CI exit codes, and terminal identity |

## Privacy and coverage boundaries

Credential values do not appear in report evidence or baseline metadata. The
HTML renderer escapes user-controlled paths and labels, and its dashboard uses
only embedded assets with a nonce-based script policy.

Scanning avoids symlinks and special files, prunes dependency/VCS/build
directories, and bounds file size and YAML complexity. Inaccessible files and
unparseable configurations are reported as incomplete coverage.

The scanner does not execute application code, access Git history, validate
tokens online, pull images, evaluate Compose overrides, or test firewall
reachability. See [security rules](rules.md) for rule-specific interpretation.

## Documentation and public demo

MkDocs Material builds these pages. A post-build hook runs the actual scanner
against `examples/vulnerable` and renders an interactive demo report using the
same HTML renderer as the CLI. The demo uses a relative target label instead
of a build-machine path. GitHub Pages serves the resulting static artifact.
