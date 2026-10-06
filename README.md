# BastionBloom

**Turn scattered configuration warnings into actionable security priorities.**

BastionBloom is a local-first security scanner for developers and small teams.
It checks source files for accidentally committed secrets, Docker Compose and
Dockerfile configurations for deployment risks, and GitHub Actions workflows
for dangerous permissions and untrusted input. Its correlation engine connects
related findings to highlight the combinations that matter most.

The scanner runs entirely on your machine. It does not upload source code,
execute project code, launch containers, or contact the services being scanned.
Detected credential values are redacted from all output.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
bastionbloom --help
```

Requires Python 3.11 or newer. Full usage, rule documentation, examples, and
verification instructions will accompany the implementation.

## License

MIT. Created by [rakshit-737](https://github.com/rakshit-737).
