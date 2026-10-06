# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

## Reporting a vulnerability

BastionBloom is a defensive security tool. If you find a vulnerability in the
scanner, CLI, report renderer, documentation site, or repository workflows,
please report it privately through
[GitHub Security Advisories](https://github.com/rakshit-737/bastionbloom/security/advisories/new).

Please include:

- the affected commit, version, or deployed URL;
- a concise description of the impact;
- reproducible steps or a minimal fixture;
- any relevant logs or screenshots after removing real secrets.

Do not include live credentials, private keys, customer data, or unredacted
source code in a public issue. If GitHub Security Advisories are unavailable,
open a public issue requesting a private reporting channel without including
exploit details.

We will acknowledge a report as soon as practical, investigate it, and credit
the reporter in the release notes unless they prefer to remain anonymous.

## Safe testing

Use the synthetic fixtures in `examples/vulnerable/` and `examples/hardened/`.
The vulnerable values are intentionally fake. BastionBloom does not execute
project code, launch containers, validate tokens online, or contact services
being scanned.
