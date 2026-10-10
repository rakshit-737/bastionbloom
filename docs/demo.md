# Working demo

The demo uses the repository's shipped examples. All findings come from actual
scanner runs, and the credential strings in the vulnerable fixture are synthetic.

<p><a class="md-button md-button--primary" href="../demo-report/">Open the interactive security report</a></p>

The live report is regenerated from the current scanner and fixtures every time
the documentation site builds. It supports search, severity/status filters,
redacted evidence, recommended fixes, and links between connected findings.
When correlations exist, a **Priority risks** panel puts those connected checks
before the individual findings they summarize.

## 1. Inspect a vulnerable deployment

```bash
bastionbloom scan examples/vulnerable --details
```

The current example produces **23 findings across four files**. Five are
critical, including an untrusted checkout in a privileged pull-request
workflow and all three connected-risk checks:

| Check | Connected conditions |
| --- | --- |
| COR001 | A database is published beyond loopback and uses weak/empty/trust authentication |
| COR002 | A published management service mounts the Docker daemon socket |
| COR003 | A privileged service also mounts the host's root filesystem |

![Real vulnerable-example scan](assets/screenshots/cli-vulnerable.png)

The default threshold returns exit code `1`. Use `--fail-on none` when you
want to explore the demonstration without finding-based failure.

## 2. Explore the HTML dashboard

```bash
bastionbloom scan examples/vulnerable --format html --output security-report.html --fail-on none
```

![Generated HTML report with interactive filters and remediation](assets/screenshots/html-dashboard.png)

This demo has no baseline, so the report labels its findings **Unbaselined** and
the summary calls them **Findings to review**. They are not classified as new
regressions until you compare a later scan with a reviewed baseline.

Try these interactions in the live report:

1. Start in **Priority risks** and follow a linked check to its finding.
2. Select **Critical** to isolate the highest-severity findings.
3. Search for **COR001** to inspect the connected database risk.
4. Expand **connected findings** to follow the source checks.
5. Clear the filters, then search for **SEC005** to view redacted
   credential evidence.

Search, severity, and baseline-status filters are written into the report URL.
Copy that URL to share the same view; **Clear filters** resets every filter and
removes its URL parameters. Links to findings also clear active filters so the
destination is visible.

The browser report is a static snapshot. Scanning remains a local CLI operation.

## 3. Compare the hardened configuration

```bash
bastionbloom scan examples/hardened --fail-on low
```

The hardened version uses an internal database network and runtime secret
files, removes privileged host access, declares a non-root final image user,
and pins workflow actions with read-only repository permissions.

![Real hardened-example scan with zero findings](assets/screenshots/cli-hardened.png)

The scanner reports **zero findings** and exits `0`. This result describes the
included static checks; runtime/CVE checks are outside its coverage.

See the [rule catalog](rules.md) for each check's semantics and the
[development guide](development.md) to reproduce these screenshots.
