---
title: BastionBloom - Local security intelligence
hide:
  - navigation
  - toc
---

<section class="bb-hero">
  <div class="bb-eyebrow">BASTIONBLOOM / LOCAL SECURITY INTELLIGENCE</div>
  <h1>Small clues.<br>Connected risks.</h1>
  <p class="bb-lead">Find leaked credentials, unsafe deployments, and risky workflows. Connect the signals into security priorities you can actually fix.</p>
  <div class="bb-actions">
    <a class="md-button md-button--primary" href="getting-started/">Start your first scan</a>
    <a class="md-button" href="demo-report/">Explore the live report</a>
  </div>
</section>

<dl class="bb-metrics" aria-label="BastionBloom at a glance">
  <div class="bb-metric"><dt>Security rules</dt><dd>24</dd></div>
  <div class="bb-metric"><dt>Connected-risk checks</dt><dd>3</dd></div>
  <div class="bb-metric"><dt>Source-code uploads</dt><dd>0</dd></div>
</dl>

## Security review that keeps the context

An exposed database is a concern. An exposed database **with unsafe
authentication** is a priority. BastionBloom connects findings within the same
Compose service so important combinations rise to the top.

<div class="bb-features">
  <div class="bb-feature"><h3>Credentials stay redacted</h3><p>Detect recognizable token formats, private-key material, and credential-like literals without putting values into reports.</p></div>
  <div class="bb-feature"><h3>Deployment risks connect</h3><p>Inspect Dockerfiles and Compose services for privileged containers, dangerous host mounts, exposed databases, and weakened authentication.</p></div>
  <div class="bb-feature"><h3>Workflows get a review</h3><p>Find broad token permissions, mutable action references, untrusted shell interpolation, and privileged pull-request checkouts.</p></div>
  <div class="bb-feature"><h3>CI tracks regressions</h3><p>Portable baselines keep existing findings visible while failing your pipeline only for new or severity-escalated risks.</p></div>
</div>

## See the working tool

![Actual vulnerable-example scan with the startup banner and connected risks](assets/screenshots/cli-vulnerable.png)

<p class="bb-caption">Captured from the working CLI using synthetic example configurations. The shipped vulnerable example produces 23 findings; the hardened example produces zero.</p>

[Walk through the demo](demo.md){ .md-button }
[Read the rule catalog](rules.md){ .md-button }

## First scan in a minute

Install the minimal CLI using [Getting started](getting-started.md), then run
this from the repository root:

```text
bastionbloom scan examples/hardened --fail-on low
```

The command works in macOS/Linux shells and Windows PowerShell. Python **3.11 or
newer** is required. The scanner reads local files without executing project
code, launching containers, or contacting scanned services.

## Pick your next step

- **[Getting started](getting-started.md):** installation, first scans, and report generation.
- **[CLI guide](cli.md):** options, baseline comparisons, exclusions, and CI exit codes.
- **[Demo walkthrough](demo.md):** vulnerable versus hardened configurations and an interactive report.
- **[Security rules](rules.md):** detection semantics, severity, confidence, and coverage.
- **[Architecture](architecture.md):** how file scanning, correlation, and reporting fit together.
- **[Development](development.md):** checks, local documentation previews, and screenshot reproduction.
