# SentinelHTTP v0.1.0

First public release of SentinelHTTP, a local HTTP/HTTPS configuration
assessment tool for authorized targets.

- One bounded GET by default, with opt-in redirect tracing and three
  uncredentialed CORS probes under a shared request budget.
- Scope approval and verified dialing at every request; private destinations
  require explicit opt-in, and traced HTTPS-to-HTTP downgrades are blocked.
- Evidence-led TLS, header, cookie, CSP, CORS and redirect observations; a
  versioned finding catalog and coverage-aware Configuration Score.
- Versioned JSON plus terminal, Markdown and HTML reports; conservative diff
  for compatible root scans; local loopback dashboard with bundled assets.
- Human presentation in English, Spanish, Russian and Simplified Chinese.
- Synthetic [dashboard screenshots](screenshots.md), an
  [interview review](interview-review.md), frontend ESLint and Git-history
  secret scanning in CI.

The [quick start](../README.md) and [installation guide](install.md) explain
usage and platform requirements. On Windows, macOS and iOS, HTTPS scanning
requires an explicit PEM CA bundle. Report files can contain sensitive origin,
certificate and cookie-name metadata. Findings are configuration observations,
not proof of exploitation or a full-site security verdict.

The [release readiness matrix](release-readiness.md) and
[Phase 22 report](phase22-report.md) record local and Linux CI verification.
