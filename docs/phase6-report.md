# SENTINELHTTP PHASE 6 REPORT

Date: 2026-09-18. Gate: **PASS WITH LIMITATIONS**.

## Scope delivered

Pure, deterministic analysis of the existing HTTP client's captured response
headers. The phase covers CSP presence/deferment, HSTS, XCTO, Referrer-Policy,
Permissions-Policy, XFO, COOP, CORP, COEP and the untrusted Server claim. It keeps
capture, response context, applicability, syntax and observed effect separate.
No findings, severity, score, browser guarantee, product fingerprint or CVE
inference was added.

Response context distinguishes HTML, JSON, other, redirect, no-content and unknown
representations. Missing, malformed, repeated or oversized Content-Type remains
explicit. HSTS applies only to verified HTTPS DNS names and treats max-age=0 as
inactive. CSP policy semantics and XFO/frame-ancestors correlation remain deferred
to Phase 8.

Field-specific duplicate processing follows each normative algorithm. Structured
Fields use a bounded RFC 9651 Item/Dictionary parser, including all bare-item and
parameter types, strict strings/display strings, duplicate last-member semantics
and optional Base64 padding. Permissions-Policy retains typed Token/String direct
and inner-list allowlist items, validates source-expression grammar, and records
ignored values/reporting parameters without suppressing valid policy data.

## Integration, bounds and privacy

`httpclient` captures analysis immediately after receiving response headers and
before reading the body. A body failure retains header evidence; a failure before
headers returns `capture_unavailable` with no missing-header claims.

The analyzer retains only the ten tracked fields, at most 16 values per field,
4,096 bytes per value and 32,768 bytes overall. Content-Type inspection is capped
at 1,024 bytes. Truncation suppresses semantic parsing for that field. Explicit
evidence replaces invalid UTF-8, control and Unicode format characters; valid HTAB
can still participate in field-specific parsing. Parsed output and raw accessors
return independent copies.

Raw values are available only through `Report.Values`. Default report formatting
does not expose them, and default HTTP Response formatting/JSON excludes the entire
header analysis. Parsed strings remain untrusted and require output-context
escaping.

## Validation executed

Fresh `go test -count=1 -json -coverprofile coverage-phase6.out ./...`: PASS.
281 passing test/subtest completion records; 0 failed and 0 skipped. 89 top-level
test/fuzz-target completion records. Go statement coverage: headeranalysis 90.1%,
httpclient 94.8%, network 92.5%, tlsanalysis 97.1%, total 92.1%. These are not
branch coverage percentages.

`go vet ./...`: PASS. FuzzAnalyze: 204,395 executions, PASS (10-second requested
campaign, approximately 11.6 seconds including startup/shutdown). `gofmt -l .`
returned no paths. `go mod verify` returned `all modules verified`. Bundled runtime:
go1.27.1 windows/amd64. No dependency or runtime upgrade was made.

Tests cover capture availability, deterministic mixed-case maps, HTML/JSON/redirect/
204/304/unknown context, secure-context applicability, field duplicate and fallback
rules, quoted HSTS and extension directives, HTAB/control handling, RFC 9651 types
and malformed values, Permissions source expressions, evidence budgets, deep-copy
ownership, default-output privacy and HTTP/TLS/body-failure integration. Fixtures
remain local; no public target assessment was performed.

## Independent review

The first read-only review found no Critical issues and identified HSTS quoted/
duplicate handling, partial Structured Fields parsing, HTAB semantics and 304
classification as Important. Corrections and regressions were added. A second pass
found two remaining HSTS/Permissions-Policy semantic cases; those were corrected.
The final focused review reported no Critical or Important findings and assessed
the phase Ready: Yes. The reviewer did not execute tests; execution evidence above
belongs to the primary agent.

## Limitations

- `go test -race ./...` with CGO_ENABLED=1 was attempted and is **blocked**, not
  PASS: the host has no `gcc` C compiler. Race-detector validation remains due in a
  supported environment.
- Bounds limit retained and parser input, but do not claim a strict process RSS or
  CPU ceiling for the Go HTTP/runtime layers.
- Permissions-Policy does not maintain a browser-specific registry of currently
  supported features or compute an origin-relative effective policy.
- CSP directives and XFO/frame-ancestors correlation are deferred to Phase 8.
  Absence of Permissions-Policy, COOP, CORP or COEP is not a universal weakness.
- Parsed and raw header strings are untrusted. No reporting/UI escaping layer or
  findings catalog exists yet.

## Artifacts and next phase

`artifacts/phase6` contains tests.jsonl, coverage.txt, vet.txt, fuzz.txt, race.txt,
environment.txt and modules.txt. `coverage-phase6.out` contains the statement
profile. Implementation is in `internal/core/headeranalysis` plus the existing
`httpclient` adapter. Documentation is in header-analysis.md, architecture.md,
http-client.md, threat-model.md, README and this report.

Next: **Phase 7 — Cookie Analysis**, not implemented in this delivery.
