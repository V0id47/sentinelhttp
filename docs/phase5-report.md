# SENTINELHTTP PHASE 5 REPORT

Date: 2026-09-16. Gate: **PASS WITH LIMITATIONS**.

## Scope delivered

Pure TLS analysis of the existing strict HTTP-client handshake. Bounded subject,
issuer, supported SANs, SHA-256, UTC validity, floor days remaining, 30-day expiry
observation, presented and verified chains. Explicit verified/unverified/unavailable
states; HTTP has not_applicable. Existing typed certificate errors preserved.
No new connections, insecure retries, downgrade probes, revocation/issuer URL
fetches, findings engine or features from Phase 6 onward.

## Integration and privacy

httpclient captures evidence before discarding a TLS error and returns immediately
on handshake failure. Certificate text remains outside default response formatting
and JSON. TLSAnalysis returns independently owned nested slices. Analysis cannot
open sockets or change Boundary policy. Runtime CertificateVerificationError is
the source of unverified certificates, without turning failed validation off.

## Validation executed

Fresh `go test -count=1 -json -coverprofile=coverage-phase5.out ./...`: PASS.
219 passing test/subtest completion records; 0 failed and 0 skipped. 67 top-level
tests/fuzz targets. Go statement coverage: tlsanalysis 97.1%, httpclient 94.6%,
network 92.5%, total 94.0%. These are not branch coverage percentages.

`go vet ./...`: PASS. FuzzDisplayText: 429,675 executions, PASS (10-second requested
campaign, approximately 11 seconds including shutdown). Tests use local ephemeral
CA fixtures and controlled inputs; no public target assessment.

Bundled runtime: go1.27.1 windows/amd64. `gofmt -l` reports no unformatted files;
`go mod verify` confirms all modules. No dependency or runtime upgrade this phase.

New tests cover trusted, unknown-authority, hostname mismatch, expired and future
certificates; no HTTP after failed validation; independent copies and default
JSON/fmt privacy; exact/negative/far-future dates; missing evidence; supported SAN
types; hostile control/format text; chain and SAN truncation. Local TLS fixtures
verify 300 SANs / 20 presented certificates and runtime rejection of a certificate
message above 256 KiB. Existing Phase 3/4 regression and AIA trap tests still pass.

Initial tests failed because Capture/TLSAnalysis were absent, then passed after
implementation. During test construction, a Nanosecond constant typo and an
accepted-size fixture accidentally above the runtime cap were corrected. Neither
was a production defect or a relaxed production safety limit.

## Independent review

Read-only review of analysis, client integration, ownership and privacy found no
material defects. Reviewer suggested expanding the canary from JSON to fmt output;
that regression is now included and passing. Reviewer did not independently
execute tests; execution evidence above belongs to the primary agent.

## Limitations

- `go test -race ./...` attempted with CGO_ENABLED=1: blocked by missing gcc, not
  PASS. Runtime race detection remains outstanding in a supported environment.
- Retained evidence caps do not establish an RSS ceiling; parsing and temporary
  rendering allocations precede summary limits. No exhaustive ASN.1 audit claimed.
- Runtime and platform validation was performed on Windows only. Explicit CA PEM
  requirement remains on Windows/macOS/iOS. Revocation is not checked.
- Certificate text from the explicit accessor remains untrusted, potentially
  sensitive and requires output-context escaping. No reporting engine exists yet.

## Artifacts and next phase

artifacts/phase5 contains tests.jsonl, coverage.txt, vet.txt, fuzz.txt, race.txt and
environment.txt.
coverage-phase5.out holds the statement profile. Historical phase artifacts remain.
Implementation: internal/core/tlsanalysis and the existing httpclient adapter.
Documentation: phase5-plan.md, tls-analysis.md, this report, README and architecture.

Next: **Phase 6 — Header Analysis**, not implemented in this delivery.
