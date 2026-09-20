# Phase 12 report — Configuration Score

Date: 2026-09-20. The pure `internal/core/scoring` package evaluates one
chosen primary response. It returns an integer Configuration Score only when
at least two scored domains and 50 weight points have complete, applicable
evidence. Otherwise JSON contains `value: null` and an explicit
`insufficient_evidence` status. Four ordered components show assessed,
not-applicable or unavailable coverage and fixed rule penalties. CORS probes,
redirect journeys and other paths do not influence this score.

The architecture self-review is in `docs/architecture-self-review.md`.
Scoring stays above the HTTP client and finding engine; it does not add a
network path. The exact formula, weights and limitations are in
`docs/scoring.md`.

An independent read-only review found one Important issue: CSP could appear
assessed when its analyzer omitted observations at the 64-entry cap. A revised
regression fills that cap with non-scored observations, leaves the finding
engine untruncated and demonstrates an inflated 100/100 without the fix. The
scorer now requires an untruncated CSP report. A separate self-audit regression
found that malformed MIME context could earn the entire header-domain weight
through HSTS alone; known content context is now required. Re-review found no
remaining Critical or Important issues.

## Recorded gate

The gate uses pinned workspace Go 1.27.1 on Windows/amd64 with the configured
workspace module/build caches. Raw command output and native exit codes are
under `artifacts/phase12`; machine-readable counts are in `summary.json`.

| Check | Result |
|---|---|
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase12.out ./...` | PASS, exit 0; 10 packages, 264 top-level tests, 683 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 91.2% overall; scoring package 85.7% |
| `go vet ./...` | PASS, exit 0 |
| `go mod verify` | PASS, exit 0 |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, exit 1 before compilation: `cgo: C compiler "gcc" not found` |

The race attempt is not a passing race test. The local integration fixtures
use HTTP/TLS servers and the existing private-target test policy; no public
Internet target was assessed. Coverage is statement coverage, not branch
coverage. Scoring arithmetic is deterministic for the same captured response,
but the score is a deliberately narrow configuration summary, not a claim of
site-wide security or exploitability.

Next: **Phase 13 — Reporting**, not implemented in this delivery.
