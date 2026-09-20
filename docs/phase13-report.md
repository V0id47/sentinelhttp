# Phase 13 report — Versioned reporting

Date: 2026-09-20. `internal/core/reporting` now builds a bounded, privacy-
minimized JSON document from captured evidence without performing I/O. The
document includes the selected primary response, narrow analyzer summaries,
redirects, optional CORS probe attempts, versioned findings, a nullable
Configuration Score, omission counts and explicit limitations. It has strict
`Parse`/`Validate` ingress and safe terminal, Markdown and standalone HTML
renderers. The schema and privacy contract are in `docs/reporting.md`.

The architecture self-review is in `docs/architecture-self-review.md`. The
reporting package remains above the network and HTTP client; no secondary
socket path was added. JSON is the single interchange boundary for the planned
CLI, diff engine and dashboard. The report validator checks internal
consistency, including evidence provenance and score penalties, but does not
authenticate saved files or claim that observations are true.

Independent review found several inconsistencies in the first implementation:
oversized nested arrays before typed decode; unbounded probe failure text;
redirect/evidence and score catalog drift; hidden cookie omissions; raw CSP
directive names; and indexed evidence pointing at unrelated cookie/CSP items.
Those were fixed with a bounded streaming preflight, fixed code/name
vocabularies, semantic cross-checks and adversarial regression tests. A final
review found a valid edge case in score reconciliation: a finding may exist in
an unavailable score domain. The reconciliation now applies only to assessed
domains; an HTTPS integration test covers that case. Scoped re-review found no
remaining Important issue.

## Recorded gate

The gate uses pinned workspace Go 1.27.1 on Windows/amd64 with workspace
module/build caches. Raw output and exit codes are under `artifacts/phase13`;
machine-readable counts are in `summary.json`.

| Check | Result |
|---|---|
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase13.out ./...` | PASS, exit 0; 11 packages, 298 top-level tests, 788 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 89.8% overall; reporting package 83.6% |
| `go vet ./...` | PASS, exit 0 |
| `go mod verify` | PASS, exit 0 |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, exit 1 before compilation: `cgo: C compiler "gcc" not found` |

The race attempt is not a passing race test. Local integration fixtures use
HTTP/TLS test servers under the explicit private-target test policy; no
public Internet target was assessed. Coverage is statement coverage, not
branch coverage. The release gate must include Linux CI race testing.

Next: **Phase 14 — CLI and bounded scan orchestration**.
