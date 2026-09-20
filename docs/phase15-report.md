# Phase 15 report — semantic diff

Date: 2026-09-20. `sentinelhttp diff OLD.json NEW.json` now parses two bounded,
versioned reports and emits a deterministic JSON or escaped terminal comparison
without network I/O. Stable findings, primary headers, root-path cookie
policy, TLS/certificate, CSP and complete one-response redirect state are
compared. Missing or ambiguous evidence is explicit `unknown`; different
origins and redacted initial paths are `incomparable`.

The architecture review found three additional Important risks: a public URL
hash could expose guessable paths/queries, cookie host-only scope was missing,
and origin-only redirect summaries could hide same-host path changes. The
hash was removed in favor of a root-or-redacted marker, host-only scope was
added to the cookie projection, and multi-hop redirect comparison now reports
unknown. Re-review found no remaining Critical or Important issue. This means
the first diff version is intentionally root-only; it does not claim changes
for arbitrary redacted paths or CORS probes.

The CLI rejects oversized or invalid inputs with safe error codes and writes
private, atomic no-clobber output. Adversarial tests cover failed captures,
truncation, cookie/redirect ambiguity, path privacy, terminal controls, input
caps and output conflicts. The pure diff engine does not import network I/O.

## Recorded gate

Pinned workspace Go 1.27.1 on Windows/amd64. Raw outputs and exit codes are
under `artifacts/phase15`; `summary.json` has machine-readable counts.

| Check | Result |
|---|---|
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase15.out ./...` | PASS, exit 0; 14 packages, 328 top-level tests, 825 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 88.8% overall; diffing 76.8% |
| `go vet ./...` | PASS, exit 0 |
| `go mod verify` | PASS, exit 0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS, exit 0 |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, `gcc` absent on this workstation |

Race testing must run in Linux CI before release. This phase does not
initialize Git or publish a release.

Next: **Phase 16 — local dashboard backend**.
