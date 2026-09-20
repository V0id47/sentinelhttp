# Phase 11 report — Finding Engine

Date: 2026-09-20. The approved Phase 11 design is implemented as the pure
`internal/core/findingengine` package. It turns selected, already captured
HTTP/TLS, header, cookie, CSP, CORS-probe and redirect evidence into 12
conservative versioned rules. Findings are grouped by rule and safe origin,
carry deterministic IDs and fixed explanatory text, and expose bounded opaque
evidence references. No scoring, CLI, network operation or renderer was added.

An independent read-only review found three Important issues: a redirect stop
could use a hop already omitted by the exchange cap, a caller-owned CORS report
could trigger unbounded slice cloning, and contradictory probe fields could be
promoted into risk findings. Each was reproduced with a failing regression,
fixed and re-reviewed. The re-review found no remaining Critical or Important
issues. It also caught a canonical-origin validation mismatch; the engine now
reuses `corsanalysis.ValidSerializedOrigin`, preserving legitimate varying
allowlist origins while rejecting noncanonical values. A failed or not-run
optional probe is not counted as an inconsistent input.

## Recorded gate

Run from the project root with `artifacts/phase11/run-gate.ps1`, then
`artifacts/phase11/summarize.ps1`. The Go binary was pinned workspace
Go 1.27.1 on Windows/amd64; `CGO_ENABLED` was 0 for the ordinary suite.
Native outputs and exit codes are retained in `artifacts/phase11`.

| Check | Result |
|---|---|
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase11.out ./...` | PASS, exit 0; 9 packages, 254 top-level tests, 673 pass events, 0 fail, 0 skip |
| Weighted statement coverage | 2,800 / 3,062 statements = 91.4% overall; finding engine 241 / 277 = 87.0% |
| `go vet ./...` | PASS, exit 0 |
| `go mod verify` | PASS, exit 0 |
| `FuzzStableFindingID`, 10 seconds | PASS, exit 0; 898,218 executions |
| `FuzzUnsafePathNeverEntersFindings`, 10 seconds | PASS, exit 0; 115,438 executions |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, exit 1: `cgo: C compiler "gcc" not found` |

The race attempt did not compile any package, so it provides no race-detector
result. Ordinary tests and fuzzing use only pure cases, fake dependencies and
local HTTP/TLS fixtures; no public Internet target was assessed. Coverage is
Go statement coverage, not branch coverage. The complete event summary is in
`artifacts/phase11/summary.json`, and the raw profile is
`coverage-phase11.out`.

## Limits carried forward

The engine accepts caller-owned evidence and performs consistency checks, not
cryptographic provenance checks. It inspects at most 256 exchange-slice
positions while seeking up to 32 distinct exchanges; many repeated entries
can cause a later valid exchange to be omitted and explicitly counted. At most
21 trace hops, 256 findings and 16 references per finding are retained. CORS
findings cover fixed synthetic, unauthenticated samples and never assert an
authenticated data leak. Redirect downgrade findings describe a proposed hop
blocked by SentinelHTTP. No finding proves an exploit or a site-wide state.

Next: **Phase 12 — Scoring**, not implemented in this delivery.
