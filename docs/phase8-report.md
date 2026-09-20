# Phase 8 report — CSP Policy Analysis

Date: 2026-09-18
Status: complete — independent broad security review approved

Phase 8 delivers bounded, deterministic analysis of response-header
`Content-Security-Policy` and `Content-Security-Policy-Report-Only` evidence. It
uses the **W3C Content Security Policy Level 3 Editor's Draft 2026-09-16** baseline.
The implementation keeps enforced and report-only policies, header fields and
comma-separated serialized-policy-list members separate. It does not union source
lists, create findings/severity/scores, inspect a body/DOM, execute a browser,
perform CSP-related I/O or implement CORS.

## Final recorded gate

All commands used workspace-pinned Go 1.27.1, with build and module caches
under the local workspace root.

| Check | Native exit code | Result |
|---|---:|---|
| `gofmt -w internal/core/cspanalysis internal/core/httpclient internal/core/headeranalysis` | 0 | PASS |
| `go test -count=1 -json -coverprofile=coverage-phase8.out ./...` | 0 | PASS |
| `go tool cover -func=coverage-phase8.out` | 0 | PASS |
| `go vet ./...` | 0 | PASS |
| `go mod verify` | 0 | PASS — `all modules verified` |
| `go test ./internal/core/cspanalysis -run '^$' -fuzz '^FuzzAnalyze$' -fuzztime 10s` | 0 | PASS |
| `go test ./internal/core/cspanalysis -run '^$' -fuzz '^FuzzNonceHashPayloadsAreNeverRetained$' -fuzztime 10s` | 0 | PASS |
| `CGO_ENABLED=1 go test -race ./... -count=1` | 1 | BLOCKED — `gcc` not found on `PATH` |

The JSON test stream records 200 top-level passes, 0 top-level failures and 0
top-level skips. It records 502 passing test events including subtests, 0 failing
and 0 skipped events. All 6 packages passed: `cookieanalysis` (66 test events),
`cspanalysis` (147), `headeranalysis` (59), `httpclient` (79), `network` (138) and
`tlsanalysis` (13).

## Statement coverage

Coverage is measured from `coverage-phase8.out`, weighted by profile statement
counts. It is Go statement coverage, not branch coverage.

| Package | Covered / statements | Coverage |
|---|---:|---:|
| `internal/core/cookieanalysis` | 424 / 467 | 90.8% |
| `internal/core/cspanalysis` | 568 / 607 | 93.6% |
| `internal/core/headeranalysis` | 563 / 625 | 90.1% |
| `internal/core/httpclient` | 233 / 246 | 94.7% |
| `internal/core/network` | 270 / 292 | 92.5% |
| `internal/core/tlsanalysis` | 100 / 103 | 97.1% |
| **Total** | **2,158 / 2,340** | **92.2%** |

## Fuzz, race and environment

Both required 10-second fuzz campaigns passed. The saved output reports 125,891
executions for `FuzzAnalyze` and 53,735 for
`FuzzNonceHashPayloadsAreNeverRetained`; both finished `PASS` for
`sentinelhttp/internal/core/cspanalysis`. The privacy target checks that nonce/hash
payload canaries never enter JSON or formatting.

Race detection was attempted with `CGO_ENABLED=1`. It is blocked, not passed:
Go reported `cgo: C compiler "gcc" not found: exec: "gcc": executable file not
found in %PATH%`, and the packages consequently did not build for `-race`.
`artifacts/phase8/environment.txt` records Go 1.27.1 on windows/amd64, CGO enabled
for that attempt, and the workspace cache paths.

## Independent review and resolutions

The final broad re-review is **Approved** with no Critical, Important or Minor
findings; its ten-test matrix passed. The five original Important issues were
resolved with RED/GREEN regressions: truncated enforcement no longer creates
absence observations; partial policies retain structural/unaffected-control
observations; retained `frame-ancestors` preserves precedence; ancestor source
grammar is constrained; and retained ports own their bytes. The two original Minor
issues were resolved: object-control absence is not HTML-gated, and a trailing dot
is removed before applying the DNS-name limit.

Follow-up review corrections established that bare `*` is a valid
`frame-ancestors` host source, a later truncation cannot undo a complete retained
`frame-ancestors` precedence fact, and unrelated invalid/partial directives do not
block XFO fallback when complete frame-ancestors evidence establishes absence.
Truncation before/inside that directive and a discarded candidate remain
indeterminate. The complete review history is in
`.superpowers/sdd/2026-09-18-csp-policy-analysis/task-7-broad-review.md` and the
Task 7 implementation report.

## Artifact inventory and limits

`artifacts/phase8/` contains the JSON test stream, coverage, vet, module,
format, both fuzz, race, environment and post-documentation verification outputs,
each with a native exit-code record. `coverage-phase8.out` is at repository root.
The output artifacts, not redirection alone, establish the recorded results.

The remaining limits are intentional: header-delivered CSP only; no meta CSP,
body/DOM parsing, browser execution, concrete resource-URL matching,
report-endpoint interpretation, arbitrary multi-policy source-set intersection,
nonce-quality/reuse proof, XSS/clickjacking proof, findings, severity, score or
CORS analysis. Parser bounds are input/retention limits, not strict CPU or RSS
ceilings. The CSP baseline is an Editor's Draft and can change after the pinned
date.

## Post-documentation verification

After this final report was written, `go test ./... -count=1` exited 0, `go vet
./...` exited 0, and `gofmt -l internal` exited 0 with empty output. The complete
outputs and their native exit-code records are `artifacts/phase8/final-tests.txt`,
`final-vet.txt`, `final-gofmt.txt` and their corresponding `.exit.txt` files.

Next: **Phase 9 — CORS Analysis**, not implemented in this delivery.
