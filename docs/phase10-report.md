# Phase 10 report — Redirect Analysis

Date: 2026-09-19
Status: complete — independent security review found no Critical or Important issue

Phase 10 adds an opt-in, bounded GET redirect trace. Each attempted hop runs
through a fresh target approval and verified connection, captures response
headers without reading the body, and records a partial trace if a later
request fails. It follows only 301, 302, 303, 307 and 308; it blocks
HTTPS-to-HTTP before another connection. The contract and scope limits are in
[redirect analysis](redirect-analysis.md).

## Recorded gate

`artifacts/phase10/run-gate.ps1` used pinned Go 1.27.1 on windows/amd64 with
the workspace build and module caches. Native exit codes and full output are
saved under `artifacts/phase10/`.

| Check | Native exit code | Result |
|---|---:|---|
| `go fmt ./...` | 0 | PASS |
| `go test -count=1 -json -coverprofile=coverage-phase10.out ./...` | 0 | PASS |
| `go tool cover -func=coverage-phase10.out` | 0 | PASS |
| `go vet ./...` | 0 | PASS |
| `go mod verify` | 0 | PASS — all modules verified |
| `FuzzResolveLocation`, 10 seconds | 0 | PASS — 303,183 executions |
| `FuzzInvalidLocationNotReturned`, 10 seconds | 0 | PASS — 642,289 executions |
| `CGO_ENABLED=1 go test -race ./... -count=1` | 1 | BLOCKED — `gcc` absent from `PATH` |

The JSON stream records **234 top-level passes**, 0 failures and 0 skips;
**638 passing test events** including subtests and fuzz seeds, 0 failures and
0 skips. All eight packages passed. The reproducible count and coverage
summary is `artifacts/phase10/summary.json`.

| Package | Passing test events |
|---|---:|
| `cookieanalysis` | 66 |
| `corsanalysis` | 64 |
| `cspanalysis` | 147 |
| `headeranalysis` | 59 |
| `httpclient` | 113 |
| `network` | 138 |
| `redirectanalysis` | 38 |
| `tlsanalysis` | 13 |

## Statement coverage

Coverage is weighted by statement counts in `coverage-phase10.out`; it is Go
statement coverage, not branch coverage.

| Package | Covered / statements | Coverage |
|---|---:|---:|
| `internal/core/cookieanalysis` | 424 / 467 | 90.8% |
| `internal/core/corsanalysis` | 287 / 327 | 87.8% |
| `internal/core/cspanalysis` | 568 / 607 | 93.6% |
| `internal/core/headeranalysis` | 563 / 625 | 90.1% |
| `internal/core/httpclient` | 325 / 341 | 95.3% |
| `internal/core/network` | 270 / 292 | 92.5% |
| `internal/core/redirectanalysis` | 22 / 23 | 95.7% |
| `internal/core/tlsanalysis` | 100 / 103 | 97.1% |
| **Total** | **2,559 / 2,785** | **91.9%** |

## Review and limits

The independent read-only security review found no Critical or Important
implementation issue. It confirmed approval and verified dialing at each hop,
pre-dial downgrade and same-host stops, shared deadline, and safe default
JSON/formatting. Its minor test coverage notes were addressed with trace-level
303/307/308, fragment-only, and same-host/different-port fixtures. A
subsequent RED/GREEN regression preserved `LocationStatus=valid` when a valid
URI-reference fails HTTP(S) target validation. Review notes are saved in
`.superpowers/sdd/2026-09-19-redirect-analysis/review.md`.

The default public-host boundary can follow a `Location` to another public
host. A caller whose authorization is limited to the initial host must set
`SameHost`. That option compares the canonical host only; it can follow a
redirect to another port on that host. The trace is not a same-origin or
same-service authorization check. Cross-host and scheme changes are
observations, not findings or proof of exploitability.

The local fixture suite and pure fuzz campaigns exercise bounded navigation,
privacy and error handling, but cannot cover every server response or browser
behavior. No public Internet scan was run. Race testing was attempted with
cgo enabled and failed before package tests because Go reported
`cgo: C compiler "gcc" not found`. It remains **BLOCKED**, with the exact
output and exit code in `artifacts/phase10/race.txt` and `race.exit.txt`.
There is no Git commit or GitHub publication in this phase because this
workspace is not yet a Git repository; publication follows completion of the
project.

## Post-documentation verification

After this report, the final gate is recorded in
`artifacts/phase10/final-tests.txt`, `final-vet.txt`, `final-gofmt.txt` and
`final-mod-verify.txt` with matching native exit-code files. Completion
requires all four commands to exit 0 and `final-gofmt.txt` to be empty.

Next: **Phase 11 — Finding Engine**, not implemented in this delivery.
