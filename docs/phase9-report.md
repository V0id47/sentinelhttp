# Phase 9 report — CORS Analysis

Date: 2026-09-19
Status: complete — independent security re-review clean

Phase 9 adds bounded passive CORS response analysis and an explicit operation
that samples two fixed origins and one preflight. All probes pass through a fresh
target-scope approval and verified connection, use one shared timeout, stop at
response headers, and send no credentials. The report records observations and
conditional risks rather than confirmed browser exposure. The behavior and its
limits are defined in [CORS analysis](cors-analysis.md).

## Recorded gate

The repeatable gate is `artifacts/phase9/run-gate.ps1`. It used pinned Go 1.27.1
on windows/amd64 with the workspace's Go build and module caches. Native exit
codes and full outputs are saved in `artifacts/phase9/`.

| Check | Native exit code | Result |
|---|---:|---|
| `go fmt ./...` | 0 | PASS |
| `go test -count=1 -json -coverprofile=coverage-phase9.out ./...` | 0 | PASS |
| `go tool cover -func=coverage-phase9.out` | 0 | PASS |
| `go vet ./...` | 0 | PASS |
| `go mod verify` | 0 | PASS — all modules verified |
| `FuzzAnalyze`, 10 seconds | 0 | PASS — 161,341 executions |
| `FuzzInvalidValuesAreNotRetained`, 10 seconds | 0 | PASS — 229,735 executions |
| `CGO_ENABLED=1 go test -race ./... -count=1` | 1 | BLOCKED — `gcc` absent from `PATH` |

The JSON stream records **220 top-level passes**, 0 failures and 0 skips; it
records **574 passing test events** including subtests and fuzz seeds, 0 failures
and 0 skips. All seven packages passed. The reproducible event and coverage
summary is `artifacts/phase9/summary.json`.

| Package | Passing test events |
|---|---:|
| `cookieanalysis` | 66 |
| `corsanalysis` | 64 |
| `cspanalysis` | 147 |
| `headeranalysis` | 59 |
| `httpclient` | 87 |
| `network` | 138 |
| `tlsanalysis` | 13 |

## Statement coverage

Coverage is weighted by statement counts in `coverage-phase9.out`; it is Go
statement coverage, not branch coverage.

| Package | Covered / statements | Coverage |
|---|---:|---:|
| `internal/core/cookieanalysis` | 424 / 467 | 90.8% |
| `internal/core/corsanalysis` | 287 / 327 | 87.8% |
| `internal/core/cspanalysis` | 568 / 607 | 93.6% |
| `internal/core/headeranalysis` | 563 / 625 | 90.1% |
| `internal/core/httpclient` | 257 / 272 | 94.5% |
| `internal/core/network` | 270 / 292 | 92.5% |
| `internal/core/tlsanalysis` | 100 / 103 | 97.1% |
| **Total** | **2,469 / 2,693** | **91.7%** |

## Review and limits

The independent review found no Critical issue. Its two Important findings were
fixed with RED/GREEN regressions: malformed or truncated allow-methods can no
longer produce a positive preflight assessment, and `s-maxage=0` now overrides a
positive `max-age` for shared-cache context. Further regressions reject
noncanonical numeric origins, distinguish canonical from dotted IPv4-mapped
IPv6, and classify a 304 preflight as non-OK rather than as a redirect. The
second review found no remaining security issue; the full functional suite
passed again. No Git commit or GitHub publication is part of this phase because
the workspace is not a Git repository; publication is planned after the full
project is finished.

The 10-second fuzz campaigns covered deterministic analysis and exclusion of
invalid raw values. They passed, but neither fuzzing nor the local fixture tests
prove behavior against every server or browser. The probe uses two origins and
one preflight shape; it does not issue an authenticated request, execute a
browser, inspect sensitive response data, follow redirects, or prove exposure.
The cache predicate is intentionally narrow and can miss other cacheable cases.
Input and retention bounds do not impose strict CPU or RSS ceilings.

Race testing was attempted with cgo enabled and failed before package tests
because Go reported `cgo: C compiler "gcc" not found`. This is **BLOCKED**, not a
passing race result. `artifacts/phase9/race.txt` and `race.exit.txt` preserve
the exact evidence.

## Post-documentation verification

After this report was written, the final gate is recorded in
`artifacts/phase9/final-tests.txt`, `final-vet.txt`, `final-gofmt.txt` and
`final-mod-verify.txt` with matching native exit-code files. Completion requires
all four commands to exit 0 and `final-gofmt.txt` to be empty.

Next: **Phase 10 — Redirect Analysis**, not implemented in this delivery.
