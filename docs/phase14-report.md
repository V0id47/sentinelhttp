# Phase 14 report — CLI and bounded scan orchestration

Date: 2026-09-20. `cmd/sentinelhttp` now exposes `version` and `scan` over a
small `internal/cli` coordinator. A default scan performs one GET; explicit
flags enable a bounded GET redirect trace and three uncredentialed CORS
probes. The CLI reserves their combined worst-case request count before any
network operation, uses one scope boundary and one scan-wide deadline, and
passes captured evidence to the Phase 13 report builder. The flags, exit
codes, output semantics and limitations are in `docs/cli.md`.

The architecture self-review is in `docs/architecture-self-review.md`. The
network boundary remains the only socket owner. The CLI adds process/file I/O
above the core without moving scans into reporting or the future dashboard.
Private-target mode now reports the effective same-host policy enforced by the
boundary. Windows report output applies a protected user/SYSTEM/Administrators
ACL before writing bytes; POSIX-like output uses mode `0600`.

Independent read-only review found two Important issues: persisted reports
could declare a request budget below their evidence, and private-target scans
could report `same_host:false` despite enforcing it. Both were reproduced by
tests and fixed. Re-review found no remaining Critical or Important issue.
The local socket-ownership test initially rejected the Windows ACL adapter's
`syscall` and `unsafe` imports; its exception now names that one file exactly.
The adapter must remain small and reviewed.

## Recorded gate

Pinned workspace Go 1.27.1 on Windows/amd64 with workspace build/module
caches. Raw output and native exit codes are under `artifacts/phase14`;
machine-readable counts are in `summary.json`.

| Check | Result |
|---|---|
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase14.out ./...` | PASS, exit 0; 13 packages, 312 top-level tests, 809 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 89.5% overall; CLI package 85.2% |
| `go vet ./...` | PASS, exit 0 |
| `go mod verify` | PASS, exit 0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS, exit 0 |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, exit 1 before compilation: `cgo: C compiler "gcc" not found` |

The race attempt is not a passing race test. Functional scans use local
HTTP/TLS fixtures and private-lab opt-in only; no public Internet target was
assessed. Statement coverage is not branch coverage. Linux CI must run race
testing before release. The product is not yet a Git repository or release.

Next: **Phase 15 — semantic diff of validated reports**.
