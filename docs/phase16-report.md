# Phase 16 report — local dashboard backend

Date: 2026-09-20. `sentinelhttp serve REPORT.json [--no-open]` now validates one
bounded report before binding a random `127.0.0.1` port and serving an
immutable JSON snapshot at `/api/report`. The index is a local placeholder for
Phase 17. The browser opens by default through a fixed platform command;
`--no-open` is available for terminal/test use. Ctrl+C cancels the server.

The server has fixed routes, exact loopback Host and same-origin Origin checks,
no CORS grant, no-store/nosniff/no-referrer/deny-frame headers and a restrictive
CSP. It cannot select arbitrary files or initiate scans. The socket guard has
one exact exception for this inbound loopback listener; the existing network
boundary remains the only outbound scan dial owner. Independent read-only
review found no Critical or Important issue.

## Recorded gate

Pinned workspace Go 1.27.1 on Windows/amd64. Raw outputs and native exit
codes are under `artifacts/phase16`; `summary.json` has counts.

| Check | Result |
|---|---|
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase16.out ./...` | PASS, exit 0; 15 packages, 332 top-level tests, 829 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 88.4% overall; dashboard 87.3% |
| `go vet ./...` | PASS, exit 0 |
| `go mod verify` | PASS, exit 0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS, exit 0 |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, local `gcc` absent |

The dashboard is unauthenticated over loopback by design. A local process can
read it while running. Linux CI must provide the race gate before release.

Next: **Phase 17 — bundled local dashboard frontend**.
