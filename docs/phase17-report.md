# Phase 17 report — bundled dashboard frontend

Date: 2026-09-20. The local dashboard now embeds a strict TypeScript React UI.
It reads only the validated `/api/report` snapshot and an optional server-side
`/api/diff` comparison. Views cover summary, findings and separated evidence
domains, request journey, diff, raw evidence and scan limits. The CLI accepts
`serve REPORT.json --compare OLD.json`; both reports are validated and the
semantic diff is computed before binding. The browser cannot choose files or
start a scan.

The frontend uses React text rendering for report-controlled strings and has
no remote assets or report-controlled links. Desktop (1366 and 1920 px),
tablet (800 px) and mobile (390 px) were reviewed in the local browser. The
mobile navigation is keyboard dismissible and focus contained; tested views
did not overflow horizontally and the browser console recorded no warnings or
errors. A synthetic pair of local reports showed four expected changes in the
Diff view. Independent review found and then verified fixes for two misleading
labels in request journey and incomplete cookie evidence. A subsequent bundle
rebuild made those source fixes effective in the served binary.

## Recorded gate

Pinned workspace Go 1.27.1 on Windows/amd64. Raw outputs and native exit
codes are under `artifacts/phase17`; `summary.json` contains the counts.

| Check | Result |
|---|---|
| Strict TypeScript and Vite production build | PASS; local embedded JS/CSS, no CDN |
| `go fmt ./...` | PASS, exit 0 |
| `go test -count=1 -json -coverprofile=coverage-phase17.out ./...` | PASS, exit 0; 15 packages, 333 top-level tests, 830 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 88.3% overall; dashboard 88.7% |
| `go vet ./...` and `go mod verify` | PASS, exit 0 |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` | PASS, exit 0 |
| Final Go tests, vet, format and module verification | PASS |
| `CGO_ENABLED=1 go test -race ./... -count=1` | BLOCKED, local `gcc` absent |

The first gate correctly rejected a temporary demo generator that imported
`net/http` outside the socket boundary. That generator was removed and the gate
rerun green. Phase 18 must localize the fixed UI and CLI explanatory text;
Phase 20 must add a Linux CI race gate before release.
