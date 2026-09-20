# Phase 19 report — adversarial regression

Date: 2026-09-20. The report preflight now rejects duplicate object member
names, including case-folded aliases that Go's JSON decoder could otherwise
interpret as the same field. Before the fix, the new focused test demonstrated
that both exact and case-folded duplicates passed preflight; after the fix,
they return a safe malformed-report error. The 64-member object limit remains
tested with unique member names.

Adversarial dashboard tests now cover encoded asset traversal, encoded slashes,
double-slash paths, alternate Host values, null and foreign Origins and a
foreign loopback port. The CLI's combined 20-redirect/three-probe budget
rejects 23 reserved requests before any network hit and accepts the exact
24-request ceiling. A valid synthetic report containing
`<svg onload=alert(1)>` was opened in Spanish: the string appeared as text in
Overview and Findings, the DOM contained no matching SVG node or external
links, and the browser console had no warnings or errors. The changed finding
kept its original prose with a visible translation fallback.

## Recorded gate

Raw outputs and exit codes are in `artifacts/phase19`; `summary.json` contains
the package and statement-coverage totals.

| Check | Result |
|---|---|
| Strict TypeScript, catalog export, Vite bundle and catalog audit | PASS |
| `go fmt ./...`, `go vet ./...`, `go mod verify` | PASS |
| `go test -count=1 -json -coverprofile=coverage-phase19.out ./...` | PASS; 17 packages, 342 top-level tests, 848 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 87.5% (4133/4721) |
| Linux/amd64 CGO-disabled cross-build | PASS |
| `go test -race` on local Windows | BLOCKED: `gcc` absent; Linux CI gate remains required |

The reporting fuzz target includes one valid document and four malformed or
hostile seeds. A 20-second run with two workers reported 4,130 executions and
18 new interesting inputs, no crash. Progress plateaued after the first few
seconds; the run does not establish a strict CPU or memory limit for arbitrary
JSON or browser rendering. The parser enforces an 8 MiB input cap, bounded
nested shapes, typed validation and safe error classes. No public target was
scanned.
