# Phase 18 report — four-language presentation

Date: 2026-09-20. English, Spanish, Russian and Simplified Chinese now cover
CLI help and safe error descriptions, human report renderers, shipped finding
narratives and dashboard chrome. `--lang` selects CLI presentation; the
dashboard has a local selector. The canonical JSON schema, technical tokens and
target-controlled evidence remain unchanged. Unknown or modified finding prose
uses the original text with a visible fallback warning rather than a guessed
translation.

The browser was checked at mobile width in Russian, Simplified Chinese and
Spanish, including Findings. A valid adversarial report with changed finding
text and a noncatalog limitation displayed those strings unmodified and showed
the fallback warning. No horizontal overflow was observed. Independent review
identified truthfulness and escaping issues; the exact-match rule guard,
locale dates, raw evidence handling, inherited-key guard and fixed limitation
allowlist were corrected and reviewed again.

## Recorded gate

Raw command output and exit codes are in `artifacts/phase18`; `summary.json`
contains package and coverage totals.

| Check | Result |
|---|---|
| Strict TypeScript, catalog export and bundled Vite build | PASS |
| Catalog coverage audit | PASS; 77 distinct finding phrases covered |
| `go fmt ./...` | PASS |
| `go test -count=1 -json -coverprofile=coverage-phase18.out ./...` | PASS; 17 packages, 339 top-level tests, 836 pass events, 0 fail, 0 skip |
| Weighted Go statement coverage | 87.6% (4129/4716) |
| `go vet ./...`, `go mod verify` | PASS |
| Linux/amd64 CGO-disabled cross-build | PASS |
| Local `go test -race` | BLOCKED: `gcc` is absent on the Windows workstation; Linux CI is a Phase 20 release gate |

No public Internet target was scanned. The browser QA reports are observations
of local, synthetic fixtures, not claims of exhaustive UI coverage.
