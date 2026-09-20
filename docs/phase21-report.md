# Phase 21 report — public documentation

Date: 2026-09-20. Four entry READMEs now describe the implemented product in
English, Spanish, Russian and Simplified Chinese. They share the same safe
quick start, authorized-use condition, private-target opt-in, platform CA
requirement, report privacy contract and limits on findings, score and diff.
Focused guides cover installation, development, security and the portfolio
case study. The current architecture, reporting, scoring, CORS, redirect,
dashboard and CLI docs were corrected where phase-specific future-tense text
had become stale; historical phase reports and specs remain historical records.

The local Markdown link check found 96 valid local links across 78 files and
zero broken targets. The documented `version`, Spanish `diff`, exact `npm ci`
and frontend build commands ran successfully. The local browser dashboard and
scan commands had already been exercised against synthetic fixtures; no
public target was used. The CI workflow now runs the link check and was
validated again by actionlint with exit 0.

## Recorded gate

The raw Phase 21 gate is under `artifacts/phase21`: 17 Go packages, 342
top-level tests, 848 pass events, zero fail/skip, 87.6% weighted Go statement
coverage (4136/4721), plus frontend build, catalog audit, docs links, format,
vet and module verification. The local race attempt is still blocked by the
missing C compiler; the published Linux CI run is the release gate.
