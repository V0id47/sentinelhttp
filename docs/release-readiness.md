# v0.1.0 release readiness

Date: 2026-09-20. This is the v0.1.0 acceptance matrix. The initial published
commit `06570363c7312e7c9fb011393cfe0327923913d5` passed the full
[Linux CI run](https://github.com/V0id47/sentinelhttp/actions/runs/35504147285).
Checks use local synthetic fixtures, not public targets.

| Gate | State before publication | Evidence / remaining condition |
|---|---|---|
| Authorized scope and SSRF boundary | PASS locally | [Network safety](network-safety.md), [SSRF model](ssrf-model.md), socket-ownership and peer tests |
| Bounded HTTP/TLS, redirects and CORS probes | PASS locally | [Threat model](threat-model.md); HTTPS on Windows/macOS/iOS still requires explicit PEM CA roots |
| Findings, score and report privacy | PASS locally | [Reporting](reporting.md), [scoring](scoring.md), parser fuzzing and projection tests |
| Conservative diff | PASS locally | [Diff contract](diff.md); root-only identity and unknown cases remain intentional |
| Local dashboard and four locales | PASS locally | 1366 px desktop and 390 px mobile Overview/Diff visual checks; mobile body width stayed within viewport; [localization](i18n.md) |
| Reproducible frontend/catalog artifacts | PASS locally | Five generated files matched SHA-256 before/after regeneration; CI rejects drift |
| Dependency and workflow audit | PASS locally | Phase 20 `npm audit` zero known vulnerabilities, `govulncheck` none found, actionlint exit 0; [hardening report](phase20-report.md) |
| Documentation | PASS | Four READMEs, install/development/security/case study and release notes; 115 valid local links across 54 published Markdown files |
| Go race detector on Linux | PASS | CI run 35504147285 completed successfully, including `go test -race ./...`; local Windows lacks `gcc` |
| Reviewed public Git file set | PASS | 203-file initial commit reviewed before push; no caches, reports, private keys, `.env` files or local plans; common secret-pattern scan found no matches |
| Clean checkout | PASS | Local clone of the committed tree: lockfile `npm ci`, Go tests, docs link check and regenerated catalog/assets with zero Git diff |
| GitHub publication | PASS | Public [repository](https://github.com/V0id47/sentinelhttp) on `main`; initial commit and green CI linked above |

The local Phase 21 gate recorded 342 top-level Go tests across 17 packages,
848 pass events, zero fail/skip and 87.6% weighted Go statement coverage.
Coverage is not a security guarantee. A successful report or score covers only
the operations actually performed; validation does not attest report origin.
The [architecture self-review](architecture-self-review.md) tracks the residual
risks and deliberate limits.
