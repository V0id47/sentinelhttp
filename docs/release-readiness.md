# v0.1.0 release readiness

Date: 2026-09-20. This is the v0.1.0 acceptance matrix. The final
code-bearing commit `c45b7f091b606f97396ada1bc92b3b97be847f29` passed
[Linux CI run 35505265003](https://github.com/V0id47/sentinelhttp/actions/runs/35505265003),
including ESLint, the Go race detector, dependency audits and full-history
Gitleaks. Checks use local synthetic fixtures, not public targets.

| Gate | State | Evidence / remaining condition |
|---|---|---|
| Authorized scope and SSRF boundary | PASS locally | [Network safety](network-safety.md), [SSRF model](ssrf-model.md), socket-ownership and peer tests |
| Bounded HTTP/TLS, redirects and CORS probes | PASS locally | [Threat model](threat-model.md); HTTPS on Windows/macOS/iOS still requires explicit PEM CA roots |
| Findings, score and report privacy | PASS locally | [Reporting](reporting.md), [scoring](scoring.md), parser fuzzing and projection tests |
| Conservative diff | PASS locally | [Diff contract](diff.md); root-only identity and unknown cases remain intentional |
| Local dashboard and four locales | PASS locally | 1366 px desktop and 390 px mobile Overview/Diff visual checks; mobile body width stayed within viewport; [screenshots](screenshots.md) and [localization](i18n.md) |
| Reproducible frontend/catalog artifacts | PASS locally | Five generated files matched SHA-256 before/after regeneration; CI rejects drift |
| Dependency and workflow audit | PASS locally | Phase 20 `npm audit` zero known vulnerabilities, `govulncheck` none found, actionlint exit 0; [hardening report](phase20-report.md) |
| Documentation | PASS locally | Four READMEs, install/development/security/case study, [interview review](interview-review.md), screenshot gallery and release notes; 144 valid local links across 56 published Markdown files |
| Frontend lint and Git history secrets | PASS | ESLint with TypeScript 6.0.3 passed; local Gitleaks v8.30.1 scanned 3 commits (~1.68 MB), no leaks; CI run 35505265003 passed both |
| Go race detector on Linux | PASS | CI run 35505265003 completed successfully, including `go test -race` on the 17 project packages; local Windows lacks `gcc` |
| Reviewed public Git file set | PASS | 203-file initial commit reviewed before push; no caches, reports, private keys, `.env` files or local plans; common secret-pattern scan found no matches |
| Clean checkout | PASS | Local clone of the committed tree: lockfile `npm ci`, Go tests, docs link check and regenerated catalog/assets with zero Git diff |
| GitHub publication | PASS | Public [repository](https://github.com/V0id47/sentinelhttp) on `main`; code-bearing commit and green CI linked above |

The local Phase 21 gate recorded 342 top-level Go tests across 17 packages,
848 pass events, zero fail/skip and 87.6% weighted Go statement coverage.
Coverage is not a security guarantee. A successful report or score covers only
the operations actually performed; validation does not attest report origin.
The [architecture self-review](architecture-self-review.md) tracks the residual
risks and deliberate limits.
