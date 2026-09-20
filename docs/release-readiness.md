# v0.1.0 release readiness

Date: 2026-09-20. This is the release-candidate acceptance matrix; a green
GitHub CI run and reviewed publication are required before declaring v0.1.0
released. Checks use local synthetic fixtures, not public targets.

| Gate | State before publication | Evidence / remaining condition |
|---|---|---|
| Authorized scope and SSRF boundary | PASS locally | [Network safety](network-safety.md), [SSRF model](ssrf-model.md), socket-ownership and peer tests |
| Bounded HTTP/TLS, redirects and CORS probes | PASS locally | [Threat model](threat-model.md); HTTPS on Windows/macOS/iOS still requires explicit PEM CA roots |
| Findings, score and report privacy | PASS locally | [Reporting](reporting.md), [scoring](scoring.md), parser fuzzing and projection tests |
| Conservative diff | PASS locally | [Diff contract](diff.md); root-only identity and unknown cases remain intentional |
| Local dashboard and four locales | PASS locally | 1366 px desktop and 390 px mobile Overview/Diff visual checks; mobile body width stayed within viewport; [localization](i18n.md) |
| Reproducible frontend/catalog artifacts | PASS locally | Five generated files matched SHA-256 before/after regeneration; CI rejects drift |
| Dependency and workflow audit | PASS locally | Phase 20 `npm audit` zero known vulnerabilities, `govulncheck` none found, actionlint exit 0; [hardening report](phase20-report.md) |
| Documentation | PASS locally | Four READMEs, install/development/security/case study; 104 valid local links across 52 published Markdown files |
| Go race detector on Linux | PENDING | Local Windows lacks `gcc`; require actual green GitHub CI run |
| Reviewed public Git file set | PENDING | Stage and inspect exact files, including secret-pattern audit, before push |
| GitHub publication | PENDING | Create `V0id47/sentinelhttp`, push and record commit/CI run |

The local Phase 21 gate recorded 342 top-level Go tests across 17 packages,
848 pass events, zero fail/skip and 87.6% weighted Go statement coverage.
Coverage is not a security guarantee. A successful report or score covers only
the operations actually performed; validation does not attest report origin.
