# SentinelHTTP — portfolio case study

**Problem.** A one-line header checker can turn missing or malformed evidence
into an overconfident conclusion. A network diagnostic that follows redirects
or trusts a DNS name after validation can also escape the operator's intended
scope. SentinelHTTP explores how to make both mistakes harder in a compact,
reviewable local tool.

**Product.** The Go CLI captures one bounded HTTP/HTTPS response by default.
Optional redirect tracing and three uncredentialed CORS samples use one
request budget. Pure analyzers produce separate TLS, header, cookie, CSP and
CORS evidence. A fixed finding catalog states observations with confidence and
limitations. A versioned JSON report feeds terminal/Markdown/HTML views,
conservative semantic diffing and a locally bundled React/TypeScript panel.
Human copy is available in English, Spanish, Russian and Simplified Chinese;
the interchange JSON is language-neutral.

**Key decisions.** Scope approval and socket dialing live together in one Go
package. Each request is approved again and the actual peer is checked. The
HTTP adapter does not inherit environment proxies, implicit redirects, reuse
or retries. Evidence is copied and bounded before analysis. The report
projects only needed fields and separates unavailable, truncated and
not-applicable states. The score refuses to emit a number without sufficient
assessed coverage. Diffing treats redacted paths and incomplete traces as
unknown. The dashboard consumes validated local files only and cannot scan.

**Security tradeoffs.** The report intentionally omits paths, queries and
cookie values, so it cannot prove two arbitrary endpoints were identical; diff
is limited to compatible root scans. On Windows/macOS/iOS, HTTPS requires an
explicit PEM CA bundle to keep native issuer retrieval outside the approved
network path. That costs convenience but preserves a reviewable boundary.
The local dashboard is unauthenticated on loopback; users should close it
after use. Findings are configuration observations, not proof of exploitation.

**Evidence.** Local fixtures and fake DNS/dialers exercise scope decisions,
timeouts, hostile HTTP, privacy projections and output escaping without
scanning public targets. Phase 19 added parser fuzzing and a browser check
with injected markup rendered as text. The release gate recorded 342 passing
top-level Go tests across 17 packages, 87.6% weighted statement coverage,
zero findings from point-in-time npm and Go vulnerability audits, and a
deterministic frontend/catalog rebuild. The published
[Linux CI run](https://github.com/V0id47/sentinelhttp/actions/runs/35504147285)
passed the race detector and dependency gates.

**Next review areas.** Maintaining special-use IP classifications, PSL and
trust roots; validating the CI race/dependency gates on each change; and
expanding protocol coverage only if the new path can preserve the existing
single-owner network and evidence model. The project deliberately omits
authenticated scanning, crawling and exploit claims.

The [architecture self-review](architecture-self-review.md) records concrete
risks found and resolved during development. The [threat model](threat-model.md)
and [release report](phase22-report.md) contain the detailed decisions and
gate evidence. [Dashboard screenshots](screenshots.md) and the
[interview review](interview-review.md) use local synthetic evidence.
