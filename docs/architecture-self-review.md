# Architecture self-review — v0.1.0

Date: 2026-09-20. Scope: the implemented scanner, report consumers, dashboard,
four locales and release pipeline. This is a critical design assessment, not a
claim that a configuration scan proves a host secure.

## Assessment

The architecture is coherent for the v0.1.0 scope. One package, `network`, owns
outbound scope approval and the actual dial. `httpclient` uses that boundary and
does not inherit environment proxies, implicit redirects, retries, connection
reuse or decompression. Redirects and CORS probes are opt-in, serial and charged
against one request budget. The actual peer is checked at connection time, so
DNS approval is not treated as permanent authorization. The dashboard has a
separate, loopback-only inbound listener and cannot start a scan. This is the
project's strongest decision: a reviewer can find the network authority in a
small part of the codebase.

Captured, bounded evidence flows one way into TLS, header, cookie, CSP, CORS
and redirect analysis, then the finding catalog and score. Report projection
removes paths, queries, bodies, cookie values and raw redirect destinations.
The common versioned JSON schema feeds terminal/Markdown/HTML renderers,
semantic diff and the dashboard. These consumers do not open outbound sockets.
Unavailable, truncated and not-applicable evidence remain distinct; the score
requires sufficient assessed coverage and a finding states its own limits.
The diff refuses to equate redacted endpoint identities, comparing compatible
queryless-root scans only.

The trust boundary on report import is stronger after adversarial review:
eight-megabyte and structural caps, exact and case-folded duplicate-key
rejection, typed validation, safe text/HTML rendering and a browser that treats
report fields as text. This rejects ambiguous JSON interpretations, but a
valid report is still **untrusted data**, not proof of origin. The local
dashboard constrains Host and Origin, serves bundled assets under a restrictive
CSP and has no browser upload, scan target or arbitrary file route. Four
locales translate only exact catalog ID/version/source narrative matches;
unknown or tampered text stays visible as untrusted source text.

## Residual risks and deliberate limits

| Priority | Residual issue | Current control and future review |
|---|---|---|
| High | Special-use IP ranges, public suffix data and trust roots change over time. | Keep these inputs current and review any classification change against the scope and verified-dial tests. |
| High | Native trust-store chain retrieval on Windows, macOS and iOS would bypass the owned network path. | HTTPS requires an explicit PEM CA file on those platforms. Documented preflight fails closed; a future offline native-root strategy needs a separate design and test gate. |
| Medium | Local reports disclose origin, certificate and cookie-name metadata despite redaction. | CLI writes a new protected file atomically, including a private Windows DACL. Users must protect exported copies and close the unauthenticated loopback dashboard after use. |
| Medium | A locally forged but internally valid report can change findings or a dashboard view. | Parser validates shape and consistency only. Do not label a report authenticated without adding a separate signature/provenance protocol. |
| Medium | Conservative diff cannot compare arbitrary paths or incomplete redirects without disclosing more metadata. | Keep `unknown` results rather than inferring equality; changing identity rules needs an explicit privacy review. |
| Medium | A 256-position finding input cap can omit a later valid response after many duplicates. | Omitted/truncated counts prevent a complete score; retain the bound and test any future increase for cost. |
| Medium | Frontend catalog and embedded Vite assets can drift from Go source. | CI installs from the lockfile, regenerates all five artifacts and rejects a Git diff. Review source and generated output together. |
| Low | Parser fuzzing was brief and reached a plateau. | Keep deterministic hostile fixtures and expand fuzz duration/corpus when parser rules change; fuzz success is not a resource guarantee. |
| Low | GitHub Actions and the runner are external release dependencies. | Read-only CI permissions, no persisted checkout credentials, dependency audits and a green Linux race run are release gates. Review action revisions and runner migrations regularly. |

The Windows-only protected-file adapter uses `syscall`/`unsafe` and is the sole
exception to the source guard against new socket-capable imports. Keep that
file small and review any edit to it independently. The report schema and
finding catalog are versioned because changing either can affect historical
comparison and translation. No public-target scan or exploitation test was
used as release evidence.

## Release verdict

The [release readiness matrix](release-readiness.md) and
[Phase 22 report](phase22-report.md) record a clean clone, local gate, visual
checks and the published Linux CI run. The architecture is suitable for a
bounded, authorization-first portfolio tool at v0.1.0. Its conclusions remain
configuration observations over collected evidence, not comprehensive
security assurance.
