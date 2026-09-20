# Architecture self-review — 2026-09-20

Scope: the implemented Phase 3–21 product and the planned Phase 22 release.
This is a design assessment, not a claim that future components exist.

## What is sound today

The dependency direction is clear: `network` owns scope approval and the
actual dial; `httpclient` consumes that boundary; TLS, header, cookie, CSP,
CORS and redirect analyzers operate on captured inputs without new network
I/O; `findingengine` consumes their outputs. The HTTP transport has no
implicit proxy, redirect, retry, decompression or connection reuse. This
concentrates SSRF review in one boundary and keeps interpretation separate
from collection. Captured objects distinguish unavailable, complete and
truncated evidence; that distinction is essential for conservative findings.

The strongest existing architectural decision is the one-way data flow from
network operation to owned evidence to interpretation. Preserve it. The
dashboard must never become a second scanner or import internal HTTP client
behavior. CLI and dashboard should consume one versioned report schema.

Phase 13 tested this boundary with hostile persisted JSON. The narrow DTO and
strict parser reduce accidental disclosure and resource amplification, while
semantic validation ties indexed evidence and an available score to the
recorded primary response. This validation checks consistency, not whether a
report file is authentic; downstream diff and dashboard code must continue to
treat every field as untrusted. The reconciliation deliberately ignores score
domains marked unavailable, because a finding may still be observed there.

Phase 14 exposed a platform-specific file boundary: Go's `0600` mode does not
create a private Windows ACL. The CLI sets a protected DACL on the empty temp
file before writing report bytes and then atomically links it to the requested
new name. The socket-ownership source guard has one exact Windows-file adapter
exception for the required `syscall`/`unsafe` imports; that file must remain
small and independently reviewed for any future change.

Phase 15 exposed a privacy/comparability tradeoff. The report intentionally
does not retain paths or queries, and a public digest of them can be guessed
for short secrets. The diff therefore compares only queryless root scans of
the same origin. Scoped cookies and multi-hop redirect paths remain unknown
where the redacted report cannot establish identity. The dashboard must show
those unknowns clearly rather than interpreting silence as equivalence.

Phase 16 adds a separate inbound socket exception for a loopback-only Go
dashboard server. Its route handler consumes only prevalidated report bytes;
the scan boundary remains the sole outbound dial owner. The exact Host/Origin
gate and no-CORS policy must be kept when Phase 17 bundles assets. No server
route may accept a report path, URL, scan target or upload from a browser.

Phase 17 keeps browser interaction over the validated report API. React renders
untrusted report values as text and has no scan controls or report-controlled
links. The TypeScript source and the Go-embedded Vite assets must be rebuilt
together: review caught a stale bundle after two truthfulness corrections.
The source guard also caught a temporary demo generator that imported
`net/http` outside the approved socket packages; removing it restored the
boundary. This confirms the source guard is useful beyond production code.

Phase 18 adds a presentation layer without changing the report schema or
analyzer predicates. Both the Go renderers and React match finding rule ID,
catalog version and complete source narrative before translating. Unknown or
tampered prose stays as untrusted text with an explicit fallback. The shared
catalog export creates a build-time coupling: a release must rebuild the
frontend and verify the exported catalog before compiling Go. Exact-match
limitation translation likewise avoids turning attacker-controlled report text
into a trusted product message.

Phase 19 found that structural validation alone left a JSON interpretation
ambiguity: Go's decoder accepts duplicate and case-folded aliases, taking a
later value. Preflight now rejects either form before typed decoding. This
closes a cross-consumer disagreement risk while preserving the eight-megabyte,
depth and collection caps. Browser inspection of a valid hostile report showed
the injected markup as text, without a new SVG node or external link. Timed
fuzzing found no crash, but its plateau and short duration are not a hard
resource guarantee; the runtime/OS remain trusted and parser CPU/RSS limits
are still approximate.

Phase 20 confirmed that the platform CA restriction is an intentional
boundary decision, not a missing TLS option: native-root export or AIA
retrieval could move I/O outside the approved socket path. The explicit PEM
bundle remains the release behavior and must be prominent in installation
instructions. The source audit found no additional outbound socket owner or
frontend execution sink. CI now reconstructs both generated catalogs and
static assets from the lockfile, rejects drift, and includes Linux race and
online vulnerability gates. Its execution result is still pending GitHub
publication; a local cross-build does not substitute for a race run.

Phase 21 replaces the interim README with four language entry points and
checks their local links. Documentation now states the operational limits at
first contact: authorized use, one GET by default, explicit CA bundle on
native-verifier platforms, sensitive report metadata and conservative diff
identity. The remaining risk is release process evidence, not an unresolved
architecture dependency: CI must run against the published repository and the
staged file set must be audited before it becomes public.

## Gaps and risks to resolve in the remaining phases

| Priority | Observation | Decision / required gate |
|---|---|---|
| High | CLI flags could multiply requests in surprising ways. | Phase 14 added a serial coordinator with a scan-wide deadline and preflight worst-case request budget. Validate request counts again during the release security review. |
| High | Renderers are a new trust boundary: target-controlled header, cookie, URL and certificate text can reach terminal, Markdown, HTML and browser contexts. | Phase 13 added narrow projections, strict validation and terminal/Markdown/HTML escaping. Retest browser sinks in Phases 17 and 19; never pass raw `httpclient.Response` to a view. |
| High | The dashboard will parse a potentially malicious local report file and serve it to a browser. | Phase 16 binds only loopback, constrains file selection/size, validates schema, adds local-only assets and a restrictive CSP; frontend never uses `innerHTML` or remote scripts. |
| High | On Windows, macOS and iOS HTTPS requires an explicit PEM CA bundle to prevent native chain retrieval outside the network boundary. This is operationally surprising on this workstation. | Phase 14 exposed `--ca-file` and a safe preflight error. Phase 20 should evaluate a bounded offline trust-store strategy without weakening TLS verification or the socket boundary. |
| Medium | CORS probes and redirect tracing are opt-in and have separate internal loops. | Phase 14 reserves their combined worst-case request budget before execution and records effective options. No crawler or credentialed probe. |
| Medium | Finding IDs are stable by rule and origin, while individual evidence IDs are per-exchange. Diffing raw evidence IDs would generate noise. | Phase 15 compares normalized semantic fields and stable finding IDs, tracks rule/schema version changes, and labels unknown/incomparable cases. Its root-only limitation preserves URL privacy. |
| Medium | `httpclient` currently invokes analyzers directly, which is manageable at present but makes the future report assembler tempting to place inside the transport package. | Keep orchestration and report assembly in new packages above `httpclient`; do not make `httpclient` depend on scoring, reporting, CLI or dashboard. Review imports at each gate. |
| Medium | The 256-position finding input guard can omit a later valid response after many duplicates. This is counted, but scoring must not treat the result as complete. | Propagate truncation and omitted counts into report/score eligibility; retain the guard for bounded hostile caller input. |
| Medium | The Windows workstation lacks `gcc`, so `go test -race` cannot compile locally. | Linux CI now contains a mandatory race step; require an actual green run before release. Record local race as BLOCKED. |
| Low | The current working directory is not a Git repository; no automated change history or release tag exists. | Initialize repository only at release-candidate readiness. Ignore rules are prepared; review staged files and secrets before GitHub publication. |

## Target shape

```text
network -> httpclient -> captured evidence -> findingengine -> scoring
                                  \             \-> report assembly
                                   \----------------> report assembly
report JSON -> reporting (terminal/Markdown/HTML)
report JSON -> diff engine
report JSON -> loopback dashboard backend -> local static frontend
CLI -> bounded scan orchestration -> report JSON
```

`report JSON` is the interoperability boundary. Scoring and diffing must not
open sockets. The scanner is the only new coordinator allowed to invoke
`httpclient`; the local dashboard reads validated reports only. Every report
consumer treats strings as untrusted even when the report came from disk.

## Phase sequence and acceptance focus

| Phase | Delivery and principal gate |
|---|---|
| 12 Scoring | Pure, versioned, reproducible configuration score with explicit coverage/unavailable state; no high score from missing data. |
| 13 Reporting | `schema_version: 1.0` canonical JSON and safe terminal/Markdown/HTML renderers with privacy tests. |
| 14 CLI | `scan`, `version`, output formats and explicit network options; one bounded operation budget through the existing scope boundary. |
| 15 Diff | Semantic comparison of two validated reports and stable finding changes, including incomparable schema/rule cases. |
| 16 Dashboard backend | Loopback-only local server over validated report files; no scanning, arbitrary file serving, telemetry or third-party assets. |
| 17 Dashboard frontend | Accessible, responsive, locally bundled UI over the same report model; adversarial rendering and visual QA. |
| 18 i18n | English, Spanish, Russian and Simplified Chinese for product chrome and fixed explanatory copy; protocols/evidence remain untranslated. |
| 19 Adversarial testing | Malicious report, target, terminal, HTML, browser, resource-bound and SSRF regression suites. |
| 20 Hardening | Dependency/static/security review, CI race gate, packaging and configuration tightening. |
| 21 Documentation | Four READMEs, install/development/security/architecture/report/scoring/diff/dashboard docs and portfolio narrative. |
| 22 Release candidate | Reproducible clean build and acceptance matrix, screenshots and release readiness; then Git/GitHub publication per the user's request. |

Each phase must produce running behavior, tests, threat updates and an evidence
gate. A later phase may revise this sequence only with an explicit recorded
architectural reason, not to add unrelated features.
