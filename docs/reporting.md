# Versioned report boundary

`internal/core/reporting` is the shared, I/O-free evidence boundary for the
CLI, diff engine and dashboard. `Build` accepts only already captured
responses, a canonical initial target, an effective non-secret configuration
and caller-supplied UTC timestamps. It computes the fixed finding catalog and
one-response Configuration Score from the same admitted evidence. It does not
run requests, read files or read the clock.

The public JSON document declares `schema_version: "1.0"`,
`tool: "SentinelHTTP"` and `tool_version: "0.1.0"`. It records scan times,
origin-redacted target/final target, a coarse root-or-redacted initial target
scope, primary request ID, effective scan
configuration, bounded request summaries, redirect hops, three fixed CORS
probe attempt slots with opaque captured-exchange IDs when probing was
requested, findings, the nullable score,
omission counters and limitations. Request summaries contain the safe origin,
opaque ID, method/result/timing, resolution and peer decisions, and narrow
TLS/header/cookie/CSP/CORS projections. JSON is the authoritative interchange
format; terminal, Markdown and HTML are views of this document.
The effective scan configuration can include trace enablement, reserved
request count, connect timeout and an explicit-trust-bundle boolean. It never
stores the CA path or PEM. When a request budget is declared, `Validate`
rejects both a worst-case reservation above it and observed requests/probe
attempts above it.

The projection intentionally excludes URL paths, queries and fragments, raw
`Location` values, response bodies, authorization headers, cookie values and
raw `Set-Cookie` lines. Cookie path text is reduced to a scope label. CSP
nonce/hash payloads, source paths and report endpoints are omitted. Fixed or
normalized analyzer states are retained; certificate text, cookie names,
domains, CSP host sources, valid CORS origins and finding prose remain untrusted
text. Operators should treat report files as potentially sensitive because
origins, certificate subjects, cookie names and inferred configuration can
reveal system details.
The scope marker supports conservative root-only diffing without retaining
paths, queries or a guessable digest of them. Redacted initial endpoints cannot
be proved identical from reports alone. Reports must remain private because
other projected metadata can still be sensitive.

`Build` deduplicates identical response pointers by opaque ID, rejects
conflicting IDs, and sorts request summaries for stable output. The report
holds at most 32 distinct request summaries, 21 redirect hops, three probe
attempts, 256 findings and 16 evidence references per finding; the encoded
document is capped at 8 MiB. A cap violation is an error, not a silent drop.
The finding engine's own explicit omission counters remain visible when it
truncates supported input. Each request also records cookie capture status,
field count, analyzed count, omitted count and truncation, and the top-level
partial flag includes analyzer truncation. Unknown CSP directive tokens are
represented by a fixed `unknown` label. Cookie evidence includes bounded
Secure/HttpOnly attribute states and an identity-repeat flag so a finding's
indexed evidence can be checked against the reported cookie. A score is only
available when its own minimum evidence threshold is met; CORS probes and
redirects never affect it.

`Parse` first tokenizes under array, depth and object-member caps, rejecting
duplicate and case-folded object keys, before
allocating typed slices. It then uses a strict JSON decoder with
unknown-field rejection, an 8 MiB input cap, trailing-data rejection and
structural validation. `Validate`
checks schema/tool compatibility, time/order, canonical redacted targets,
identities, redirect continuity, evidence indices, fixed probe codes, counts,
the versioned score catalog and nested string/array limits before any
renderer sees the document. Validation establishes internal consistency, not
the authenticity of a file or of the observed endpoint. The dashboard
parses incoming files through this boundary and does not place report
strings into raw HTML, script, URL or CSS contexts.

For untruncated reports with an available score, validation reconciles
primary-response findings with penalties only in assessed score domains.
Findings can legitimately exist in a domain marked unavailable without
changing the score. Redirects are also checked against their HTTP status and
Location state; uncaptured CORS probe attempts cannot carry captured analysis.

`Render` validates first. Terminal output replaces C0/C1 controls, ANSI
escapes and Unicode format/line-separator characters from dynamic strings.
Markdown escapes punctuation and raw HTML in dynamic text, flattening line
breaks. HTML uses `html/template` text escaping and a static CSP that forbids
scripts, remote assets, base URLs and forms. No renderer opens a link or
executes report content. The report explicitly says that findings describe
performed checks and an empty finding list does not prove application
security.

The CLI owns scan orchestration, file persistence and atomic output writes.
The diff engine consumes two validated documents without I/O. The local
dashboard serves a validated snapshot; authenticated scanning is not
implemented. The report package remains pure. Human renderers support four
locales without changing the canonical JSON; see [localization](i18n.md).
