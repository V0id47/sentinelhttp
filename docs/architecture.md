# Architecture

SentinelHTTP is a local, bounded HTTP configuration assessor. The Go CLI
coordinates one scan; the network boundary alone approves and opens outbound
connections. Pure analyzers turn captured evidence into findings, a score and
a versioned report. The optional dashboard reads validated local reports and
cannot initiate scans.

```text
CLI -> network Boundary -> HTTP client -> captured response
                                      -> pure analyzers -> findings + score
                                                     -> versioned report
                                                     -> render / diff / dashboard
```

## Network authority

`internal/core/network` parses targets, classifies every resolved address
and issues an opaque, single-use `ApprovedEndpoint`. `Boundary.Dial` connects
to its approved literal IP and verifies the actual TCP peer. An approval is
bound to its issuing boundary and operation context, and expires after ten
seconds. Policy values are copied at construction; test resolver and dialer
injection is package-private. No production caller can supply an arbitrary
dial function.

Every request, CORS sample and redirect hop receives a new approval. Mixed
allowed and denied DNS answers fail closed. The optional same-host redirect
rule can tighten scope, while HTTPS-to-HTTP downgrades stop before another
dial. The source ownership test guards against accidental raw socket use
outside the boundary; it is not a sandbox for malicious Go code. See
[network safety](network-safety.md) and the [SSRF model](ssrf-model.md).

## Bounded capture

`internal/core/httpclient` leases the verified connection to a private
`net/http` transport for one exchange. It does not use environment proxies,
implicit redirects, retries, connection reuse or automatic decompression.
It applies explicit header, body and time limits, then closes the connection.
TLS checks name, trust and validity with a TLS 1.2 minimum. On
Windows/macOS/iOS, HTTPS requires an explicit PEM CA bundle so native issuer
retrieval cannot bypass the network boundary.

The response retains partial evidence and a safe error code when an operation
fails. Analyzer captures distinguish unavailable evidence from an observed
absence. Sensitive raw accessors are explicit; ordinary formatting and JSON
do not expose the captured body or full header and certificate reports. See
the [HTTP client](http-client.md) and [security limits](security.md).

## Analysis and optional probes

The client captures header-derived evidence before reading the body, so a
later body failure does not erase it. Pure packages analyze
[TLS](tls-analysis.md), [response headers](header-analysis.md),
[cookies](cookie-analysis.md), [CSP](csp-analysis.md) and
[CORS](cors-analysis.md). They perform no network I/O. Reports bound retained
fields and values, preserve truncation and applicability, and expose deep
copies. Cookie values, CSP nonce/hash payloads and report endpoints are not
retained in analyzer reports.

Passive CORS analysis sends no Origin header. An explicit CORS probe makes
two uncredentialed GET samples and one OPTIONS preflight sample through
fresh approvals; it reads response headers only. An explicit GET-only
[redirect trace](redirect-analysis.md) follows at most the configured
number of HTTP(S) status redirects, validating each proposed hop before
connection. Neither operation claims browser exploitability.

## Interpretation and interchange

`internal/core/findingengine` consumes captured responses and optional probe
or trace evidence without owning sockets. Its fixed catalog emits bounded,
versioned observations only from complete, applicable evidence. The
[Configuration Score](scoring.md) evaluates one primary response and is
nullable when assessed coverage is insufficient; it does not include the
optional CORS or redirect operations.

`internal/core/reporting` projects evidence into a narrow versioned JSON
document. Paths, queries, bodies, cookie values and raw redirect locations
do not enter it. Build and Parse share structural and semantic validation,
including size and shape limits and duplicate-key rejection. Validation
checks consistency, not report origin. Terminal, Markdown and standalone
HTML renderers escape their output contexts. See the
[finding engine](finding-engine.md) and [report contract](reporting.md).

The CLI in `cmd/sentinelhttp` and `internal/cli` owns the scan deadline,
request-budget preflight and output files. It creates a private temporary
file and publishes a new destination atomically without clobbering an
existing report. See [CLI usage](cli.md).

## Local consumers

`internal/core/diffing` compares validated reports conservatively. It
requires compatible schema and queryless root scans of the same origin;
missing evidence, redacted paths and incomplete redirect journeys become
`unknown`, not inferred fixes. See [diff](diff.md).

`internal/dashboard` validates and snapshots a report, then binds only
`127.0.0.1` on a random port. It serves fixed API and embedded asset routes
with Host/Origin checks and a restrictive CSP. The React/TypeScript frontend
renders report-controlled text without dynamic links or HTML and cannot
select files or scan targets. See [dashboard](dashboard.md).

Human-facing CLI, renderer and dashboard copy supports English, Spanish,
Russian and Simplified Chinese. JSON remains language-neutral. Shipped
finding translations require an exact catalog version and prose match;
changed text falls back visibly. See [localization](i18n.md).

## Verification and limits

CI regenerates the finding catalog and embedded frontend assets, checks for
drift, and runs lint, tests, the Go race detector, dependency audits and
secret scanning. The [release-readiness matrix](release-readiness.md)
records the published v0.1.0 evidence. The
[threat model](threat-model.md) and
[architecture self-review](architecture-self-review.md) describe residual
risks. SentinelHTTP does not authenticate, crawl, execute scripts, verify
certificate revocation or prove site-wide security.
