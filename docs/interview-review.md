# SentinelHTTP — interview review

These answers describe v0.1.0 behavior and its limits. They are useful when
reviewing the [architecture](architecture.md), [threat model](threat-model.md)
and [portfolio case study](portfolio.md).

**Why is a wildcard CORS header not automatically a vulnerability?**
`Access-Control-Allow-Origin: *` can be appropriate for a public resource.
SentinelHTTP records the header and uncredentialed probe behavior, but cannot
show that a browser could read sensitive authenticated data. A confirmed
exposure needs resource sensitivity, credentials and browser behavior evidence.

**Why does a missing or weak CSP not prove XSS?** CSP is a defense-in-depth
control. Its absence or permissive directives reduce a mitigation; they do not
show an injection source, unsafe sink or executable payload. The parser reports
observed directives and limitations rather than inventing an exploit.

**Why can `Server` and framework headers be misleading?** A server, proxy or
application can set arbitrary header strings. They are claims visible on the
wire, not authenticated product identification. The report preserves that
distinction.

**How does the scanner reduce accidental SSRF?** The scope boundary parses a
target, resolves and classifies every address, denies private and special-use
destinations by default, issues a one-use approval, dials the approved IP and
checks the actual peer. Every additional request goes through that boundary.
Explicit `--allow-private` is for authorized local labs.

**What about DNS rebinding and redirects?** A hostname is not approved forever.
Each request resolves and obtains a fresh approval; dial uses the approved
literal address and verifies the connected peer. Optional redirect tracing
revalidates every hop, enforces the request budget and blocks HTTPS-to-HTTP
downgrades. A cross-host redirect is an observation, not an automatic finding.

**Why not scan every TLS cipher?** v0.1.0 analyzes the authenticated connection
it actually negotiated. Exhaustive probing multiplies traffic and expands the
network authority surface. The report cannot infer support for untried suites.
On Windows, macOS and iOS, an explicit PEM CA file keeps native issuer
retrieval outside the network boundary.

**Why discard cookie values, bodies and URL paths?** They can contain session
secrets and personal data. The report keeps only evidence needed for its
configuration claims. This privacy choice limits comparison: diff can match
compatible root scans but must label other endpoint identities unknown.

**Why is JSON authoritative?** A single versioned schema lets terminal,
Markdown, HTML, diff and dashboard views consume the same bounded evidence.
The strict import parser rejects ambiguous duplicate keys and inconsistent
records. It validates structure, not the report's provenance or truthfulness.

**What makes a finding evidence-backed?** A versioned rule binds an observation
to captured evidence and states inference, confidence, remediation and
limitations. Missing or truncated input cannot become a reassuring negative
finding. A score is emitted only when enough domains were assessed.

**Why a local dashboard?** It presents saved assessments without a cloud
service or second scanner. The Go server binds loopback, serves bundled assets,
checks Host/Origin and accepts validated report files selected by the CLI. It
has no browser upload or target URL route. Loopback access is not
authentication, so users should close the server after use.

**What can SentinelHTTP not conclude?** It does not prove exploitability,
complete coverage of a site, absence of vulnerabilities, authenticated CORS
data exposure or a report's origin. It has no crawler, login, JavaScript
execution, password testing or exploit framework. The [release readiness
matrix](release-readiness.md) records what was actually tested.
