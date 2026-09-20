# Security and operating limits

SentinelHTTP is for authorized configuration assessment. It sends one bounded
GET by default. Redirect tracing and uncredentialed CORS sampling are opt-in;
the CLI reserves their worst-case request count before any network I/O. It
does not authenticate, crawl, exploit, execute target scripts or send stored
cookies. A finding describes evidence captured by this run, not a verified
vulnerability or whole-site state.

The outbound boundary canonicalizes targets, classifies every resolved IP,
rejects mixed allowed/denied answers, issues a single-use approval for one
literal endpoint and verifies the connected TCP peer. Proxies, implicit
redirects, retries, connection reuse and automatic decompression are disabled.
Each opted-in hop or CORS sample gets a fresh approval. Private and loopback
targets require `--allow-private`; link-local and known metadata destinations
remain denied. HTTPS→HTTP trace downgrades stop before another dial.

TLS uses normal name, trust and validity verification with a TLS 1.2 minimum.
On Windows/macOS/iOS, HTTPS requires an explicit PEM CA bundle because native
chain-building may retrieve issuers outside the approved boundary. A bundle
replaces system roots for that scan; no `InsecureSkipVerify` path is provided.
Certificate revocation is not checked. The operator maintains trust roots.

The report is a narrow, versioned projection. It omits URL paths/queries,
response bodies, cookie values and raw redirect locations, but origins,
certificate subjects, cookie names and inferred configuration can still be
sensitive. Keep reports private. Files are created with private permissions
and never clobber an existing destination. JSON input is size/shape/version
bounded, rejects duplicate keys and is semantically validated. That checks
consistency, not provenance; a fabricated but internally consistent report is
still possible. Renderers escape terminal, Markdown, HTML and React text
contexts; raw JSON remains untrusted data.

The dashboard binds a random `127.0.0.1` port, verifies Host and Origin,
grants no cross-origin access and serves only fixed routes and embedded assets.
It performs no scan or arbitrary file read. Other local processes or browser
extensions can potentially access its unauthenticated loopback port while it
runs. Use a trusted workstation and stop the server when finished.

Parser, resolver, TLS runtime and OS resource ceilings are not universal CPU
or RSS guarantees. DNS policy tables and the pinned Public Suffix List need
maintenance. The score is a reproducible product metric for one response, not
CVSS. The diff labels redacted-path, incomplete-coverage and version conflicts
as unknown instead of inventing a resolved finding.

See the [detailed threat model](threat-model.md), [SSRF model](ssrf-model.md),
[architecture self-review](architecture-self-review.md) and
[Phase 20 audit](phase20-report.md). Report suspected security defects through
the GitHub repository's private vulnerability reporting feature when available;
do not include real target reports or credentials in a public issue.
