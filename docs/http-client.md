# Secure HTTP client — Phase 4

Implemented 2026-09-16 in `internal/core/httpclient`. The transport still owns
one exchange per call; later phases added analyses and an explicit redirect
journey. No scanner, CLI or findings engine is implemented.

## API and ownership

`New(boundary, Config)` copies configuration and parses optional CA PEM into a
private pool. `Do(ctx, target, GET|HEAD|OPTIONS)` returns Response plus error, with
metadata even on failure. No arbitrary methods, body, request headers, credentials,
cookie jar, client certificates or proxy configuration.

Every Do calls Boundary.Approve and Boundary.Dial. Only Boundary resolves,
classifies, approves and opens TCP. The HTTP adapter receives a peer-verified
connection. It owns and closes that connection on success, truncation and error.
TLS is performed manually over that same socket with the logical hostname.

Transport dial callbacks are single-use **connection leases**, not network dialers.
They check logical authority, TCP protocol and an atomic consumption flag before
returning the existing connection. The inappropriate scheme callback rejects.
They contain no resolver/socket primitive/fallback. Second use fails.

Host uses Target.Authority, preserving logical host and explicit port. TLS
ServerName uses Target.TLSName, never a substituted resolved DNS address. Literal
IPs use IP SAN verification; crypto/tls omits DNS SNI for IP literals.

## Transport decisions

| Setting | Value and reason |
|---|---|
| Proxy | nil; no environment lookup |
| DialContext | verified one-use socket for HTTP; reject for HTTPS |
| DialTLSContext | verified, already-handshaken socket for HTTPS; reject for HTTP |
| DisableKeepAlives | true; new approval/socket per operation |
| DisableCompression | true; no automatic gzip |
| Protocols | HTTP/1 only |
| ForceAttemptHTTP2 / TLSNextProto | false / empty |
| MaxConnsPerHost | 1 per ephemeral transport |
| MaxIdleConns / MaxIdleConnsPerHost | 1; no usable reuse pool |
| IdleConnTimeout | configured total; CloseIdleConnections on exit |
| TLSHandshakeTimeout | set defensively; actual manual handshake uses its own context |
| ResponseHeaderTimeout | configured bounded deadline |
| ExpectContinueTimeout | 0; requests have no body or Expect header |
| MaxResponseHeaderBytes | configured initial-header cap |

Requests send logical Host, `SentinelHTTP/0.1.0 Security Assessment`, Accept `*/*`,
Accept-Encoding `identity` and connection-close semantics. A server ignoring
identity cannot trigger decompression: bounded encoded entity bytes are returned.

**Transport.RoundTrip is called directly.** No redirect layer exists. The initial
Client.Do + CheckRedirect=ErrUseLastResponse approach was replaced after a failing
test: Go parses Location before CheckRedirect and discards a valid 302 if Location
is malformed. RoundTrip preserves status/Location/body without interpreting or
following Location. This is the documented refinement of the requested design.

No retries or IP failover: a fresh transport has no reused connection, and its
lease cannot return a second socket. No http.Get, DefaultClient, DefaultTransport,
ProxyFromEnvironment or tls.Dial. HTTP/1.0 and HTTP/1.1 fixtures pass; HTTP/2 is
deferred and HTTP/3 excluded. Parsing uses net/http, including its documented/
observed tolerance of some nonconforming header names; there is no custom parser.

## Limits

| Limit | Default | Hard maximum |
|---|---:|---:|
| DNS/connect | Boundary's 3s each | Boundary's 10s each |
| TLS handshake | 5s | 10s |
| Response headers | 10s | 30s |
| Whole Do operation | 15s | 60s |
| Retained entity body | 2 MiB | 8 MiB |
| Initial headers | 64 KiB | 128 KiB |
| Operator CA PEM | none | 1 MiB |

Zero config values select defaults. Negative/out-of-bounds values fail before I/O.
Total context begins before approval and includes DNS/connect/TLS/HTTP/body. Caller
deadlines can shorten it. The verified socket receives a total deadline and a
cancellation close callback capturing the original TCP connection immutably.
TLS uses HandshakeContext. No goroutine is spawned to emulate timeouts around
non-cooperative dependencies.

These bound blocking I/O, not all CPU/RSS use inside certificate verification,
Go parsers or the system resolver. TLS has runtime handshake allocation limits,
not an application MaxResponseHeaderBytes guarantee.

Header byte cap is the principal defense; there is no independent count cap. It
covers initial HTTP headers. Informational responses have runtime handling and
HTTP/1 trailers have a separate small runtime buffer bound (about 4 KiB here).
Trailers are not captured. No aggregate whole-connection wire-byte bound claimed.

## Body semantics

Read through `io.LimitReader(body, max+1)` before `io.ReadAll`; Content-Length
never determines allocation. The extra byte proves actual exceedance.

- EOF at/below limit: BodyComplete=true, BodyTruncated=false.
- Extra byte: retain at most max, BodyTruncated=true, BodyComplete=false; keep
  headers and return no error because the intentional bound worked.
- Premature close/read error: keep partial bytes/headers and return a stable error
  with BodyComplete=false. Partial EOF is not called limit truncation.
- HEAD completeness describes this exchange, not the representation of a GET.

BytesRead is transfer-decoded entity bytes, including the one-byte lookahead; it
can be max+1. It is not wire bytes or decoded gzip content. DeclaredContentLength
is separate (-1 when unknown). Body.Close and TCP close occur on every return.

## Strict TLS and CA restriction

Minimum TLS1.2; InsecureSkipVerify=false; no client certs, session cache or HTTP/2
ALPN. Safe typed error categories cover trust, hostname, validity and handshake
timeout where Go supplies sufficient evidence. No TLS security assessment yet.

Config.LabCAPEM is the minimal CA-bundle API. A bundle can contain lab or selected
public roots; it replaces system roots for that client. The CLI exposes this
input as `--ca-file` with a one-megabyte PEM limit.
An explicit new CertPool selects Go's offline verifier.

**Windows/macOS/iOS HTTPS requires an explicit PEM bundle.** Without
one, tls_ca_bundle_required is returned before approval/dial. Native certificate
verification can retrieve AIA/root material outside Boundary. The bundled Go
Windows implementation calls CertGetCertificateChain without cache-only/AIA-disable
flags. This is a fail-closed usability limitation, not relaxed verification.
Linux uses local Go system-root behavior with no bundle; the Phase 20 Linux CI
build and race gate is the release validation. No native-store exporter, public
bundle download or certificate manager was added.

Missing intermediates fail instead of being fetched. A local missing-issuer/AIA
trap test proves zero secondary requests with explicit roots. Revocation is not
assessed. Sources: [Go x509 verification](https://go.dev/src/crypto/x509/verify.go),
[Windows chain-building flags](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain).

## Evidence and privacy

Each call returns random operation ID, safe target, validated method, UTC start/end,
monotonic duration, status/protocol, length/byte/completeness fields, Boundary
resolution/peer evidence and minimal TLS version/cipher/logical name/ALPN/verified
metadata. No issuer, SAN, expiration or cipher assessment.

ConnectionAttempts counts invocation of Boundary.Dial, not proof of a socket;
RequestAttempts counts invocation of RoundTrip, not proof of server receipt.
Both are at most one. Future orchestration reserves its budget before Do and
aggregates outcomes; there is no global counter or scan budget engine.

Private transient http.Header retains repeated values, including separate
Set-Cookie entries. HeaderValues returns copies with case-insensitive lookup.
Go canonicalizes names; global wire order and original name casing are not retained.
Location/Server remain untrusted observations. Cookie analysis consumes the
separate Set-Cookie entries without altering this raw transient store.

Body returns a bounded copy; DiscardBody clears/releases retained bytes but cannot
guarantee erasure of all Go/runtime copies. HeaderInfo returns sorted names, counts
and sensitivity. Names remain untrusted text, not presentation-ready strings.

Default Response formatting/JSON contains sanitized metadata only: no raw body,
header values, query/path, Location or cookies. Metadata produces independent
nested snapshots. Raw accessors are deliberately sensitive and must not be logged.
All header values are omitted by default, even unknown headers. The sensitivity
catalog additionally marks Authorization, Proxy-Authorization, Cookie, Set-Cookie,
X-API-Key, Api-Key, X-Auth-Token, X-Access-Token and authentication-info variants.

Phase 6 adds `HeaderAnalysis()`. It returns a deep copy of bounded results derived
from the captured headers, and its explicit `Values` accessor exposes only the ten
analyzed fields. The report is captured before body reading, so an incomplete body
does not erase header evidence. Failures before response headers leave capture
unavailable. Response JSON/fmt still excludes both the report and its values. See
[header analysis](header-analysis.md) for context, status and field semantics.

Phase 7 adds `CookieAnalysis()`. It returns a deep copy of bounded results captured
at the same pre-body point. The report retains no cookie/extension values and
default Response output excludes it. Cookie names and effective paths/domains are
explicit untrusted evidence. Default-path calculation receives `URL.EscapedPath`,
so encoded slashes keep their wire-visible path structure. The raw
`HeaderValues("Set-Cookie")` API is unchanged
and remains sensitive. See [cookie analysis](cookie-analysis.md) for the RFC model,
PSL version, limits and inference semantics.

Phase 8 adds `CSPAnalysis()`. At the same pre-body point, the client passes
separate `Content-Security-Policy` and `Content-Security-Policy-Report-Only` field
sets, normalized document applicability and normalized XFO evidence to the pure
`cspanalysis` package. It retains policy boundaries: several fields and
comma-separated serialized-list members remain separate policies, while enforced
and report-only sets are never joined. A pre-header failure stays
`capture_unavailable`; a body failure cannot erase an already complete CSP report.

`CSPAnalysis()` is an explicit deep-copy accessor. Its retained directive/source
components are untrusted text and must be escaped for their final output context.
The report retains neither raw CSP fields, nonce/hash payloads, report endpoints
nor opaque directive values. Default Response JSON/fmt still serializes Metadata
only. `HeaderValues` remains a sensitive raw-header accessor; it can expose either
CSP field family. See [CSP analysis](csp-analysis.md) for limits, source grammar,
fallback chains and its non-finding boundary.

Phase 9 adds `CORSAnalysis()`, a deep-copy accessor for bounded CORS evidence
captured at the same pre-body point. An ordinary `Do` sends no synthetic Origin;
pre-header errors remain unavailable and later body errors retain the report.
Default Response JSON/fmt omits it, while `HeaderValues` remains an explicit
sensitive raw-header accessor. `ProbeCORS(ctx, target)` separately performs at
most three fixed header-only exchanges through the same scope boundary and one
overall timeout. It sends no credentials, reads no response body and follows no
redirect. See [CORS analysis](cors-analysis.md) for request shapes, assessment
limits and incomplete-attempt behavior.

Phase 10 adds `TraceRedirects(ctx, target, options)` as a separate GET-only,
header-only journey. It manually calls the same one-exchange path for every
attempt and revalidates each destination through `Boundary`; `Do` itself never
follows redirects. The returned ordered trace records each hop's safe metadata,
existing analyses, Location state and explicit stop reason. Default trace
JSON/fmt redact paths, queries and raw Location; callers can retrieve the raw
field through `hop.Response.HeaderValues("Location")`. See [redirect
analysis](redirect-analysis.md) for limits, scope and downgrade semantics.

Errors expose stable codes, never raw net/http errors containing URLs/hostile text.
Go has no typed header-limit error; a narrow prefix match along its error chain
classifies the pinned runtime's size failure. Future changed wording may become
generic protocol error, but still fails safely. Local regressions cover it.

httptrace was evaluated but not added: overall timing plus Boundary evidence is
sufficient here; no DNS/connect/TLS/TTFB timing-breakdown claim. Mechanisms reviewed:
[net/http Transport](https://pkg.go.dev/net/http#Transport) and
[HandshakeContext](https://pkg.go.dev/crypto/tls#Conn.HandshakeContext).
