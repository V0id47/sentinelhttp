# Core architecture — v0.1.0

This document preserves the detailed phase-by-phase design and describes the
implemented product. The network boundary is the only outbound scan socket
owner; the dashboard is a separate inbound loopback listener. The CLI is the
coordinator above them, and JSON reports connect pure analysis to local views.

Phase 3 scope: one internal Go package, `internal/core/network`. Keeping
approval issuance and consumption in the same small package avoids exporting a
constructor that could manufacture an approved address. Splitting this into seven
public packages would weaken the capability boundary without improving this phase.

```text
ParseTarget(raw) -> immutable Target
NewBoundary(initial, Policy) -> configured Boundary
Boundary.Approve(ctx, target)
  -> resolve or classify literal
  -> evaluate every returned address
  -> opaque ApprovedEndpoint + independent ResolutionRecord
Boundary.Dial(ctx, approved)
  -> owner / one-use / expiry / cancellation checks
  -> net.Dialer to approved literal IP:port
  -> compare actual TCP peer
  -> net.Conn + PeerRecord
```

Files:
- target.go: URL parsing, IDNA, host/authority/TLS name and sensitive RequestURL
  separated from default origin-only display.
- policy.go: predicates plus reviewed special-purpose ranges; explicit decisions.
- errors.go: machine codes, safe errors, DNS/dial cause categorization.
- boundary.go: private resolver/dialer interfaces, approval issuance/consumption,
  resolution records, timeouts, socket ownership and peer checks.
- target_test.go, boundary_test.go, adversarial_test.go: unit, integration, fuzz,
  architecture and hostile dependency cases.

Production construction uses the system resolver and net.Dialer; test injection
is package-private. Production callers cannot install a raw dial function.
Target/ApprovedEndpoint fields are unexported. Zero/JSON-created approvals fail;
copying a capability retains a shared atomic consumption flag. It is bound to its
issuing Boundary and original operation context and expires after ten seconds.

The returned evidence is a separate copy. Mutating it cannot change the selected
endpoint. Boundary copies policy values and retains only the initial hostname,
not the initial path/query. Production state is immutable except token consumption.
Tests replace dependencies before operations, never while concurrent calls run.

No public API accepts a string hostname for dialing. The Phase 4 HTTP/TLS client
consumes this boundary, preserving Target.Authority for HTTP and Target.TLSName for
certificate validation. For IP-literal targets, validate IP SANs; do not fabricate
a DNS SNI. HTTP pooling and redirect orchestration remain absent.

Each request or redirect calls Approve again; Dial cannot reuse an approval.
SameHost compares canonical host, not port, scheme or registrable domain. Downgrade
redirect decisions belong to the redirect orchestration; Approve supports
HTTP and HTTPS independently and does not represent a redirect chain.

The caller owns and closes a successfully returned connection. Dial closes any
connection returned together with an error, after cancellation, or with a wrong
peer. Context governs establishment; callers must govern protocol I/O and close
the socket after success. No background request loops are created.

Architectural enforcement is not a sandbox against malicious Go code: code could
import net itself. TestSocketOwnership guards the present production source tree
against raw socket primitives outside the exact Boundary source path and forbidden
imports. The reviewed Phase 4 HTTP adapter is explicitly permitted, while default
clients/transports, ProxyFromEnvironment and tls.Dial remain forbidden. Code review
and test changes remain trusted.

## Dependencies and development environment

Go 1.27.1 Windows/amd64 was downloaded from go.dev into the workspace-only
`.sentinelhttp-tools` directory and verified against its published SHA-256.
go.mod records the language floor and exact dependency versions:
golang.org/x/net v0.59.0 (IDNA and the compiled Public Suffix List) and x/text
v0.42.0 (transitive). Phase 7 uses the PSL snapshot already shipped in that pinned
x/net module; Phase 8 adds no module dependency.
No system PATH changes were required. Git initialization and public release
followed only after the Phase 22 acceptance gate.

## Phase 4 adapter

`internal/core/httpclient` depends on network without duplicating policy:
config/method validation -> approval -> verified dial -> optional strict TLS ->
single-use transport lease -> RoundTrip -> bounded body -> close.

Client configuration is immutable and independent calls can run concurrently.
Each call has private transport/response state; Response is caller-owned and must
not be mutated/discarded concurrently with reads. Metadata returns a deep snapshot.
No global counters, arbitrary request-header API or cookie jar.

Files: client.go (lifecycle), transport.go (socket lease), config.go (limits/CA),
model.go (safe metadata/raw accessors), errors.go (safe taxonomy), alongside tests.
See http-client.md and ADR 0005 for direct RoundTrip and platform CA restrictions.

## Phase 5 analysis

`httpclient` passes the same connection's TLS state and transient handshake error
to `tlsanalysis.Capture`. This pure package performs no I/O and does not alter
authentication. It extracts bounded, owned evidence; runtime errors and raw DER
are not retained. Failed handshakes still terminate before HTTP.

Response stores this evidence privately. `TLSAnalysis()` returns an independent
copy, explicitly exposing untrusted certificate text. Default formatting/JSON
continues to exclude that text. See tls-analysis.md for limits and semantics.

## Phase 6 analysis

`headeranalysis` is another pure package with no I/O or network imports. The HTTP
client calls it only after `RoundTrip` has returned response headers, before the
bounded body read. A body failure therefore preserves a complete header capture;
failures before headers retain `capture_unavailable` and cannot become false
absence conclusions.

The analyzer receives only response status, scheme/TLS/IP context and a header
snapshot. It classifies representation from status and one valid Content-Type,
then records applicability separately from syntax/effect. It evaluates a fixed
allowlist of ten security-related fields in deterministic order. CSP is recorded as
observed there; detailed CSP parsing belongs to the dedicated Phase 8 package.
`Server` is an untrusted claim.

Evidence has per-field count/value bounds plus a 32 KiB aggregate retention budget.
Control and Unicode format characters are replaced in explicit evidence. Any
truncation suppresses semantic parsing for that field. Raw values remain private
inside the report and require `Values`; default response JSON/fmt omits the entire
analysis. `HeaderAnalysis()` and nested parsed directives are deep copies. See
header-analysis.md for exact field semantics and current limitations.

## Phase 7 analysis

`cookieanalysis` is a pure package without HTTP/network imports or I/O. The HTTP
client passes each captured Set-Cookie field separately, canonical emitter context,
request path and explicit observation time immediately after receiving headers.
The body lifecycle cannot erase the report; pre-header failures retain an
unavailable capture.

The package never retains cookie or extension values. It separates parse status,
effective Domain/Path/persistence policy, draft-model acceptance and the explicitly
limited session-like heuristic. The network layer supplies an IDNA-canonicalized
emitter; Domain attributes follow the draft's ASCII/CHAR processing and use x/net's
compiled PSL. Max-Age overrides Expires; prefix and SameSite requirements are evaluated
without creating findings or claiming universal browser behavior.

Response stores the report privately and `CookieAnalysis()` returns a deep copy.
Default JSON/fmt still serializes Metadata only. Required name/domain/path evidence
is untrusted and only reachable through the explicit accessor. See
cookie-analysis.md for types, bounds, rules and versioned normative basis.

## Phase 8 analysis

`cspanalysis` is a pure, deterministic package: it accepts only captured CSP
fields, normalized document applicability and normalized X-Frame-Options evidence.
It performs no I/O, DNS, URL requests, body/DOM parsing, browser execution, final
finding, severity or score generation. The client invokes it with both CSP header
families immediately after header analysis and before the body is read. Failed
pre-header exchanges leave its capture unavailable; a later body failure preserves
the captured report.

The report keeps enforced and report-only policy sets separate, and preserves each
field and comma-list member as a distinct policy. It never unions source lists.
Within one policy it records first-directive-wins parsing, bounded typed sources and
per-policy CSP3 fallback controls. `Response.CSPAnalysis()` returns a deep copy;
the private stored report and default Response JSON/fmt do not expose CSP evidence.
Only bounded directive/host-source components appear in the explicit report and
remain untrusted. Nonce/hash payloads, raw field values, report endpoints and
opaque directive values are excluded. See csp-analysis.md for grammar, bounds,
observations, framing semantics and limitations.

## Phase 9 analysis

`corsanalysis` is a pure package with no network or HTTP-client dependency. The
client captures CORS response headers immediately after `RoundTrip` returns and
before reading the body. A pre-header failure remains `capture_unavailable`;
later body errors preserve the completed report. `Response.CORSAnalysis()` returns
an owned deep copy, while default Response JSON/fmt still omits the report.

Passive analysis records bounded ACAO, ACAC, Vary, preflight-list and cache
evidence without sending an Origin header. `Client.ProbeCORS` is a distinct
opt-in operation: two GET samples and one OPTIONS preflight sample use fixed
origins and headers, each through a fresh single-use scope approval and verified
dial. All three share one overall deadline. Probes stop at response headers and
do not follow redirects or read bodies. The pure comparison layer labels only
sample observations and conditional risks; it does not claim browser exposure.
See cors-analysis.md for exact semantics and limits.

## Phase 10 analysis

`redirectanalysis` is pure: it classifies the five followable statuses and
resolves one bounded `Location` reference without I/O. The opt-in
`Client.TraceRedirects` sequences the existing one-exchange client rather than
allowing the HTTP transport to navigate automatically. Each header-only GET
attempt receives fresh scope approval, a verified dial and the same TLS/header
analysis as `Do`; a shared context limits the whole journey. The orchestration
stops before a downgrade, out-of-scope or repeated target can cause an extra
request. It retains partial evidence with explicit stop reasons and safe default
serialization. See redirect-analysis.md for the data contract and limitations.

## Phase 11 findings

`internal/core/findingengine` is a pure consumer of captured `httpclient`
responses, redirect traces and optional CORS probe results. It does not import
into `httpclient` or alter its network boundary. A fixed 12-rule catalog maps
complete, applicable upstream evidence to conservative observations; the
builder groups by rule and safe origin, computes deterministic IDs, deduplicates
references and enforces output limits. Probe assessments are recomputed from
matching captured attempts. Redirect stop rules recheck the terminal Location.
These checks guard ordinary inconsistent input, not malicious fabrication of
caller-owned structs. No scoring, CLI or rendering occurs here. See
finding-engine.md for exact predicates, limits and privacy contract.

## Phase 12 scoring

`internal/core/scoring` is a pure consumer of one chosen primary
`httpclient.Response`. It invokes `findingengine.Evaluate` on that response
and computes a versioned four-domain Configuration Score only when enough
relevant evidence was assessed. The score is nullable, exposes coverage and
fixed penalty contributions, and omits optional CORS/redirect operations.
It does not drive scanning or introduce a second interpretation of finding
predicates. See scoring.md for weights and limits.

## Phase 13 reporting

`internal/core/reporting` is the next pure consumer after analyzers,
`findingengine` and `scoring`. It explicitly projects captured response
snapshots into a narrow versioned DTO, so no raw HTTP response, cookie value,
body or URL path can reach the interchange document through default
serialization. The CLI orchestrates network calls and owns file
writes; the report package only assembles, validates, parses and renders.

Both `Build` and `Parse` lead to the same structural validator. This is the
trust boundary for diff and browser consumers: unsupported schema
versions and oversized or inconsistent files fail before presentation.
Terminal, Markdown and HTML renderers then apply output-context escaping.
The standalone HTML view uses `html/template` and static no-script CSP.
Reports do not authenticate their own origin or prove site-wide security.
See reporting.md for the schema, bounds and privacy projection.

## Phase 14 CLI

`cmd/sentinelhttp` delegates process arguments to `internal/cli`. The CLI is
the sole scan coordinator: it creates one scope boundary, one HTTP client and
one scan-wide deadline, then performs the base GET or an opted-in redirect
trace, followed only when requested by a three-attempt CORS probe. Worst-case
request cost is rejected before any network activity. It passes captured
responses to pure reporting; no analyzer or renderer opens sockets or files.
The report records effective limits without raw URL or CA path. File output
uses a private same-directory temp plus atomic no-clobber hard link. See
cli.md for flags, exit codes and output behavior.

## Phase 15 diff

`internal/core/diffing` compares two validated reports without opening a
socket. It requires compatible schema and conservative target identity:
queryless root scans of the same origin. Missing coverage, redacted paths,
scoped cookies and incomplete redirect journeys become explicit `unknown`
results, not inferred remediation. See [diff](diff.md).

## Phases 16–17 local dashboard

`internal/dashboard` validates and snapshots the report, optionally computes a
baseline diff, then binds only `127.0.0.1:0`. It serves fixed API and embedded
asset routes with Host/Origin checks and a restrictive CSP. The React/TypeScript
frontend consumes those snapshots; it cannot choose files or initiate scans.
Report-controlled values render as text, never dynamic links or HTML.
See [dashboard](dashboard.md).

## Phase 18 localization

`--lang` selects fixed human-facing CLI and renderer copy. The frontend has a
local selector. Both presentations translate shipped findings only when rule
ID, rule version and complete canonical narrative match; unknown or changed
text remains untrusted evidence with a fallback warning. The JSON schema is
language-neutral. See [localization](i18n.md).

## Phases 19–20 hardening

Report preflight rejects duplicate and case-folded JSON keys before typed
decoding. Adversarial tests cover route/Host/Origin confusion, request budget
and browser text rendering. CI reconstructs catalogs and embedded assets,
checks for drift and runs Go race, vet, tests and dependency audits on Linux.
The Windows/macOS/iOS HTTPS requirement for an explicit PEM CA bundle remains
an intentional restriction: automatic issuer retrieval would cross the
reviewed network boundary. See [security](security.md) and the
[architecture self-review](architecture-self-review.md).
