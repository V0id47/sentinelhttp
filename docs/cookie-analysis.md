# Cookie analysis — Phase 7

Implemented 2026-09-18 in `internal/core/cookieanalysis`. The package is pure and
deterministic: it performs no DNS, socket, file or clock I/O. `httpclient` supplies
the observation time and the separate `Set-Cookie` fields from the response it
already received.

## Capture and identity

`capture_unavailable` means no response headers were received. It returns no
per-cookie records, so a method, scope, connection, TLS or protocol failure cannot
be reported as an absence of cookies. `capture_complete` means Go accepted the
initial header block. A complete capture with zero fields is a real observation.

Each `Set-Cookie` field produces at most one record and is parsed independently.
The analyzer never comma-splits a field: the comma in `Expires=Wed, 21 Oct ...` is
part of the cookie date. Go's `http.Header.Values("Set-Cookie")` preserves the
separate entries used as input, although original wire order relative to other
header names and original header-name casing are unavailable.

The identity is emitting resource + cookie name + effective domain + effective
path. The emitting resource uses Target.SafeURL, so query and concrete request path
remain redacted. `IdentityRepeated` marks two records in the same response with the
same complete identity; it does not choose a winner or simulate a cookie jar.

## Parsing and effective policy

Parsing, effective policy and name heuristics remain separate in the model.
Attribute state is `absent`, `valid`, `invalid`, `duplicate` or `truncated`.
Case-insensitive known attributes are Secure, HttpOnly, SameSite, Domain, Path,
Expires and Max-Age. Unknown attributes retain only a lower-case, syntactically
valid name and occurrence count; their values are discarded.

The cookie pair follows the draft's tolerant user-agent algorithm rather than the
stricter server grammar: a name need not be an HTTP token, a missing equals sign
creates a nameless cookie, and internal value whitespace is accepted. Empty
name+value and forbidden control octets are rejected. Cookie values are inspected
only transiently for those rules and the nameless-prefix defense. Display names
replace invalid UTF-8/control/format characters, expose `NameSanitized`, and lossy
names are never conflated when marking repeated identities.
Valid empty names can participate in exact repeated-identity detection. Sanitized
names or paths and truncated records cannot.

- Repeated known attributes are visible as `duplicate`. The last value that the
  RFC algorithm would retain supplies the effective value. Invalid Expires and
  Max-Age values are ignored for this selection. The last processed Domain value
  decides scope, so an empty value restores host-only behavior and an invalid
  nonempty value rejects the cookie. An empty/relative last Path produces the RFC
  default path.
- A valid Max-Age takes precedence over Expires. Positive means persistent; zero
  or negative is a deletion instruction. Otherwise, a valid future Expires means
  persistent and a past/current date means deletion. With neither, persistence is
  `session`; this describes storage lifetime, not authentication. Observed values
  remain explicit, while effective positive lifetimes are capped at the draft's
  recommended 400 days and carry `Clamped=true` when changed.
- Expires uses the tolerant cookie-date token algorithm, including two-digit year
  adjustment and calendar/range validation. It is not parsed as a comma-separated
  list or restricted to one HTTP-date rendering.
- Domain accepts the draft's CHAR range, lowercases ASCII and strips one leading
  dot before matching it to the already IDNA-canonicalized emitter. Non-ASCII
  U-labels in the attribute are rejected; their A-label form is accepted. Scope is
  evaluated against the bundled Public Suffix List. A
  public-suffix Domain is rejected unless it equals the emitter, where the draft
  algorithm ignores the attribute and uses a host-only cookie. An absent or empty
  Domain is also host-only. Effective broader scope is an observation; it does not
  prove control or compromise of a subdomain.
- An absent, empty or relative Path uses the RFC default-path algorithm. `Explicit`
  distinguishes an actual valid Path from that fallback, which matters to
  `__Host-`. The HTTP integration supplies the escaped request path, preserving
  encoded slashes. Retained paths replace invalid UTF-8/control/format characters,
  expose `Sanitized`, and lossy paths do not participate in identity comparison.
- SameSite is `Strict`, `Lax`, `None` or effective `Default`; an unrecognized value
  is invalid but maps to Default. Under this model, SameSite=None without Secure is
  rejected.
- Secure and HttpOnly record presence and repetition. Under this model, a Secure
  cookie emitted by a non-HTTPS response is rejected.
- `__Secure-` requires HTTPS plus Secure. `__Host-` additionally requires an
  effective host-only cookie and an explicit `Path=/`. The user-agent policy matches prefixes
  case-insensitively, including the nameless-cookie defense; `Kind` uses canonical
  spelling in the report.

An attribute value longer than the draft's 1,024-octet processing limit is ignored
for effective policy and is represented as invalid when it is a tracked attribute.

`Acceptance` is `accepted`, `rejected` or `indeterminate` under the implemented
RFC6265bis-22 subset. It is an analysis result, not proof of behavior in every
browser, user setting or future specification. Malformed cookie pairs and invalid,
mismatched or public-suffix Domain scope are rejected. Truncated evidence is
indeterminate instead of receiving a semantic conclusion: tracked attributes are
`truncated`, prefix and persistence are indeterminate, and identity/session-like
inference is suppressed.

## Session-like inference

`SessionLike` never identifies authentication. Names containing `session`/`sessid`
or conventional `sid` forms produce a medium-confidence name-pattern inference.
A non-persistent cookie without that pattern produces a low-confidence lifetime
inference. A persistent preference may still carry application state; no purpose,
account, privilege or exploitability is inferred. Deletion instructions do not
receive the lifetime inference.

## Bounds, ownership and privacy

Analysis accepts at most 128 fields, 4,096 bytes per field, 64 KiB total parser
input, 64 attribute segments per field, 256 bytes for a cookie name and 32 unique
unknown attribute names per cookie. A limit hit is explicit and suppresses a
definitive acceptance result. These are retained/parser-input limits, not a strict
process CPU or RSS ceiling. The HTTP transport's initial-header cap remains the
outer wire-facing defense.

Cookie values are never copied into the report, hashed, logged or exposed by a
cookie-analysis accessor. Unknown attribute values are also discarded. Cookie
names, effective Domain/Path and unknown attribute names are required evidence and
remain untrusted, potentially sensitive strings; callers must escape them for the
output context. Default Response JSON/fmt excludes the complete cookie report,
including those names and paths. The older explicit `HeaderValues("Set-Cookie")`
accessor remains sensitive and can expose the raw field.

`Report.Clone` and `Response.CookieAnalysis()` copy all nested slices. The response
captures the report immediately after response headers and before body reading, so
an incomplete body does not erase cookie evidence.

## Scope and references

This phase adds no cookie jar, request Cookie header, cross-response replacement,
browser execution, findings, severity or score. It does not treat a session-like
name as authentication or a broad Domain as a compromised subdomain. Partitioned
and other extensions are recorded only by sanitized attribute name in this phase.

The processing model is pinned to
[draft-ietf-httpbis-rfc6265bis-22](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/22/),
an active Internet-Draft in the RFC Editor queue as of this implementation. Domain
scope uses `golang.org/x/net/publicsuffix` v0.59.0, whose compiled PSL identifies
publicsuffix.org revision `d6c92f1bbb7433e5db7b8405c25d4035fb8ff376`
(2026-02-06). A dependency update can therefore change future PSL classifications
and must be recorded with scan/rule provenance by later reporting phases.
# Phase 11 consumer

The [finding engine](finding-engine.md) uses accepted, valid, untruncated,
non-repeated cookies with the explicitly limited session-like heuristic. It
never treats that heuristic as proof of authentication.
