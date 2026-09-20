# Response header analysis — Phase 6

Implemented 2026-09-18 in `internal/core/headeranalysis`. The package is pure and
deterministic: it performs no DNS, socket, file or clock I/O. It analyzes the
headers from the one response already obtained by `httpclient`.

## Capture and context

`capture_unavailable` means no response headers were received. It returns no
per-header results, so a transport/TLS/protocol failure cannot be misreported as
missing security headers. `capture_complete` means Go accepted the initial header
block. Individual retained values can still be truncated by the analysis limits.

Context is kept separate from parsing:

- 3xx responses are `redirect`; 204 and 304 are `no_content`.
- One valid Content-Type selects HTML, JSON or other. Missing, malformed, repeated
  or overlong values leave representation unknown, with a specific context state.
- HSTS is applicable only to verified HTTPS on a DNS name. HTTP and IP literals
  are ignored; other incomplete contexts remain unknown.
- CSP, Permissions-Policy and XFO are applicable to HTML here. COOP and COEP also
  require a known trustworthy context; plain HTTP remains conservatively unknown.
- XCTO and CORP remain applicability-unknown because their effect depends on the
  consuming fetch/resource context unavailable in this phase.

Applicability does not rewrite parser status. For example, a syntactically valid
COOP value on plain HTTP remains `valid` with applicability `unknown`.

## Result model

Every complete capture returns ten results in fixed order. Status is one of:
`absent`, `valid`, `invalid`, `ambiguous`, `ignored`, `observed`, `deferred`,
`truncated` or `unrecognized`. `Effective` records only the field algorithm
implemented here; it is not a vulnerability, browser guarantee or final finding.
No severity or score is assigned in this phase.

| Header | Phase 6 interpretation |
|---|---|
| Content-Security-Policy | `observed` bounded header evidence. Detailed policy parsing, separate report-only processing and `frame-ancestors`/XFO correlation are provided by Phase 8 `cspanalysis`. |
| Strict-Transport-Security | First field only; unique directive names; required numeric max-age accepts token or quoted-string form; max-age=0 is inactive; includeSubDomains/preload recorded without claiming preload registration. |
| X-Content-Type-Options | Browser first-token behavior; `nosniff` can be effective while a nonconforming combined field is invalid. |
| Referrer-Policy | Last recognized standard token wins; unknown-only input is unrecognized. |
| Permissions-Policy | RFC 9651 dictionary with direct Items or Inner Lists; Token/String allowlist entries retain their type; Strings are checked against the CSP scheme-source/host-source grammar; unsupported items are ignored per field rules; a repeated key uses the last member and is marked repeated. Feature support/default allowlists are not inferred. |
| X-Frame-Options | Current HTML set processing for DENY/SAMEORIGIN and conflicting/repeated fields. Phase 8 consumes this normalized result for observed CSP `frame-ancestors` precedence; it does not make a clickjacking finding. |
| Cross-Origin-Opener-Policy | One Structured Fields token plus valid parameters; invalid/unknown values have effective fallback `unsafe-none`. |
| Cross-Origin-Resource-Policy | One exact case-sensitive `same-origin`, `same-site` or `cross-origin` token. |
| Cross-Origin-Embedder-Policy | One Structured Fields token; invalid/unknown values have effective fallback `unsafe-none`. |
| Server | `observed` untrusted claim only; no product, version or CVE inference. |

The parser follows field-specific duplicate rules instead of globally joining or
discarding values. HSTS uses the first field. Referrer-Policy scans comma tokens.
XFO evaluates the resulting lowercase set. COOP/CORP/COEP reject multiple combined
items. COOP/COEP parameters use the complete bounded RFC 9651 bare-item grammar.
Permissions-Policy applies Structured Fields dictionary last-member wins. A direct
allowlist value with the wrong type is ignored; an invalid `report-to` type is
recorded separately and does not suppress an otherwise valid allowlist.

## Bounds, ownership and privacy

Only the ten tracked fields are retained. Limits are 16 values per field, 4,096
bytes per retained value and 32,768 bytes total; Content-Type context inspection is
limited to 1,024 bytes. Invalid UTF-8, control characters and Unicode format
characters become U+FFFD in retained evidence. Valid HTAB whitespace may still be
interpreted by a field-specific algorithm while the displayed evidence is
sanitized; other unsafe controls produce an invalid result without an effective
value. If a
value/count/global limit is hit, that result is `truncated` and no syntax/effect
conclusion is made.

`Report.Values(id)` is the explicit untrusted evidence accessor. Raw values are in
a private map and do not appear in default report JSON/fmt. Parsed tokens and
Permissions-Policy values are also untrusted strings and require output-context
escaping. `Clone`, `Result` and the HTTP response accessor deep-copy nested slices.
The default HTTP Response JSON/fmt omits the whole header report.

The analysis is captured immediately after response headers and before body read.
Thus a premature body close still returns header results. It does not inspect or
sniff body bytes and cannot upgrade an unknown Content-Type context.

## Phase 8 boundary, deferred work and references

The generic report remains the bounded raw-header/context source for Phase 8. Its
`Values(ContentSecurityPolicy)` accessor can expose retained enforced CSP fields
and is sensitive/untrusted; it does not add a report-only CSP accessor. It neither
merges policies nor performs CSP semantics. The dedicated report is obtained via
`Response.CSPAnalysis()` and is documented in [CSP analysis](csp-analysis.md).
Findings, contextual severities and score contribution remain deferred to their
catalog/reporting phases. Absence of Permissions-Policy, COOP, CORP or COEP is not
treated as a universal weakness.

Normative bases: [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797),
[RFC 9651](https://www.rfc-editor.org/rfc/rfc9651),
[Fetch](https://fetch.spec.whatwg.org/),
[HTML](https://html.spec.whatwg.org/),
[Referrer Policy](https://www.w3.org/TR/referrer-policy/) and
[Permissions Policy](https://www.w3.org/TR/permissions-policy-1/).
# Phase 11 consumer

The [finding engine](finding-engine.md) consumes only complete, applicable HSTS
and nosniff results. It does not reinterpret raw header values or promote a
pre-header failure into an absence finding.
