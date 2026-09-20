# CORS analysis

SentinelHTTP records CORS response evidence without interpreting a permissive
header as proof of data exposure. The implementation follows the
[WHATWG Fetch Living Standard snapshot of 2026-09-02](https://fetch.spec.whatwg.org/#http-cors-protocol),
with `Vary` and explicit cache context from
[RFC 9110 §12.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#name-vary) and
[RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html).

## Passive capture

Every completed `Client.Do` response is passed to the pure `corsanalysis`
package immediately after headers arrive and before body reading. The report
remains available when a later body read fails. A failure before headers yields
`capture_unavailable`, not an inference that CORS headers are absent. Passive
analysis sends no `Origin` or other additional request header.

`Response.CORSAnalysis()` returns a deep copy of the bounded report. It records
the status and occurrence count of ACAO, ACAC, `Vary`, allow-methods,
allow-headers, expose-headers and max-age, plus narrow Cache-Control facts needed
for contextual `Vary` assessment. ACAO is classified as absent, `*`, literal
`null`, one conservative serialized HTTP(S) origin, invalid, ambiguous or
truncated. `null` is distinct from the wildcard. Repeated or comma-separated
ACAO cannot match a single origin under Fetch's CORS check. Only a single exact
lowercase `Access-Control-Allow-Credentials: true` enables the ACAC flag;
duplicate or differently cased values do not. These are header observations,
not a browser simulation: the ordinary request has no `Origin` to compare.

At most 16 values per relevant field, 4,096 bytes per value and 32 KiB of total
relevant input are analyzed. Oversized evidence is explicitly truncated;
unsafe/invalid bytes are invalid rather than silently normalized. A truncated
or malformed field cannot establish a positive CORS conclusion. Raw invalid
values are not retained. Only valid bounded origin and token components may
appear in the explicit report, and they remain untrusted display text. The
default `Response` JSON/format output omits the report and all header values;
`HeaderValues` remains a separate sensitive raw-header accessor.

## Opt-in probes

`Client.ProbeCORS(ctx, target)` is a separate explicit operation. It performs
at most three sequential header-only exchanges to exactly that target:

1. `GET` with `Origin: https://sentinelhttp-probe-a.invalid`.
2. `GET` with `Origin: https://sentinelhttp-probe-b.invalid`.
3. `OPTIONS` with the first origin, `Access-Control-Request-Method: GET` and
   `Access-Control-Request-Headers: X-SentinelHTTP-Probe`.

The `.invalid` origins are fixed strings, never destinations to resolve. Each
exchange receives a fresh scope approval and verified dial from
`network.Boundary`. A single batch deadline is no later than the client's
configured `TotalTimeout` and respects an earlier caller deadline. There is no
redirect following, proxy, retry, cookie jar, authentication header, client
certificate, generic custom-header API, decompression or response-body read.
The probe result records the state, safe error code and bounded CORS report of
each attempt; later slots stay `not_run` after a pre-header failure. A captured
HTTP 4xx/5xx is still response evidence. Redirect responses describe only
themselves and are not treated as evidence about their destinations.

Two exact ACAO echoes for the two fixed origins are reported as
`reflection_observed_for_samples`, not universal origin acceptance. If both
also advertise exact ACAC `true`, the result is a `potential_risk` for manual
review, not authenticated exposure. Wildcard ACAO plus ACAC `true` is recorded
as a credentialed-browser configuration mismatch: Fetch does not share a
wildcard response when credentials mode is `include`. A non-credentialed request
can still use the wildcard, and a public resource is not automatically weak.

The one preflight is `consistent_with_allowance` only when its response has an
ok status, ACAO allowing the first fixed origin or `*`, and an allow-headers
list containing `X-SentinelHTTP-Probe` or non-credentialed `*`. `GET` is a
CORS-safelisted method, so the preflight need not explicitly list it in
allow-methods; a malformed or truncated allow-methods list still prevents a
positive assessment. Missing required headers or a non-ok, non-redirect response is
`not_observed_allowed`; a redirect, malformed/truncated relevant header or
missing response is `indeterminate`. The operation does not send a subsequent
GET carrying the synthetic header, so this is only one sampled preflight shape.

Missing `Vary: Origin` is reported only when the two captured non-redirect GET
responses demonstrably vary in ACAO, and only for a sample lacking both
`Vary: Origin` and `Vary: *`. It remains an observation unless that same
response has explicit shared-cache freshness evidence: positive `s-maxage`, or
`public` with positive `max-age` when `s-maxage` is absent, with no `private`,
`no-store` or `no-cache`. An explicit `s-maxage=0` takes precedence over a
positive `max-age`.
Only then is it a `potential_risk` for cache confusion. Static ACAO values do
not require this signal. The narrow cache predicate may miss other cacheable
responses, but avoids inferring cache exposure from headers alone.

The classification vocabulary is `observation`, `misconfiguration` and
`potential_risk`. The analyzer has no `confirmed_exposure`, browser
execution, authenticated request, sensitive-data analysis or
cross-resource/redirect-chain conclusion. The CLI exposes the opt-in
operation as `--probe-cors`.
## Finding engine consumer

The [finding engine](finding-engine.md) rebuilds probe samples from matching
captured attempts and reruns the pure assessment. It emits only two conditional
LOW findings; the passive CORS report alone does not prove exposure.
