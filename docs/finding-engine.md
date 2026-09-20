# Finding engine

`internal/core/findingengine` converts already captured HTTP evidence into a
bounded, versioned `Report`. `Evaluate(Input)` is pure: it performs no DNS,
network or file I/O and never initiates a probe or redirect journey. Callers
provide any ordinary exchanges, an optional redirect trace and an optional
CORS probe result. The engine performs no scan orchestration, scoring or
rendering; those are separate consumers.

```go
report := findingengine.Evaluate(findingengine.Input{
    Exchanges: []*httpclient.Response{response},
    Trace:     trace,     // optional
    CORSProbe: probe,     // optional
})
```

The machine-readable JSON uses snake_case fields. `EngineVersion` and all
initial `RuleVersion` values are `"1"`. Each finding separates the captured
observation, inference, conditional hypothesis, impact, remediation and
limitations. Severity describes the rule's conservative priority; confidence
describes evidence fit, not exploit success. The initial catalog emits only
`INFO` and `LOW`. A finding means *observed on at least one captured exchange*,
never *true for every route*.

## Rule catalog

All predicates require complete, applicable evidence for the relevant field.
An unavailable pre-header capture cannot establish absence. A body-read failure
after headers does not erase captured headers. A valid 4xx/5xx response may
still support a response-specific finding. The fixed catalog owns every
explanatory sentence and reference; server text is never interpolated.

| Rule | Required captured evidence | Severity / confidence | Scope of claim |
|---|---|---|---|
| `headers.hsts_not_active` | Complete header capture on verified HTTPS DNS host; applicable HSTS is absent or valid but inactive | LOW / HIGH | One response without active HSTS; no preload assertion |
| `headers.nosniff_absent` | Complete headers, valid HTML or JSON Content-Type context, XCTO absent | INFO / HIGH | Hardening signal absent; no MIME exploit assertion |
| `cookies.session_like_no_secure` | Accepted, valid, untruncated, non-repeated session-like cookie on verified HTTPS; Secure attribute absent | LOW / LOW or MEDIUM | Session-like is a heuristic, not authentication proof |
| `cookies.session_like_no_httponly` | Same cookie prerequisites; HttpOnly attribute absent | LOW / LOW or MEDIUM | No script access or XSS is established |
| `csp.no_complete_enforcement` | Complete CSP capture on applicable HTML; untruncated enforced set reports `enforcement_absent` | INFO / HIGH | No complete enforced header policy observed; no XSS claim |
| `csp.unsafe_inline_observed` | Complete applicable HTML capture; one non-truncated enforced policy reports `unsafe_inline_effective` | INFO / MEDIUM | One policy, possibly narrowed by other enforced policies |
| `csp.unsafe_eval_observed` | Same CSP prerequisites; one enforced policy reports `unsafe_eval_present` | INFO / MEDIUM | Policy observation, not exploit proof |
| `cors.sampled_reflection_with_credentials` | Recomputed assessment from two captured, matching synthetic-origin GET attempts reports `reflection_observed_for_samples` as `potential_risk` | LOW / LOW | Unauthenticated samples; no exposed data claim |
| `cors.vary_origin_shared_cache` | Recomputed assessment reports `vary_origin_missing` as `potential_risk` for a captured sample with explicit shared freshness | LOW / LOW | No actual cache or leak was tested |
| `redirects.https_to_http_proposed` | Captured followable HTTPS last hop; valid matching Location proposes HTTP; trace stopped `downgrade_blocked` | LOW / HIGH | Proposed destination was blocked before a request |
| `redirects.loop_or_limit` | Captured followable last hop and matching Location; trace stopped at exact loop or redirect limit | INFO / HIGH | Operation-specific navigation signal |
| `tls.leaf_expiring_soon` | Verified HTTPS metadata and TLS analysis; untruncated verified leaf classified `expiring_soon` | INFO / HIGH | Certificate observed within 30 days of expiry; no revocation check |

Report-only CSP, wildcard ACAO alone, unverified TLS dates, rejected or
truncated cookies, partial pre-header failures, and cross-host redirects alone
do not trigger these rules. Cookie confidence follows the upstream session-like
inference, capped at MEDIUM. CORS rules recompute from captured attempts rather
than trusting the mutable stored assessment. Trace rules check the terminal
response and resolve its Location again; these are consistency checks, not
proof that a caller-owned object is authentic.

## Identity, aggregation and limits

`FindingID` is lowercase SHA-256 of the NUL-separated tuple
`sentinelhttp-finding-v1`, rule ID and canonical safe origin. It excludes
exchange ID, timestamp, path, query and rule version. Each rule/origin pair
aggregates into one finding with sorted, deduplicated evidence references.
Findings sort by rule ID, origin and ID. Evidence sorts by source, exchange ID,
hop index, item index and code. A reference's inapplicable index is `-1`; real
indexes are zero-based. The ID identifies a rule/origin observation across
scans, not a specific scan or authenticated fact.

Evaluation processes the first 32 distinct valid exchange IDs from the
`Exchanges` slice and then trace hops. It inspects at most the first 256 slice
positions while seeking those exchanges, and at most 21 trace hops. It accepts
one optional three-attempt CORS probe. Output retains at most 256 findings and
16 references per finding. `OmittedInputs`, `OmittedFindings` and
`OmittedEvidence` count resource-cap omissions, which also set `Truncated`.
`SkippedInputs` counts nil, malformed or inconsistent caller-owned inputs and
conflicting response objects sharing an ID. An overlong trace cannot produce a
terminal stop finding because its true end lies outside the inspected window.
The 256-position guard may skip a later valid exchange; the report records
that omission instead of silently treating it as a complete scan.

## Privacy and trust

Finding targets contain only the canonical origin and existing redaction
marker. The engine validates that the origin round-trips through
`network.ParseTarget` and `SafeURL`, and that exchange IDs are 32 lowercase
hex digits. Evidence references contain only opaque IDs, fixed codes and
numeric indexes. Default JSON and formatting do not contain raw path, query,
fragment, Location, header or cookie value, cookie name, certificate text,
CSP source or raw error. Static catalog prose and URLs are reviewed with each
rule version. HTML and Markdown renderers must still escape output for
its context.

Input response, trace and probe structs are caller-owned. Validation cannot
attest their provenance and callers must not mutate them concurrently with
evaluation. The returned report and nested slices are owned by the caller.
The engine never sends credentials, executes a browser or validates an exploit.
Consumers must preserve the distinction between observed evidence
and a site-wide or authenticated security conclusion.
