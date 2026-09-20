# Configuration Score — Phase 12

`internal/core/scoring.Evaluate(primary)` calculates a bounded,
deterministic score from **one already captured primary response**. It calls
the Phase 11 finding engine for that same response. It does not make requests,
read files or use the current clock. The scanner chooses and records
which response is primary. CORS probes, redirect journeys, other paths and
authenticated behavior are outside this score and remain visible separately
as evidence and findings.

The score model version is `1`. JSON is authoritative for its machine-readable
form. `value` is an integer from 0 to 100 when available, or `null` with
`status: "insufficient_evidence"`. The label is **Configuration Score**.
Always display `coverage_percent` and the four components beside the number.
The score reflects only the checks performed on one response; it is not a
security level, vulnerability count, exploitability estimate or site-wide
guarantee.

## Coverage and formula

The four fixed domain weights sum to 100:

| Domain | Weight | Assessed when |
|---|---:|---|
| TLS | 20 | HTTPS metadata and TLS analysis both verified, with an untruncated presented leaf |
| Headers | 30 | Complete capture, known content-type context and at least one applicable, complete HSTS or XCTO check; malformed relevant fields make the domain unavailable |
| Cookies | 20 | Complete untruncated capture on verified HTTPS with an accepted, valid, non-repeated, untruncated cookie that the upstream heuristic calls possibly session-like |
| CSP | 30 | Complete capture on applicable HTML with untruncated overall observations and enforced policy set |

HTTP makes TLS `not_applicable`. A complete cookie capture with no eligible
session-like cookie makes cookies `not_applicable`. Redirect or no-content
responses make CSP `not_applicable`; other non-HTML representations remain
`unavailable` because the upstream analyzer does not establish document
applicability. A pre-header failure cannot establish any positive coverage.
A body failure after headers leaves independently complete categories intact.

`possible_weight` sums all domains except `not_applicable` ones.
`assessed_weight` sums only `assessed` domains. Coverage is the half-up rounded
percentage `100 × assessed_weight / possible_weight`, or 0 if nothing is
possible. A numeric score needs at least two assessed domains and at least
50 assessed weight. Skipped or truncated finding-engine input also suppresses
the number. Missing evidence is never treated as a passing check.

For an available result, subtract the fixed penalties below from assessed
domain weights, cap each domain deduction at its weight, then calculate
`round_half_up(100 × (assessed_weight − capped_penalties) /
assessed_weight)`. Rule evidence is grouped per origin, so each rule deducts
at most once. The per-component penalty list shows the exact arithmetic.

| Finding rule | Penalty points |
|---|---:|
| `tls.leaf_expiring_soon` | 6 |
| `headers.hsts_not_active` | 12 |
| `headers.nosniff_absent` | 4 |
| `cookies.session_like_no_secure` | 6 |
| `cookies.session_like_no_httponly` | 4 |
| `csp.no_complete_enforcement` | 16 |
| `csp.unsafe_inline_observed` | 5 |
| `csp.unsafe_eval_observed` | 4 |

The weights are explicit product policy, not CVSS values or probabilities.
Cookie penalties are modest because “session-like” is a LOW/MEDIUM-confidence
heuristic. CSP unsafe-source penalties are modest because another enforced
policy can narrow the combined effect. Version changes must document any
formula or weight revision; an old score and a new-version score should not be
compared as though their scales were identical.

## Privacy and use

The score target is the canonical origin-only redacted string. JSON and
formatting contain only fixed labels, rule IDs, statuses, numeric fields and
static limitations. They do not contain path/query/fragment, header/cookie
values or names, CSP sources, certificate text or raw errors. Each human
renderer escapes displayed fields for its output context.

The scoring report and its nested slices belong to the caller. The source
`httpclient.Response` remains caller-owned and must not be mutated concurrently
with evaluation. The score does not compensate for checks SentinelHTTP did not
perform and should never be the sole basis for a security decision.
