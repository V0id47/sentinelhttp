# CSP policy analysis

Implemented 2026-09-18 in `internal/core/cspanalysis`. This pure, deterministic
package analyzes bounded header-delivered Content Security Policy evidence. It is
pinned to the **W3C Content Security Policy Level 3 Editor's Draft 2026-09-16**.
That is an Editor's Draft, so later changes are outside this recorded baseline.

## Capture, ownership and policy boundaries

`httpclient` invokes `cspanalysis.Analyze` after response headers are accepted and
after generic header analysis, but before the response body is read. Input consists
only of separate enforced and report-only field values, normalized document
applicability, and normalized X-Frame-Options (XFO) evidence. The package performs
no I/O, DNS, URL requests, body/DOM parsing, browser execution, findings, severity
or score generation.

`capture_unavailable` means no response headers arrived. `capture_complete` means
the response header block was received; a later body error cannot erase its CSP
report. Document applicability is `applicable` for HTML, `not_applicable` for a
redirect or no-content response, and `unknown` otherwise.

The report has distinct `Enforced` and `ReportOnly` policy sets. Every CSP field
and every comma-separated serialized-policy-list member becomes its own policy;
the analyzer never joins fields, merges source lists, or turns enforced policies
into one union. Each policy records disposition, field/member indexes, parse state,
ordered directives, syntax issue count and truncation. All enforced policies apply
cumulatively, so policy-scoped observations do not claim the combination permits a
behavior.

`Response.CSPAnalysis()` and `Report.Clone()` deep-copy all nested policy,
directive, source, control and observation slices. Default `Response` JSON and
formatting contain metadata only, never the CSP report. Explicit structured report
text is target-controlled and must be escaped for its eventual output context.

## Parser and source evidence

Within a policy, semicolons separate directives; CSP ASCII whitespace separates
tokens; directive names use ASCII case-folding; and the first occurrence wins.
Later duplicates are retained only as an ignored-duplicate count. Names outside the
ASCII letter/digit/hyphen grammar, non-ASCII/unsafe tokens and invalid controls
become partial or invalid structured evidence. Unknown directives are represented
as opaque directives with an opaque-token count only.

Source-list parsing applies to `default-src`; script/style directives and their
element/attribute forms; `object-src`, `base-uri`, `frame-ancestors`,
`form-action`, `connect-src`, `img-src`, `font-src`; and the fallback-supporting
`child-src`, `frame-src`, `media-src`, `manifest-src` and `worker-src`. It classifies
only complete expressions as a recognized quoted keyword, scheme, host, general
wildcard, nonce, hash or invalid source. Host sources can retain normalized scheme,
host, port, path and subdomain-wildcard state. A DNS host may have a single trailing
dot: the remaining DNS name is limited to 253 bytes. U-labels are invalid; accepted
A-labels are not resolved or contacted. A source-list containing `'none'` plus
other expressions is marked nonconforming, and an empty source list remains an
explicit restrictive control.

`frame-ancestors` has its narrower ancestor-source grammar: it permits a scheme,
host (including the bare `*` host part), `'self'`, or sole `'none'`. It rejects
nonce/hash and all other keywords. A mixed `'none'` list is partial and
nonconforming. A retained
enforced `frame-ancestors` directive still has CSP/XFO precedence even when that
directive's source list is nonconforming; the report does not claim the malformed
source list is an effective ancestor restriction.

Nonce and hash payloads are never retained. Their source records hold only kind,
grammar validity, `Redacted=true`, and for hashes the canonical `sha256`, `sha384`
or `sha512` algorithm. The report also never retains complete CSP fields, reporting
endpoints or opaque directive values. Existing `HeaderValues` and the generic
header-analysis `Values(ContentSecurityPolicy)` remain explicit sensitive raw
accessors; consumers must avoid logging them. Retained source components own their
bytes and do not keep a complete raw CSP field backing allocation reachable.

## Effective controls and observations

Controls are selected separately inside each non-truncated policy. The exact CSP3
fallback chains are:

| Control | Chain |
|---|---|
| script element | `script-src-elem` → `script-src` → `default-src` |
| script attribute | `script-src-attr` → `script-src` → `default-src` |
| style element | `style-src-elem` → `style-src` → `default-src` |
| style attribute | `style-src-attr` → `style-src` → `default-src` |
| worker | `worker-src` → `child-src` → `script-src` → `default-src` |
| frame | `frame-src` → `child-src` → `default-src` |
| object, connect, image, font, media, manifest | named directive → `default-src` |
| base URI, frame ancestors, form action | explicit directive only; no fallback |

Each control is `explicit`, `fallback`, `unrestricted`, or `indeterminate`.
Malformed/discarded candidates and incomplete evidence make the affected result
indeterminate; truncation produces no effective controls. Structural duplicate and
nonconforming observations survive unrelated partial-policy syntax errors, and
permissive observations survive when their selected effective control is complete.
Truncation still suppresses all policy-derived observations. `unrestricted` means
only that the individual policy supplied no complete control and is never proof of
browser exploitability.

The bounded observation codes are evidence-level configuration signals:
`enforcement_absent`, `report_only_without_enforcement`,
`duplicate_directive_ignored`, `source_list_nonconforming`,
`unsafe_inline_effective`, `unsafe_eval_present`, `general_wildcard_present`,
`object_sources_permitted`, `object_control_absent`, `base_uri_control_absent`,
`frame_ancestors_control_absent` and `form_action_control_absent`. They have no
severity, remediation, exploit or final-finding meaning. `'unsafe-inline'` is
effective only when the selected complete script/style list has no nonce/hash, and
for script also no `'strict-dynamic'`. General `*` is distinct from a host
subdomain wildcard. `enforcement_absent` and
`report_only_without_enforcement` require complete, non-truncated enforced
evidence, while still reporting an empty or invalid-but-fully-analyzed enforced
set. `object_control_absent` requires complete enforced evidence but is independent
of document applicability. The base-URI, frame-ancestors and form-action absence
observations additionally require applicable HTML. Missing evidence cannot create
any of these conclusions.

## XFO relation and bounds

For applicable HTML, a complete retained enforced `frame-ancestors` directive
records `csp_overrides_xfo`, including when unrelated policy syntax is partial,
its own source list is nonconforming, or a later directive truncates the policy. A
report-only policy never overrides XFO. Truncation before `frame-ancestors`, or
inside that directive, leaves no complete retained directive and records
`indeterminate`. If complete frame-ancestors evidence establishes that no retained
directive exists, valid effective XFO records `xfo_fallback_observed`; unrelated
invalid or partial directives do not block that fallback. Set/policy truncation or
a discarded `frame-ancestors` candidate can hide the directive and remain
`indeterminate`. Absent valid controls record `no_observed_framing_control`.
Missing capture or unknown/not-applicable context also records `indeterminate`.
This is precedence evidence only, never a clickjacking conclusion.

Limits are 16 field values per disposition, 4,096 bytes per field, 64 KiB total
input across both dispositions, 32 policies per disposition, 64 directives per
policy, 256 source/opaque tokens per policy, 1,024 bytes per token, 512 retained
path bytes, 256 retained bytes for every other source component, and 64 observations.
Any limit hit is explicit truncation. It suppresses affected effective/assessment
conclusions and is an input/retention bound, not a strict CPU or RSS guarantee.

## Explicit limitations

This analyzer handles response headers only. It does not parse meta CSP, a document
body or DOM; match concrete resource URLs; inspect report endpoints; simulate a
browser or violation; intersect arbitrary source sets across multiple enforced
policies; prove nonce entropy/uniqueness/reuse; or prove XSS or clickjacking. It
does not implement CORS.

Normative reference: [CSP Level 3 Editor's Draft (2026-09-16)](https://w3c.github.io/webappsec-csp/).
## Finding engine consumer

The [finding engine](finding-engine.md) consumes complete applicable HTML CSP
observations. Unsafe source findings describe one non-truncated enforced policy;
they do not claim that the intersection of all policies permits that behavior.
