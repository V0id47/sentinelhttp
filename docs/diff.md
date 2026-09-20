# Semantic report diff

`sentinelhttp diff OLD.json NEW.json [--format terminal|json] [--output FILE]`
compares two locally stored, validated reports. It makes no network requests.
`--lang en|es|ru|zh-CN` localizes terminal labels; JSON is unchanged.
JSON is the versioned interchange (`diff_version: "1"`); terminal output quotes
dynamic text, including control and bidirectional characters. Inputs have an
8 MiB cap each and output to a file is private, atomic and no-clobber.

The displayed target hides path and query. Each report records only whether
the canonical initial URL was the root path with no query (`target_scope:
"root"`) or had a redacted path/query (`"redacted"`). The automatic diff
compares only root scans of the same origin; redacted endpoints are
`incomparable` because it cannot prove they were the same URL. No digest of
path or query is stored. Reports remain sensitive because other projected
metadata can reveal configuration.

Findings match by stable finding ID and rule version. A finding can be called
new or resolved only when both primary requests completed, neither finding
set is truncated or omitted, and scan coverage is comparable. Multi-hop
traces and CORS probes deliberately make one-sided findings `unknown`, because
the origin-redacted report cannot prove that exactly the same endpoint paths
were assessed. Matching findings may still show a severity change under the
same rule version. A rule-version mismatch is `unknown`.

Headers, root-path cookies, TLS negotiation and leaf certificate fingerprint,
and CSP are compared on successful primary captures for the same final safe
origin. Cookie policy includes host-only scope. Scoped cookie paths are not
retained, so their policy changes are `unknown`. Redirect journeys compare
only complete terminal traces under the same scope/redirect policy; multi-hop
paths are redacted and therefore `unknown`. IDs, timings, IPs, evidence order and certificate
days remaining are ignored. A partial result contains trustworthy changes
alongside explicit `unknown` sections; absence of a change is not proof of
equivalent security. CORS probe and score changes are not interpreted by this
first diff version.
