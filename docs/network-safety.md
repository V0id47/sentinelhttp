# Network safety — scope-v1

## Canonical target

HTTP/HTTPS only, absolute URL, nonempty host, no userinfo. Default ports 80/443;
explicit canonical decimal ports 1–65535, no zero/leading zeros/signs/overflow.
Paths and valid queries are preserved for the approved HTTP request. Fragments are removed.
Malformed query escapes are rejected explicitly because net/url does not validate
RawQuery itself. No credentials are extracted from URLs. Rejection cannot remove
a secret already typed into shell history: that is outside this library.

DNS names use `idna.Lookup.ToASCII` plus strict ASCII DNS label checks. Names are
lowercased and one trailing root dot is stripped. Thus EXAMPLE.com. and example.com
have identical scope/DNS/TLS identity. Empty/interior empty labels, multiple final
dots, underscores, controls, format characters and host escapes are rejected.
Raw targets are limited to 8192 bytes and valid UTF-8. IDNA normalization is not a
visual homograph guarantee; display uses canonical ASCII, not a prettified Unicode
name. No custom punycode conversion exists.

Bracketed IPv6 is canonicalized through netip. Zone IDs are rejected. Mapped IPv6
is unmapped before policy and connection. Literal IPs skip DNS but not approval.
Historical numeric forms (2130706433, 0177.0.0.1, 0x7f000001, 127.1) are rejected:
the netip regression test confirms these are not accepted canonical IPs. A lexical
numeric-ambiguity guard rejects them without implementing legacy conversion.
Valid IPs with a trailing dot are rejected as ambiguous rather than sent to DNS.

## Classification

netip.IsPrivate covers RFC1918 and IPv6 ULA, not all non-public space.
IsGlobalUnicast can be true for private/special-use addresses, so it is not the
policy by itself. IsLoopback, IsLinkLocalUnicast, IsMulticast, IsUnspecified and
IsPrivate are supplemented with explicit versioned ranges and invalid/zone checks.
[Go netip](https://pkg.go.dev/net/netip).

Default allows canonical public unicast only. The following classes are denied:

| Class | Examples / coverage |
|---|---|
| private | 10/8, 172.16/12, 192.168/16, fc00::/7 |
| loopback | 127/8, ::1 |
| link_local | 169.254/16 including 169.254.169.254; fe80::/10 |
| unspecified | 0.0.0.0, :: |
| multicast | IPv4 224/4, IPv6 ff00::/8 |
| documentation | 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32, 3fff::/20 |
| reserved | 0/8 remainder, 192.0.0/24, 192.31.196/24, 192.52.193/24, 192.175.48/24, 240/4, 2620:4f:8000::/48 |
| other_non_global | 100.64/10, 198.18/15, 192.88.99/24, 2001::/23, 2002::/16 and other non-public IPv6 |
| cloud_metadata | fd00:ec2::254, permanently denied before ULA opt-in |
| invalid | Invalid netip values and addresses with zone identifiers |

Global IPv6 candidates are restricted to 2000::/3, with listed exceptions denied.
This excludes NAT64 well-known/local-use prefixes, discard-only, obsolete site
local and unallocated/transition classes conservatively. Not every deny means the
address is technically unroutable. Special assignments (for example 192.0.0.9)
remain denied even where IANA permits global reachability. The intentional cost
is some false denials, never silently relaxing scope. The `reserved` label means
policy-reserved, not necessarily the IANA Reserved-by-Protocol column.

Sources reviewed 2026-09-13: [IANA IPv4 special registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IANA IPv6 special registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).
Tables are pinned in code, not downloaded during scans. Changes require review,
boundary tests and a policy-version change. A static registry needs maintenance.

## allow_private

Only adds RFC1918, ULA and loopback. Also makes SameHost effective so a lab scan
cannot redirect to a different hostname accidentally. IP reassignment within
the allowed lab classes is intentionally permitted by that opt-in. Link-local,
metadata, invalid, unspecified, multicast and special ranges remain blocked.
Known metadata DNS names and their subdomains are explicitly denied:
metadata.google.internal, metadata.goog, instance-data.ec2.internal. This list is
defense in depth, not provider discovery or an exhaustive metadata inventory.

## Resolution, approval and connection

Each operation calls the system resolver with network `ip` for A/AAAA results.
DNS results may come from OS cache/hosts/search behavior; no DNSSEC or canonical
CNAME chain evidence is claimed. Every returned address is classified before
selection. Any denied member prevents approval; a mixture of allowed/denied
members gets mixed_scope_resolution. All-denied returns the first denied class
with per-address decisions. Duplicate records are preserved. Selection uses the
lowest canonical netip address, deterministically, with no retry/fallback.

Limit: 64 answers, otherwise reject without iterating an unbounded response.
This caps application processing, not allocations already made by the system
resolver. DNS and connect default to three seconds, configurable to at most ten
seconds, always constrained by supplied contexts. Dependencies must honor context;
wrapping an arbitrary resolver that ignores cancellation in a goroutine would
not solve resource exhaustion and is deliberately avoided.

ResolutionRecord includes canonical host, source, policy version, UTC start/end,
returned/normalized addresses, per-address classification/decision, chosen endpoint
and overall decision. Zone text is never preserved: a rejection marker replaces
it. Literal source is distinct from system_resolver. No raw URL, query or cause.

The selected IP:port is held in an opaque approval with ten-second lifetime,
single-use atomic state and boundary ownership. Dial uses only that literal
AddrPort string. No environment proxies, implicit DNS during dial, pooling,
application retries or hostname failover. RemoteAddr must be a valid TCP peer,
without zone, matching normalized IP and exact port. Failure closes the socket.

## Safe display and errors

RequestURL intentionally returns sensitive request data for the HTTP
client. Do not log it. SafeURL, normal Target formatting and JSON omit **all**
path/query/fragment data, including keys, and retain only the canonical origin.
This is stricter than query-values-only redaction and prevents tokens in paths or
query names from leaking. Boundary stores only initialHost. ApprovedEndpoint
formatting is safe; raw capability state is not an evidence serialization API.

No promise that a hostname itself contains no sensitive identifiers. The operator
must treat canonical origin/address evidence as potentially sensitive assessment
data. Do not stringify arbitrary nested private structures or use unsafe/reflection
to extract secrets. Reporting uses its own narrow explicit projection.

Fault.Error returns only a stable Code. Distinct DNS not-found, temporary, timeout,
empty-answer and generic failures are retained; arbitrary internal error text is
discarded. No Unwrap exposes resolver strings. The presentation layer
localizes fixed codes without exposing resolver text.

## HTTP client integration

The implemented httpclient uses Boundary.Approve and Boundary.Dial for every call.
Its transport cannot resolve/dial independently: callbacks lease one existing
verified socket. No proxy environment, connection reuse, retry, failover or redirect
following. The source-ownership test recognizes the reviewed adapter.

HTTPS uses logical TLS identity and strict verification. Windows/macOS/iOS require
explicit CA PEM to prevent native verifier AIA/root retrieval outside Boundary.
HTTP body/header limits and protocol lifetime cancellation are described in
http-client.md; they do not change IP classification or allow_private semantics.

## Redirect integration

`TraceRedirects` validates a proposed next target through `ParseTarget` and
then repeats `Boundary.Approve` and `Boundary.Dial` for each permitted hop.
Resolution and peer evidence are per request; an earlier hostname approval is
never reused after a redirect. The optional `SameHost` journey flag can only
tighten the boundary's own policy. HTTPS-to-HTTP transitions, exact loops and
limit excess stop before another outbound request. `Client.Do` and CORS probes
still do not follow redirects. See redirect-analysis.md for the hop contract.
