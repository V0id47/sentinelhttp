# ADR 0004 — Approval capability and conservative network scope

Status: implemented for Phase 3, 2026-09-13.

## Decision

Keep parsing, policy, approval and safe dialing in one internal security package.
Production construction fixes the resolver/dialer implementations. Injection is
unexported for offline tests. An ApprovedEndpoint has no writable public state;
it is owner-bound, context-bound, expires in ten seconds and is atomically consumed
once. Copying the handle cannot create another authorization.

Classify all DNS results and deny mixtures with any disallowed address. Pin the
literal chosen address and port; verify the remote TCP peer. Never resolve again
inside dial, pool, retry or switch to a hostname string.

allow_private adds only RFC1918/ULA/loopback and forces same-host. Special-purpose
assignments and metadata remain denied. The policy intentionally rejects some
globally routable special assignments and noncanonical numeric targets. No PSL.

## Alternatives rejected

- Boolean IsSafe then client.Get(host): leaves DNS resolution TOCTOU.
- Public ApprovedEndpoint struct: callers can forge approved addresses.
- Public Consume method plus arbitrary dialer: creates another bypass interface.
- Selecting only public answers from a mixed result: masks an unsafe resolution.
- Raw URL debug output with query value filtering: leaks tokens in paths/keys.
- Goroutine wrapper to force timeout on a non-cooperative resolver: risks leaks.

## Consequences and design refinements

Separate logical host for DNS/HTTP/TLS from literal socket address. Retries and
future redirects require new approvals. No happy-eyeballs/fallback this phase.
The raw request URL is accessible only by an explicitly sensitive accessor;
default display removes path and whole query, stronger than the initial design's
query-values-only suggestion. This loses display detail but reduces secret exposure.

This package is not an OS security sandbox. TestSocketOwnership and independent
review enforce the intended source architecture; future transport additions must
preserve it. Successful connections transfer ownership to the caller.

Validation: offline fake DNS/dialer, real loopback fixture with explicit opt-in,
token-copy/concurrent replay tests, peer cleanup tests, fuzz invariants and the
Phase 3 report. No HTTP/TLS implementation or next-phase features added.
