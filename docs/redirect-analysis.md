# Redirect analysis

`Client.TraceRedirects(ctx, target, options)` explicitly follows a bounded GET
journey and returns an ordered trace. Ordinary `Client.Do` still performs one
exchange. The operation implements a conservative subset of [RFC 9110 Location
semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-location) and uses
the [Fetch redirect-status set](https://fetch.spec.whatwg.org/#statuses):
301, 302, 303, 307 and 308. Other responses, including 300 and 304, end the
journey without being followed. It does not emulate browser navigation.

## Request and scope model

Each attempted hop calls the existing single-exchange client with GET and a
header-only profile. The client requests a fresh `Boundary.Approve`, resolves
and classifies all returned addresses, and dials only its single-use approved
IP:port. The connected peer must match the approval; HTTPS keeps strict
logical-host certificate validation. This happens again even if a hostname
repeats. There are no environment proxies, retries, pooled connections,
cookie jar, credentials, arbitrary request headers or response-body reads.
The response body is closed at headers, including on the terminal hop.

The default maximum is 10 redirects; callers may choose 1–20. Invalid options
fail before network I/O. A single deadline no later than the client's
`TotalTimeout` covers the whole journey and respects an earlier caller
deadline. At most `MaxRedirects+1` exchanges are attempted. `SameHost` can
only tighten the boundary's existing host policy; when private-lab access is
enabled, the boundary already forces same-host operation. A different public
host is eligible only when the boundary permits it, and cross-host movement is
recorded as an observation rather than a vulnerability claim.
The default public-host policy may therefore send a GET to another public host
named by an untrusted `Location`. Set `SameHost` when the assessment is
authorized only for the starting host. `SameHost` compares the canonical
hostname or IP literal; it does not bind the journey to one port or service.
An assessment restricted to one origin or port needs a stricter caller policy
before enabling the trace.

## Location and stop semantics

The trace follows only a captured 301/302/303/307/308 response with exactly
one nonempty `Location` field. `Location` is a single URI-reference, so commas
inside it are data; repeated fields are treated as ambiguous and not followed.
The field is capped at 8,192 bytes. Invalid UTF-8, whitespace, control/format
characters, backslashes, malformed escapes and overlong resolved URLs stop
navigation. Relative, scheme-relative and query-only references resolve
against the current request URL before `network.ParseTarget` validates the
next HTTP(S) target. Fragments are never sent as part of an HTTP request; the
raw original field is available only through the explicit sensitive accessor.
A syntactically valid URI-reference can still fail target validation (for
example an unsupported scheme); this stops as `target_invalid` while the
Location classification remains `valid`.

The ordered stop codes distinguish terminal response, missing/ambiguous/
invalid Location, invalid next target, blocked downgrade, same-host
restriction, exact loop, redirect limit and failed request or scope approval.
An HTTPS-to-HTTP proposal is recorded and blocked before DNS or connection;
HTTP-to-HTTPS can proceed after validation. Exact revisits of the normalized
request URL stop before another request. Non-identical URLs that lead to a
server-side loop remain bounded by the redirect limit. When several reasons
apply, invalid target, downgrade, same-host restriction, loop and limit are
evaluated in that order.

A failed pre-header attempt is retained as a hop with safe failure metadata;
it is not counted as a captured response. Network and approval failures
return both the partial trace and the existing safe error code. A captured
response with a policy or parsing stop returns the trace without a raw error.
The response count covers captured HTTP responses, while redirects-followed
counts only later captured responses. `not_applicable` Location state on a
non-follow status does not imply that a Location field was absent.

## Evidence and limits

Each hop exposes a redacted `network.Target` and its `Response`, whose explicit
accessors provide status, protocol, resolution record, verified peer, TLS and
header/cookie/CSP/CORS analysis. `HeaderValues("Location")` is the only way
to retrieve the raw field and must be handled as untrusted, potentially
sensitive text. Default trace JSON and formatting reveal no path, query,
fragment or raw Location. The caller owns the returned trace and slices.

The trace emits observations for cross-host or scheme changes and blocked
downgrades, not proof of exploitability. It
does not execute a browser, parse HTML or JavaScript redirects, issue
authenticated requests, inspect response bodies, perform arbitrary method
rewriting or inherit browser fragments. The CLI exposes the opt-in trace with
`--trace-redirects`, `--max-redirects` and `--same-host`.
## Finding engine consumer

The [finding engine](finding-engine.md) examines bounded terminal trace evidence
for a proposed HTTPS downgrade or exact loop/limit stop. It does not follow any
redirect, and suppresses stop findings when the caller trace exceeds its cap.
