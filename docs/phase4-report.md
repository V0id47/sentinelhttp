# SENTINELHTTP PHASE 4 REPORT

Verified 2026-09-16. Local workspace only; no Git initialization, remote or release.

## Status

**PASS WITH LIMITATIONS**. Phase 4 secure HTTP client implemented. No phases 5+.
Important new restriction: Windows/macOS/iOS HTTPS requires explicit operator CA
PEM; default native trust validation is not used because it can fetch outside scope.

## HTTP architecture

`internal/core/httpclient`: immutable Client configuration, per-call response and
transport. Boundary approval/dial -> peer-verified connection -> optional strict
TLS -> one-use transport lease -> single RoundTrip -> bounded read -> close.
Methods are GET, HEAD and OPTIONS only. No free-form headers, auth or request body.

Created client.go, transport.go, config.go, model.go, errors.go, client_test.go,
tls_test.go, adversarial_test.go and review_test.go. Network production is unchanged;
its ownership test was extended for the reviewed adapter and tightened to exact paths.

## Transport configuration

Fresh explicit http.Transport per operation. Both dial callbacks are set; only the
matching HTTP/HTTPS callback can return the existing socket, once. Proxy=nil,
DisableKeepAlives=true, DisableCompression=true, HTTP/1-only Protocols,
ForceAttemptHTTP2=false, empty TLSNextProto, MaxConnsPerHost=1. Idle limits are
explicit and CloseIdleConnections runs on exit. ExpectContinueTimeout=0 because
supported requests have no body/Expect. No default client/transport or tls.Dial.

## Boundary integration

No HTTP package duplicates DNS/IP/scope/peer policy. Every Do calls Approve then
Dial; no transport callback opens a socket. Approvals remain owner-bound, single-use
and expiring. Full Phase 3 tests remain green. ConnectionAttempts and RequestAttempts
are at most one and distinguish local attempts from server receipt. No global counter.

## Host/SNI behavior

HTTP Host retains the canonical logical host and explicit port. TLS ServerName
uses logical identity, not resolved DNS IP. Local localhost virtual-host and SNI
fixtures pass. Literal IP identity relies on crypto/tls IP-SAN handling; no DNS SNI
is fabricated. TLS1.2 minimum, no InsecureSkipVerify, no mTLS/session cache.

Explicit CA pool replaces system roots for that client. Trusted lab, unrelated CA,
hostname mismatch, expired and not-yet-valid fixtures pass their expected outcomes;
no HTTP request is sent after TLS validation failure. Minimal TLS metadata is
captured, with no issuer/SAN/expiration/cipher analysis.

## Proxy policy

No HTTP_PROXY/HTTPS_PROXY/ALL_PROXY or lowercase variants inherited. HTTP and HTTPS
proxy trap fixtures receive zero requests. Source guard also prohibits
ProxyFromEnvironment.

## Redirect policy

No redirect following or secondary approval/connection. 3xx and Location return as
untrusted evidence. Direct RoundTrip replaces the requested CheckRedirect approach
because a test proved Client.Do parses Location first and discards otherwise valid
responses on malformed Location. Private and malformed redirect fixtures both pass.

## Timeout model

Boundary DNS/connect defaults remain 3s each. TLS default 5s, headers 10s, operation
15s; hard maxima 10s, 30s, 60s respectively. Caller deadline may shorten all phases.
Total context starts before approval. Socket deadline and cancellation closure
cover HTTP/body; TLS uses HandshakeContext. Duration uses the monotonic clock.
No strict CPU/RSS bound for runtime verifier/resolver work is claimed.

## Response limits

Body defaults to 2 MiB, hard maximum 8 MiB. Read through max+1 LimitedReader; never
preallocate from Content-Length. BytesRead includes the lookahead; retained body
does not. BodyTruncated and BodyComplete distinguish intentional limit from EOF
and incomplete/error reads. Headers remain available on partial body results.

Initial response headers: 64 KiB default, 128 KiB hard maximum. No independent
header-count limit. Trailer handling is separately bounded by the pinned runtime
and trailers are not captured. No whole-exchange wire-byte/RSS limit claim.

## Compression policy

Accept-Encoding: identity; automatic decompression disabled. Servers returning
gzip anyway produce bounded encoded entity bytes, never unlimited expansion.

## Keep-alive policy

Disabled; new approval/socket/transport per Do. No silent retries or IP failover.
Single-use lease prevents a second successful dial even if the transport requests one.
Sockets and bodies close on completion, truncation, cancellation and errors.

## Response model

Operation ID, safe target, validated method, timestamps/duration, status/protocol,
declared length, actual bytes/completeness, Boundary resolution/peer and minimal
TLS metadata. Metadata snapshots deep-copy mutable nested values. Raw headers
preserve repeated field values and case-insensitive lookup; no original wire order
or casing guarantee. 404/500 are valid responses, not client errors.

## Privacy/redaction

No raw path/query, body or header values in default Response formatting/JSON/errors.
Rejected arbitrary method input is not retained. Raw Body/HeaderValues accessors
are explicit and return copies; callers must not log them. DiscardBody minimizes
retention but is not a secure-erasure guarantee. Set-Cookie lines stay separate
without cookie analysis. Sensitive header catalog and metadata are centralized.
No persistent report schema or output renderer was added.

## Tests

Final uncached command:
`go test -count=1 -json -coverprofile=coverage-phase4.out ./...`.
Go 1.27.1, Windows/amd64, GOPROXY=off, populated module cache.

| Metric | Result |
|---|---:|
| Total test/subtest completion records | 196 |
| Pass | 196 |
| Fail | 0 |
| Skip | 0 |
| Top-level entries | 59: 56 Test functions and 3 fuzz targets running seeds |
| httpclient top-level entries | 27: 26 Test functions and 1 fuzz target |
| network top-level entries | 32: unchanged 30 Test functions and 2 fuzz targets |

196 includes parents and subtests, not 196 independent top-level tests.
New bounded campaign: `FuzzSensitiveHeader`, 10s requested, two workers,
**28,645 executions, PASS**. Existing Phase 3 fuzz seeds also pass in the full suite;
their historical mutation campaign counts are not represented as newly rerun.

Local HTTP/TLS/raw TCP fixtures cover headers, bodies, malformed protocol, statuses,
Host/SNI, trust failures, cancellation, closure, compression, proxies, redirects,
concurrency and no-reuse. No public Internet target is required or contacted by
these functional tests. No benchmark or universal resource-leak proof is claimed.

## Go statement coverage

- httpclient: **94.0% statements**.
- network: **92.5% statements**.
- Combined: **93.1% statements**.

These are not branch coverage. Profile: coverage-phase4.out; function summary in
artifacts/phase4/coverage.txt. Phase 3 coverage artifact was not overwritten.

## go vet

PASS. gofmt clean; go mod verify reports all modules verified. No new dependencies
or lint tools installed in Phase 4. Staticcheck is not installed and was not run;
the required compiler/tests/vet/format gates are evidenced.

## go test -race

Attempted with CGO_ENABLED=1. Build fails before tests: `C compiler "gcc" not found`.
This is NOT PASS and not a test skip. Race-compatible synchronization was used in
fixtures, but concurrent passing tests do not replace a race-detector run. Keep
`go test -race ./...` for a future supported Linux CI/native compiler environment.

## Security invariants

- No target socket outside Boundary; static guard plus source review.
- No implicit hostname redial: transport only leases the existing verified socket.
- Logical Host/TLS identity preserved; validation never disabled.
- No proxy/redirect/reuse/retry/failover secondary connection.
- Raw query, rejected method, header and body canaries absent from default output.
- Body/headers/time bounded independently; declared length does not drive allocation.
- Cancellation closes owned sockets; truncated/partial responses remain explicit.
- Returned metadata/header snapshots cannot mutate retained evidence.

## Adversarial cases

Default loopback denial; explicit lab access; redirect to private host; malformed
Location; proxy environment; invalid methods; repeated Set-Cookie; raw HTML/query
canaries; huge/lying Content-Length; chunked/exact-limit/over-limit bodies; invalid
status/field; oversized headers; abrupt close; slow headers/body/TLS; concurrent
calls; failed connection; wrong scheme/address/second lease; expired/mismatch/
unknown-CA/future certificate; missing-intermediate with AIA trap; native-root path
blocked before dial; cancel/limit socket closure. Phase 3 bypass tests also pass.

## Bugs discovered

1. Client.Do parsed malformed Location before CheckRedirect and discarded evidence.
   Failing regression -> direct RoundTrip -> passing regression.
2. Metadata shallow copy shared TLS/address fields. Failing mutation regression ->
   deep-copy snapshot -> pass.
3. Rejected arbitrary Method input leaked into safe metadata. Failing canary test
   -> record only validated enum -> pass.
4. Header-limit error was wrapped by net/http; initial classifier missed it.
   Inspected runtime chain -> narrow match through wrappers -> fixture passes.
5. Early cancellation callback captured a connection variable later replaced by
   TLS wrapper. Review changed it to immutable TCP capture before completion;
   no claim that the unavailable race detector detected this.

Runtime discoveries: net/http tolerates certain spaced header names (test changed
to an actually invalid token); cancellation may precede header capture (test no
longer invents guaranteed status); native Windows verifier may fetch AIA/root data
outside scope (explicit CA policy). No Phase 3 production bug was found/reopened.

Independent read-only review ran twice. Initial findings were reproduced and fixed;
second review found no material unresolved issue. Reviewer did not independently
rerun tests; execution results above were verified by the primary implementation task.

## Known limitations

- Explicit CA PEM needed for HTTPS on Windows/macOS/iOS; no native store export yet.
- Only Windows runtime verified. Linux/macOS behavior not executed here.
- Race detector unavailable due missing compiler/cgo.
- HTTP/2 deferred; HTTP/3 excluded; no mTLS/auth/proxy support.
- Standard-library parsing/timing/allocation behavior remains a dependency; no strict
  CPU/RSS or total wire-byte cap. No trailer evidence or request timing breakdown.
- Header-limit classification uses a runtime-specific non-public error string.
- Raw accessors remain sensitive; future analysis/reporting must sanitize use.
- No TLS analysis, findings, scanner, redirect engine, dashboard or release.

## Docs created/updated

Created http-client.md, threat-model.md, adr/0005-http-transport.md, phase4-plan.md
and this report. Updated architecture.md, network-safety.md, ssrf-model.md and
README.md. Initial design and historical Phase 3 report preserved.

## Acceptance gate evidence

**PASS WITH LIMITATIONS.** All functional transport gates pass on the local fixture
suite, full Phase 3 regression passes, vet/format/module verification passes and
statement coverage is measured. Race/environment/CA restrictions are disclosed,
not hidden behind a PASS claim. No features from Phase 5+ were implemented.

Artifacts: artifacts/phase4/{tests.jsonl,coverage.txt,vet.txt,race.txt,environment.txt}.
The two material architectural refinements (RoundTrip and explicit platform CA)
are justified with actual runtime evidence and ADR 0005.

## Next phase

**PHASE 5 — TLS Analysis**. Not implemented.
