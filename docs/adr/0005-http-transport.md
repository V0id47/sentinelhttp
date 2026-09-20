# ADR 0005 — One exchange over a verified connection

Status: implemented 2026-09-16.

## Decision

Boundary approves/dials before an ephemeral HTTP transport is constructed. TLS
wraps that socket with strict logical-name validation. Transport callbacks only
lease the existing connection once. HTTP/1 only; no proxies, reuse, retries,
failover, mTLS or decompression. Separate body/header/time limits.

Use RoundTrip, not Client.Do. The original CheckRedirect approach lost valid 302
evidence because Client.Do parses Location first. A failing regression demonstrated
this. RoundTrip has no redirect processing, preserving even malformed Location.

Require explicit PEM CA pools on Windows/macOS/iOS to avoid native certificate
chain retrieval outside scope. Supplying no bundle fails closed; explicit pools
preserve strict Go verification. No InsecureSkipVerify workaround.

## Alternatives and consequences

Default transports permit implicit proxy/dial/reuse behavior. A persistent custom
transport complicates fresh approval. A custom HTTP parser adds unnecessary risk.
HTTP/2 is deferred until equivalent pooling/retry guarantees are tested.

Cost: new connections/handshakes and operator CA-bundle requirements on affected
platforms. Benefit: one approval/peer record per target socket, with no independent
HTTP dial path. No performance claim, native-root exporter or cert management.

Evidence: Host/SNI, proxy traps, malformed Location, body/header limits, slow/raw
responses, cancellation/closure, AIA trap and strict TLS fixtures. Race detection
remains unverified locally due missing gcc/cgo. See http-client.md and phase4-report.md.
