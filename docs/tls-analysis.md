# TLS analysis — Phase 5

`Response.TLSAnalysis()` exposes evidence from the existing TLS connection.
`tlsanalysis.Capture(state, err, scanTime)` is pure: no sockets, DNS, trust-store
lookups, certificate URL fetching, revocation checks or protocol enumeration.
It does not change the strict validation policy or retry a failed connection.

## Evidence and authentication

- `not_applicable`: HTTP target.
- `unavailable`: no parsed certificates exposed by the runtime, including failures
  before TLS, generic handshake failures and certificate-message size rejection.
- `unverified`: presented certificates available, but handshake did not establish
  authenticated evidence. CertificateVerificationError supplies these on ordinary
  certificate validation failures. The structured HTTP error code explains why.
- `verified`: completed handshake with a verified chain. This authenticates the
  connection under the configured trust roots; it is not a service security grade.

Presented and verified chains are distinct. A presented root is not automatically
trusted. The presented chain need not include a root; verified chains may add one.
Failures retain no verified chain and perform no HTTP. Negotiated version, cipher
and ALPN are only recorded after a completed successful handshake. They describe
one session, not all server-supported protocols/ciphers. No downgrade probes.

Each certificate records bounded subject/issuer strings, SHA-256 of original DER,
UTC validity timestamps, days remaining, validity classification and typed DNS,
IP, email and URI SAN observations. Raw DER, certificate objects, AIA, OCSP and CRL
URLs and runtime error strings are not retained. SAN URIs are inert text only.
Supported SANCount covers Go's DNS/IP/email/URI fields, not arbitrary GeneralName
extensions. Subject/issuer use Go's normalized name rendering, not raw ASN.1.

The supplied scan instant is the HTTP operation start. Days remaining is
floor((notAfter - scanTime)/86400), including negative fractional days; calculation
does not saturate at Go's duration range for long-lived certificates. `expired`
means scanTime > notAfter; `not_yet_valid` means scanTime < notBefore. Otherwise,
`expiring_soon` means notAfter <= scanTime + 30 days, with `valid` beyond it.
Go's actual handshake trust decision uses its current verification time; a boundary
crossed during an operation can differ from this start-time date observation.
Date labels do not override trust errors or generate findings/severities.

## Limits and output handling

Retain at most 16 certificates per presented/verified chain, 4 verified chains,
128 supported SAN entries per certificate and 1024 UTF-8 bytes per text field.
Original presented/verified chain counts and per-certificate SAN counts are kept;
Truncated flags identify omitted entries/text. Verified chain lengths do not have
separate original counts. No conclusion about absence may be drawn from truncated
evidence. SAN retention order is DNS, IP, email, URI, preserving order within type.
Empty chains and missing certificates are not fabricated into observations.

Control and Unicode format characters are replaced with U+FFFD. This normalization
does not escape HTML, redact secrets embedded in names, or make links safe.
Callers must treat every certificate-controlled value as untrusted and encode for
their output context. Default Response JSON/String/GoString excludes certificate
evidence; only the explicit accessor exposes it. Accessor results own their nested
slices and cannot mutate the retained evidence.

These caps bound retained summaries, not all intermediate allocations or process
RSS. Go parses certificates before Capture, and name/URI rendering can allocate
temporary strings. The inspected bundled runtime limits normal TLS handshake
messages to 64 KiB and Certificate messages to 256 KiB (`crypto/tls/common.go` and
`conn.go`). An actual local fixture exceeding the latter is rejected before HTTP.
An accepted fixture with 300 SANs and 20 presented certificates verifies summary
caps. This is not a strict memory benchmark or exhaustive malicious ASN.1 audit.

Windows/macOS/iOS still require an explicit CA PEM pool, preserving the Phase 4
protection against native certificate-chain network retrieval. Linux trust-store
behavior was not exercised in this Windows run. RevocationChecked is always false.

Sources: [Go TLS verification error](https://pkg.go.dev/crypto/tls#CertificateVerificationError),
[Go X.509 certificate fields](https://pkg.go.dev/crypto/x509#Certificate), and the
bundled runtime source. No new dependencies were introduced.
# Phase 11 consumer

The [finding engine](finding-engine.md) emits an informational expiring-soon
finding only for a verified, untruncated presented leaf on a verified HTTPS
response. It does not assess revocation or future renewal.
