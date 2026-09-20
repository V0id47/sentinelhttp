# Phase 5 — TLS Analysis implementation plan

Goal: bounded certificate evidence from the existing strict TLS handshake.
Spec: ../../sentinelhttp-design/INITIAL-DESIGN-REVIEW.es.md, TLS section and Phase 5 gate.
Architecture: a pure tlsanalysis package converts Go connection state or certificate verification errors into owned evidence. httpclient retains it privately and exposes a copy. Default response formatting continues to omit certificate-controlled text.
Tech stack: existing Go toolchain and standard library only.

Constraints: no extra connections, downgrade, insecure verification, AIA/OCSP/CRL fetching, findings engine or later phases. Preserve explicit CA requirement and Boundary ownership. No Git/release actions.

1. Add tlsanalysis/analysis_test.go for dates (including negative fractional days), verified versus unverified chains, missing evidence, hostile text, SAN/chain caps and copy isolation. Run and record expected missing implementation failure.
2. Implement tlsanalysis/analysis.go: Capture(state, error, scanTime) Evidence; certificate SHA256, bounded subject/issuer and SANs, UTC validity, floor days, 30-day near expiry. Cap 16 certificates per chain, 4 verified chains, 128 SANs per cert and 1024 bytes per string. Explicit truncation and counts. No certificate URLs or raw DER retained.
3. Integrate private evidence in httpclient, exposed via TLSAnalysis() with independent slices. Capture failed verification evidence before discarding runtime errors; do not execute HTTP on failure. Integration tests use existing ephemeral local CA fixtures.
4. Run full tests, vet, formatting and coverage; inspect resource/runtime limits. Document exact results and remaining platform/race limitations. Update architecture/README and create phase5 report.

Execution: inline in the current task; the design and continuation are already approved.

Completed 2026-09-16: all four steps implemented and verified. Independent source
review found no material defect; added its fmt privacy regression suggestion.
Final evidence and environmental limitations are recorded in phase5-report.md.
