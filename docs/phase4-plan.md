# Phase 4 implementation plan

Implement only a bounded HTTP/1 client on the existing Boundary. No analysis findings.
1. Write failing HTTP fixture tests for scope/Host/redirect/proxy/body/privacy.
2. Implement httpclient config, models, strict TLS, single-socket transport and bounded reads.
3. Add offline TLS CA/SNI/validation fixtures, raw malformed/slow responses, cancellation,
   no-retry/no-reuse and architecture guards; fix evidenced regressions.
4. Independent adversarial review while checking tests/vet/format/coverage/race limitation.
5. Update architecture/network/threat docs, transport ADR and Phase 4 report. Stop.

Files: internal/core/httpclient/{client,transport,model,config,errors}.go and tests.
Adapt network's source ownership test only to permit the reviewed HTTP adapter.
Defaults: Boundary DNS/connect unchanged; TLS 5s, headers 10s, total 15s; body 2MiB
(hard 8MiB), headers 64KiB (hard 128KiB). HTTP/2 deferred, compression/reuse off.
Retain raw headers/body only in private transient structures with explicit accessors;
default formatting/JSON contains sanitized metadata. No arbitrary request headers.

Execution record (2026-09-16): implemented and independently reviewed twice.
RoundTrip replaces CheckRedirect after a demonstrated malformed-Location evidence
loss. Native verifier platforms require explicit CA PEM to prevent unscoped AIA
fetching. Tests/vet/format/module checks pass. Race build remains blocked by missing
gcc/cgo. Exact counts, coverage, limits and acceptance: phase4-report.md.
