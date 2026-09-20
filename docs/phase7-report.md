# SENTINELHTTP PHASE 7 REPORT

Date: 2026-09-18. Gate: **PASS WITH LIMITATIONS**.

## Scope delivered

Pure, deterministic analysis of the existing HTTP client's captured `Set-Cookie`
fields. Every field is processed separately, including dates containing commas.
The report distinguishes capture, parsing, attribute state, effective policy,
draft-model acceptance, persistence and a deliberately limited session-like
inference. It adds no cookie jar, outgoing `Cookie` header, browser execution,
finding, severity or score.

The implementation follows the user-agent algorithms in RFC6265bis-22 for the
covered behavior: tolerant cookie-pair parsing, last processed Domain/Path policy,
Max-Age precedence, cookie-date parsing, the recommended 400-day lifetime cap,
SameSite=None/Secure and case-insensitive user-agent prefix requirements. Domain
scope uses the compiled Public Suffix List in `golang.org/x/net/publicsuffix`
v0.59.0. The emitter is already IDNA-canonicalized by the network boundary;
non-ASCII Domain attribute U-labels are rejected under the draft's CHAR rule.

## Integration, bounds and privacy

`httpclient` captures the report immediately after response headers and before the
body read. A later incomplete body keeps the cookie evidence; failures before
headers return `capture_unavailable`. Default-path calculation receives the
escaped URL path, so an encoded slash does not become a path separator.

The analyzer accepts at most 128 fields, 4,096 bytes per field, 64 KiB aggregate
input, 64 attribute segments per field, 256 retained name bytes and 32 unique
unknown attribute names. Truncated input produces truncated attribute states and
indeterminate acceptance/prefix/persistence; it suppresses identity and session
inference. Sanitized names and paths are explicit and excluded from identity
collision detection.

Cookie and extension values never enter the report. Unknown extensions retain
only bounded lower-case names and counts. Names, effective Domain/Path and unknown
attribute names remain explicit untrusted evidence. Default Response JSON/fmt
excludes the complete report. `CookieAnalysis()` returns a deep copy; the older
explicit `HeaderValues("Set-Cookie")` accessor remains sensitive and can expose raw
values.

## Validation executed

Fresh `go test -count=1 -json -coverprofile=coverage-phase7.out ./...`: PASS.
351 passing test/subtest completion records, 119 top-level test/fuzz-target
completion records, 5 passing packages, 0 failures and 0 skipped tests. Go
statement coverage: cookieanalysis 90.8%, headeranalysis 90.1%, httpclient 94.9%,
network 92.5%, tlsanalysis 97.1%, total 91.7%. These are not branch coverage
percentages.

`go vet ./...`: PASS. `gofmt -l .` returned no files. `go mod verify` returned
`all modules verified`. The dependency inventory was recorded successfully.
Bundled runtime: go1.27.1 windows/amd64.

Two requested 10-second fuzz campaigns passed. `FuzzAnalyze` completed 1,063,166
executions after its seed corpus; `FuzzCookieValuesAreNeverRetained` completed
1,446,050 executions. They cover determinism, retained bounds and the rule that
cookie/extension values do not appear in JSON evidence. Functional integration
uses local HTTP/TCP fixtures and performs no public target assessment.

Regression coverage includes Expires commas, distinct Set-Cookie fields, duplicate
attributes, invalid persistence fallbacks, Domain order/empty/public-suffix/
non-ASCII cases, escaped and sanitized paths, `__Secure-`/`__Host-`, tolerant
nameless cookies, 400-day clamping, integer overflow, truncation propagation,
identity collision eligibility, ownership and default-output privacy.

## Independent review

The first read-only review found no Critical issue and five Important areas:
invalid duplicate persistence values, ordered Domain behavior, escaped/sanitized
Path handling, incomplete truncation propagation and identity eligibility. Each
was reproduced with a failing regression before correction. The deep-copy test
and normative coverage were also strengthened.

The final focused review reported no actionable findings and assessed the phase
**Ready: Yes**. It independently ran `go test ./... -count=1` and `go vet ./...`;
both passed.

## Limitations

- `go test -race ./... -count=1` with `CGO_ENABLED=1` was attempted and is
  **blocked**, not PASS: the host has no `gcc` C compiler. Race-detector validation
  remains due in a supported environment.
- RFC6265bis-22 remains an Internet-Draft in final publication processing. The
  model is an explicit subset and does not claim identical behavior for every
  browser, user setting or future revision.
- No cookie jar or cross-response storage model exists. Replacement order,
  existing secure-cookie overlay, browser SameSite request context and Partitioned
  semantics remain outside this phase.
- The bundled PSL is a snapshot and can age. Its compiled source identifies
  publicsuffix.org revision `d6c92f1bbb7433e5db7b8405c25d4035fb8ff376`
  (2026-02-06); dependency updates can change future classifications.
- Bounds constrain retained/parser input, not strict process CPU/RSS. Explicit
  evidence strings remain untrusted and require output-context escaping. Go cannot
  guarantee secure erasure of transient value copies.

## Artifacts and next phase

`artifacts/phase7` contains JSONL test evidence and summary, coverage, vet, format,
module verification/inventory, both fuzz campaigns, race attempt and environment.
`coverage-phase7.out` is the statement profile. Implementation is in
`internal/core/cookieanalysis` plus the existing `httpclient` adapter.
Documentation is in cookie-analysis.md, architecture.md, http-client.md,
threat-model.md, README and this report.

Next: **Phase 8 — CSP Policy Analysis**, not implemented in this delivery.
