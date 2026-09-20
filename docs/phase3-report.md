# SENTINELHTTP PHASE 3 REPORT

Date: 2026-09-13. Acceptance: **PASS WITH LIMITATIONS**.
Scope: Target Scope & Network Safety only. This is an implementation/test record,
not a claim that SentinelHTTP is a complete scanner or has a release.

## Architecture implemented

One internal Go security package owns parsing, policy, resolver, approval and dial.
Only an owner-bound, expiring, single-use opaque ApprovedEndpoint can authorize a
target TCP dial. Logical hostname/authority/TLS identity remain separate from the
literal IP:port. No HTTP/TLS protocol client was added.

## Packages/files created

- `go.mod`, `go.sum`: local module and pinned IDNA dependencies.
- `internal/core/network/target.go`: target parser, canonical identity and safe display.
- `internal/core/network/policy.go`: classification and decisions.
- `internal/core/network/errors.go`: stable, non-sensitive failure codes.
- `internal/core/network/boundary.go`: resolver, capabilities, dial and peer checks.
- `internal/core/network/target_test.go`: parsing/policy tables and fuzz targets.
- `internal/core/network/boundary_test.go`: approval/dial and loopback integration.
- `internal/core/network/adversarial_test.go`: bypass, cancellation, privacy and ownership checks.
- `README.md`, `.gitignore`, documentation listed below.

Generated local evidence: artifacts/tests.jsonl, artifacts/coverage.txt,
artifacts/race.txt, artifacts/environment.txt, artifacts/vet.txt and coverage.out.
Generated artifacts are excluded by .gitignore; no Git repository was initialized.

## Scope policy

`scope-v1`: HTTP/HTTPS, valid port, strict normalized target, public unicast by
default. Evaluate all DNS answers before selecting a deterministic allowed IP.
SameHost optional by default and forced with private opt-in. It is hostname
equality, not same-site, same-origin or legal authorization.

## Blocked address classes

Private, loopback, link-local, unspecified, multicast, documentation, policy-reserved,
other non-global, invalid/zoned and known metadata. Full range table and intentional
overblocking of globally routable special assignments are in network-safety.md.
IPv6 candidates outside 2000::/3 are denied unless explicitly private/loopback opted in.

## allow_private semantics

Adds RFC1918, ULA and loopback only; forces SameHost. Does not allow link-local,
metadata, unspecified, multicast, invalid, documentation or other special ranges.
`fd00:ec2::254` remains denied before the ULA exception. This is a Policy field;
the future CLI flag does not exist yet.

## DNS strategy

System resolver via a small unexported injectable interface. Each new approval
resolves again; literals skip DNS but receive the same classification/approval.
Three-second default deadline, configurable maximum ten seconds, maximum 64 answers.
No external DNS or Internet target is required by tests. DNS traffic performed by
the trusted resolver is distinct from the target socket governed by approval.

Resolution evidence records canonical hostname, timestamps, returned and normalized
IPs, classifications, decision and selected endpoint. Raw zone strings are omitted.
The evidence slice is independent of capability state.

## Mixed DNS strategy

Any denied answer prevents approval. Allowed+denied gets mixed_scope_resolution.
No silent public-only selection. Empty, over-limit, timeout, NXDOMAIN-equivalent,
temporary failure and generic failure are distinguished.

## DNS rebinding defense

First approval can resolve public; Dial receives its literal address and performs
no lookup. The next operation resolves afresh and rejects a subsequent loopback
answer. Reusing/copying an approval cannot authorize another dial.

## Safe dial strategy

Check issuer, zero/forged state, atomic consumption, expiry and contexts before
calling net.Dialer with literal AddrPort.String(). No retries, fallback or proxies.
Original approval context cancellation propagates during connection establishment;
late connections are closed. Caller owns successful connections and their future I/O.

## Peer verification

Require valid net.TCPAddr, no zone, valid IP and port, unmap IP, compare exact IP and
port with approval. Close the connection on error, wrong peer, malformed peer or
cancellation. Return explicit PeerRecord and peer_mismatch on rejection.

## URL/userinfo/query handling

Reject userinfo; preserve request path and valid raw query through explicitly
sensitive RequestURL. Drop fragment. Reject invalid escapes, control/format chars,
backslashes, malformed authorities and ports. SafeURL/default formatting/JSON omit
all path/query/fragment data, including query keys. Boundary retains only initial
hostname. This intentionally redacts more than the original query-values-only idea.

Rejecting a URL cannot erase credentials previously entered in shell history.
Canonical hostnames can still contain sensitive identifiers.

## IPv4/IPv6 handling

netip is the canonical representation. IDNA Lookup profile handles DNS names;
canonical ASCII is used for equality/DNS/display/TLS. One DNS trailing dot is
removed. IPv6 is bracketed in authority and unbracketed in identity. Mapped IPv6
is unmapped before classification, dialing and peer comparison. Zones and legacy
numeric IPv4 representations are rejected with no custom conversion.

## Tests

Final uncached run: `go test -count=1 -json -coverprofile=coverage.out ./...`.
Environment: Go 1.27.1, Windows/amd64; no public target connections.

| Metric | Result |
|---|---|
| Total Go test/subtest completion records | 138 |
| Pass | 138 |
| Fail | 0 |
| Skip | 0 |
| Top-level entries | 32: 30 Test functions and 2 fuzz targets running seeds |
| go vet ./... | PASS |
| gofmt -l | Empty output; PASS |
| go mod verify | All modules verified |
| Race | NOT EXECUTED successfully; see below |

The 138 includes parent entries and subtests, not 138 independent top-level tests.
Fuzz executions below are separate from this count.

Bounded fuzz campaigns (two workers):
- FuzzParseTarget, 15s requested: **25,862 executions**, PASS.
- FuzzMappedPolicy, 10s requested: **362,786 executions**, PASS.

Race attempt initially reported `-race requires cgo`; explicitly enabling cgo then
failed with `C compiler "gcc" not found`. No supported C compiler was present at
the inspected standard locations or PATH. The race build failed before tests ran;
it is neither PASS nor a test skip. Concurrent-operation unit tests pass, but do
not replace race detection. No compiler was installed globally to mask this limit.

Commands are reproducible with Go on PATH and populated dependency cache. Initial
Go/IDNA installation needed Internet; the functional tests themselves do not.
Final verification used GOPROXY=off and GOTOOLCHAIN=local.

## Go statement coverage

**92.5% statement coverage** (`go tool cover -func=coverage.out`).
This is not branch coverage. No arbitrary coverage percentage was used as the gate.

## Security invariants tested

1. No target dial for absent, zero, forged, foreign-owner, expired or denied approval.
2. Dial destination parses as literal IP:port, never the original hostname.
3. Copied/concurrent capability consumption results in exactly one dial.
4. Fresh operation resolves and approves again; no hostname re-resolution inside dial.
5. Mixed answer denial and mapped IPv6 cannot bypass IP policy.
6. allow_private cannot permit malformed/multicast/unspecified/link-local/metadata.
7. Peer IP and port must match; rejected/late/error connections are closed.
8. Evidence mutation cannot change the selected destination.
9. Cancellation and deadlines apply to DNS and establishment, including original context.
10. Default formatting/errors do not expose seeded path/query secrets.

## Bypass attempts tested

Mapped IPv6, case/trailing dot, IDNA, encoded host, malformed brackets/ports, userinfo,
legacy numeric forms, zone IDs, metadata names, special-range endpoints, public/private
DNS mix, rebinding between operations, copied/JSON-created approvals, wrong issuer,
expired approval, peer IP/port substitution, non-TCP/nil peers, cancelled/late
resolver and dialer returns, and concurrent consumption/operations.

The future redirect engine is not tested because it does not exist. Its required
primitive is tested using subsequent Approve calls and SameHost checks.

## Bugs discovered during implementation

1. Independent review found Boundary debug formatting could expose the retained
   initial URL. A failing regression reproduced it; storing only initialHost fixed
   it. Pointer/value default formatting tests now pass.
2. net/url leaves RawQuery escape validation to callers. A failing regression
   demonstrated malformed `%zz`/`%` acceptance; explicit QueryUnescape validation
   rejects malformed syntax without altering the raw query sent later.

Tooling issue, not product bug: an unquoted PowerShell `-coverprofile=coverage.out`
argument was interpreted incorrectly as a separate `.out` package. Re-ran with
quoted arguments; only the corrected successful run is the coverage evidence.

Two independent read-only review passes were performed. The first found issue 1
and missing adversarial cases; the second found no unresolved material issue after
the fix and additional tests. Review is not a proof of absence of vulnerabilities.

## Known limitations

- Race detector not run successfully; requires a supported C compiler/cgo setup.
- Only Windows runtime exercised; Linux/macOS resolver and socket behavior unverified.
- OS DNS/cache/search behavior and worker lifetime remain part of the trusted runtime.
- Peer comparison cannot prove physical routing beyond NAT/VPN/custom translation.
- Metadata inventory and static special-range registry require maintenance.
- Conservative policy intentionally denies some globally routed special-purpose space.
- No TLS validation, HTTP client, redirect chain, protocol timeouts after ownership
  transfer, final reporting, scoring or dashboard are implemented.
- Types and source guard prevent accidental API misuse; hostile Go code could add
  a raw socket import. Future changes require preserving the architecture checks.
- No performance/production-readiness/real-world security certification claimed.

## Docs updated

Created docs/architecture.md, docs/network-safety.md, docs/ssrf-model.md,
docs/adr/0004-scope-model.md, docs/phase3-plan.md and this report. The approved
initial design is preserved in the sibling sentinelhttp-design directory.

## Acceptance gate

**PASS WITH LIMITATIONS**: parsing, scope, IPv6/mapped, mixed DNS, literal dial,
peer verification, cancellation, offline fixtures, opt-in limits, repeat approval
API, documentation, tests and vet satisfy Phase 3. Race limitation is concrete and
disclosed as allowed by the requested acceptance criteria. No later-phase features
were included. Close the race/multiplatform verification gap before stronger claims.

## Next phase

**PHASE 4 — HTTP Client**. Not implemented.
