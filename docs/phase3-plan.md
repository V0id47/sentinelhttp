# Phase 3 implementation plan

Goal: an approval-before-connect boundary, with exact IP:port dialing and peer verification.
Spec: ../sentinelhttp-design/INITIAL-DESIGN-REVIEW.es.md and the user's Phase 3 request.
Scope: local Go module only; no Git initialization, HTTP scanner, TLS implementation or frontend.

1. Write parsing/policy tests in internal/core/network; observe failure, then implement immutable Target, canonical IDNA host, safe display and explicit address classification.
2. Write resolver/approval/dial tests; observe failure, then implement per-boundary opaque single-use approvals, bounded DNS/dial contexts, evidence and exact peer matching.
3. Add offline loopback integration, concurrency, cancellation, hostile resolver/dialer, API architecture and fuzz tests. Review security invariants independently.
4. Run gofmt, go test, go vet, race when runtime permits, bounded fuzz campaigns and statement coverage. Record actual outputs and limitations.
5. Document architecture, network policy, SSRF model, ADR and Phase 3 acceptance report. Stop before Phase 4.

Files: network/{target,policy,errors,boundary}.go and corresponding tests; docs/{architecture,network-safety,ssrf-model,phase3-report}.md; docs/adr/0004-scope-model.md.
The security-critical package owns approval and dialing together so no public constructor can forge approved destinations. Resolver/dialer injection remains unexported for tests; production construction always uses system resolver and net.Dialer.

Execution record: all five tasks completed locally. Red tests observed before APIs
and before two regression fixes. Independent review repeated after corrections.
Final test/vet/format/module checks pass; race build blocked by missing C compiler.
See phase3-report.md for counts, coverage, limitations and acceptance decision.
