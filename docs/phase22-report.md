# Phase 22 report — release candidate and publication

Date: 2026-09-20. SentinelHTTP v0.1.0 reached the agreed release-candidate
scope and was published at [V0id47/sentinelhttp](https://github.com/V0id47/sentinelhttp).
The first public commit was
[`0657036`](https://github.com/V0id47/sentinelhttp/commit/06570363c7312e7c9fb011393cfe0327923913d5).
Its [CI run 35504147285](https://github.com/V0id47/sentinelhttp/actions/runs/35504147285)
completed successfully on Linux, including the race detector and npm/Go
vulnerability audits. GitHub's notice about a future `ubuntu-latest` image
migration was informational and did not fail the run.

## Acceptance evidence

The final local gate passed frontend build, catalog consistency, Markdown
links, Go tests, `go vet`, formatting and module verification. It recorded 342
top-level Go tests in 17 packages, 848 pass events, no fail or skip events, and
87.6% weighted statement coverage (4136/4721). The Windows workstation could
not compile `go test -race` without `gcc`; the green Linux job supplied that
release evidence.

A clean local clone of the committed tree installed frontend dependencies from
the lockfile, passed the Go suite and documentation link check, rebuilt the
catalog and dashboard assets, and left no generated-file Git diff. The
initial 203-file staged set was checked for caches, live report artifacts,
plans, environment files, private keys and common secret patterns before the
first push. The published dashboard was visually checked at 1366×768 and
390×844 on synthetic Overview and Diff fixtures. The mobile body width stayed
inside the viewport. Those interactive checks are observations, not automated
visual regression tests.

No public service was scanned as a release test. The [readiness matrix](release-readiness.md)
lists the acceptance gates, and the [architecture self-review](architecture-self-review.md)
records residual security and maintenance risks. The software makes bounded
configuration observations; it does not authenticate reports or claim
exploitability or comprehensive security.
