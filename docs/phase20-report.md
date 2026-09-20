# Phase 20 report — release hardening

Date: 2026-09-20. A least-privilege Linux CI workflow now performs a clean
`npm ci`, regenerates the Go finding catalog and embedded frontend assets,
rejects generated-file drift, verifies Go formatting/modules, runs all tests
with and without the race detector, vets/builds the code and audits npm and Go
vulnerabilities. It uses read-only repository permission, no persisted checkout
credential, no dependency cache and no secret-bearing workflow triggers.
The workflow was checked by actionlint v1.7.12 with exit 0; its execution on
GitHub remains a Phase 22 release gate.

The release ignore rules exclude local reports, test artifacts, coverage,
`node_modules`, caches, internal ledgers and common credential file formats.
The embedded dashboard, generated catalogs, manifests and documentation remain
release inputs. Regenerating the catalog and frontend twice produced the same
SHA-256 hashes for five generated files. Source review found one outbound scan
socket owner (`network`), one inbound loopback listener (`dashboard`), no
frontend HTML injection sink or report-controlled link, and no TLS verification
bypass. The platform browser opener receives only the generated loopback URL.

The Windows/macOS/iOS HTTPS CA requirement remains deliberate. Automatically
exporting native roots or fetching missing issuers would add unreviewed OS or
network behavior; operators supply a bounded PEM bundle with `--ca-file`.
Linux uses Go's local system roots. Revocation and CA-bundle maintenance remain
outside the scanner's claim.

## Recorded gate

The full local gate under `artifacts/phase20` passed: 17 packages, 342
top-level tests, 848 pass events, zero fail/skip, 87.5% weighted Go statement
coverage (4133/4721), plus frontend build/catalog audit, format, vet and module
verification. The Linux/amd64 CGO-disabled cross-build passed. `npm audit`
reported zero known vulnerabilities across the lockfile; the pinned
`govulncheck` v1.8.0 reported **No vulnerabilities found**. The local race
attempt still cannot compile because `gcc` is absent. These online audit
results are a point-in-time check, not a guarantee of no future advisories.

The CI workflow follows the current official
[checkout](https://github.com/actions/checkout),
[setup-go](https://github.com/actions/setup-go) and
[setup-node](https://github.com/actions/setup-node) interfaces. Go dependency
assessment uses the [Go vulnerability database](https://go.dev/doc/security/vuln/).
