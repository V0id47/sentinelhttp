# Development and verification

Go source lives in `cmd/` and `internal/`. `internal/core/network` is the
outbound socket boundary; `httpclient` performs bounded exchanges; pure
analyzers, findings, scoring, reporting and diffing consume owned evidence.
`internal/dashboard` owns only the inbound loopback listener. `frontend/`
contains the strict React/TypeScript UI; Vite emits checked-in files under
`internal/dashboard/static` for Go embedding.

Use Go 1.26+ (the CI version is 1.27.1) and Node.js 24 for frontend changes.
From the repository root:

```console
npm ci --prefix frontend
npm run lint --prefix frontend
go run ./tools/cataloggen frontend/src/finding-catalog.json
npm run build --prefix frontend
go test ./cmd/... ./internal/... ./tools/... -count=1
go vet ./cmd/... ./internal/... ./tools/...
go mod verify
go test -race ./cmd/... ./internal/... ./tools/... -count=1
```

ESLint checks the TypeScript/React source with the official recommended
TypeScript rules. TypeScript 6.0.3 is pinned because `typescript-eslint`
currently supports that compiler API; the project does not need TypeScript 7
for its small frontend. The catalog generator exports versioned finding
narratives from Go. The frontend build exports fixed translations to Go and
rebuilds embedded assets.
Commit the generated JSON and static files with their sources; CI regenerates
them and fails on drift. `go test -race` requires a supported C compiler;
Linux CI runs it. The development Windows workstation lacks `gcc`, so a local
race attempt there is recorded as blocked, not passed.

The explicit Go package patterns exclude `frontend/node_modules`: a transitive
npm dependency currently ships an unrelated Go package, which `go test ./...`
would otherwise discover after `npm ci`. The project has 17 own Go packages.

Functional tests use fake DNS/dialers and local HTTP/TLS fixtures. They do not
probe public targets. The report parser, URL parser and analyzers also have Go
fuzz targets; for example:

```console
go test ./internal/core/reporting -run '^$' -fuzz '^FuzzParseUntrustedReport$' -fuzztime=20s
```

The local `artifacts/` directory contains historical gate logs and synthetic
test reports; it is ignored by Git. Rebuild the dashboard before changing Go
code that embeds it. For a browser check, create a report with an authorized
local fixture and run `serve report.json --no-open`; open the printed loopback
URL. The browser cannot start scans, select report files or fetch remote assets.

See [architecture](architecture.md), [network safety](network-safety.md),
[report schema](reporting.md), [localization](i18n.md) and
[threat model](threat-model.md).
