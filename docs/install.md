# Installation and first local scan

SentinelHTTP is a Go command with an embedded local dashboard. Use Go 1.26 or
newer; the CI toolchain is Go 1.27.1. Clone the repository and build from its
root. Windows produces `sentinelhttp.exe`; Linux and macOS produce
`sentinelhttp`.

```console
go mod verify
go build -o sentinelhttp ./cmd/sentinelhttp
./sentinelhttp version
```

In PowerShell, use `go build -o sentinelhttp.exe ./cmd/sentinelhttp` and
`.\sentinelhttp.exe version`. Go downloads the two pinned external modules
listed in `go.mod` on first build; a populated module cache permits offline
rebuilds. The committed frontend bundle is embedded by Go, so Node.js is not
required to build or use the command. To rebuild the UI from source, install
Node.js 24 and npm, then run:

```console
npm ci --prefix frontend
npm run build --prefix frontend
go build -o sentinelhttp ./cmd/sentinelhttp
```

Run a local HTTP service on port 8080 for this safe first test:

```console
./sentinelhttp scan http://127.0.0.1:8080/ --allow-private --format json --output report.json
./sentinelhttp serve report.json
```

The scanner denies private and loopback addresses by default. The explicit
`--allow-private` option is for an authorized lab target and also fixes the
redirect host. The first scan makes one GET, without following redirects or
sending cookies. `serve` binds only `127.0.0.1` on a random port. Use
`--no-open` when no browser should be launched.

For HTTPS on Windows, macOS and iOS, pass a current PEM CA bundle using
`--ca-file roots.pem`. The CLI rejects an HTTPS scan before dialing if this
bundle is absent on those platforms. A supplied bundle replaces the system
roots for that scan and is limited to 1 MiB; verification is never disabled.
On Linux, the local system trust store is used unless a bundle is supplied.
Do not fetch a bundle automatically during an assessment. Keep your chosen
bundle current and protect it according to your organization's policy.

The scan writes only to a new output path. It cannot overwrite `report.json`;
choose a new name for each run. Reports may reveal origin, certificate and
cookie-name metadata even though URL paths, queries, body and cookie values
are omitted. [CLI flags and exit codes](cli.md) · [Security model](security.md).
