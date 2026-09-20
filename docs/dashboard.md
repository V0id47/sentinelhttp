# Local dashboard backend

`sentinelhttp serve report.json` reads one report (8 MiB maximum) through the
strict `reporting.Parse` boundary before opening a socket. The server receives
only a validated JSON snapshot. `--compare old.json` optionally reads a second
bounded report and computes a pure semantic diff before bind. The server never
opens another file, accepts
uploads or performs outbound requests. `--no-open` suppresses automatic
browser launch, useful for terminals and tests; Ctrl+C stops the server.

The listener is fixed to `127.0.0.1` on a random port. `/api/report` returns
the validated report; `/api/diff` returns a precomputed comparison only when a
baseline was supplied; `/` serves bundled local UI content. No URL path or
query selects a filesystem path. Requests with a foreign Host or Origin are
rejected, there is no CORS grant, and non-GET/HEAD methods are rejected.
Responses use no-store, nosniff, no-referrer, deny-frame and a restrictive
same-origin CSP. Standard-library HTTP read/write/idle/header limits apply.

Loopback binding and Host checks limit accidental exposure and DNS rebinding,
but local processes or browser extensions on the operator's machine can still
read the report while the server runs. The report is not authenticated or
encrypted over loopback. Use `serve` only on a trusted workstation; stop it
when finished. Structural validation does not prove the report's provenance.
The React/TypeScript frontend is built from `frontend` with `npm ci` and
`npm run build`. Vite emits versioned CSS/JS under `internal/dashboard/static`,
which Go embeds into the binary; no CDN or remote font is needed. It presents
Overview, Findings, HTTP/TLS/header/cookie/CSP/CORS evidence, request journey,
the optional semantic diff, raw validated JSON and scan limits. Browser state
only controls navigation and filters. Report strings are rendered as React
text, never HTML or dynamic links. A missing capture is labelled incomplete;
silence in an analyzer is not represented as proof of safety.

`--compare` validates both files and computes the diff before the server binds.
The browser can fetch that snapshot but cannot choose files, upload reports or
start scans. Rebuild the frontend after any source change so the checked-in
embedded assets match the TypeScript source.

The dashboard offers English, Spanish, Russian and Simplified Chinese.
The selected language is stored only in browser local storage; JSON and raw
evidence stay unchanged. Shipped finding narratives are translated only on an
exact rule/version/source match, with a visible fallback for changed text.
See [localization](i18n.md).
