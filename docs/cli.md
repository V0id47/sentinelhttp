# CLI scan contract — v0.1.0

`sentinelhttp scan TARGET` performs one bounded GET by default. It does not
follow redirects, crawl, send credentials or perform CORS probes unless an
explicit option calls for the corresponding safe operation. Use it only on
systems you own or are authorized to assess. `sentinelhttp version` prints the
tool version. `diff` compares validated local reports, and `serve` opens the
loopback dashboard over one report and an optional baseline.

```console
sentinelhttp scan https://example.com --format json --output report.json --ca-file roots.pem
sentinelhttp scan http://localhost:8080 --allow-private --trace-redirects --max-redirects 3
sentinelhttp scan http://localhost:8080 --allow-private --probe-cors --format html --output report.html
sentinelhttp diff old.json new.json --lang es
sentinelhttp serve report.json --compare old.json --no-open
```

The scanner uses one `network.Boundary` for every operation. Private and
loopback addresses are denied by default. `--allow-private` permits private
and loopback lab targets and also enforces the original host. Redirect tracing
is opt-in, checks every hop afresh and blocks HTTPS-to-HTTP downgrade.
`--same-host` also restricts redirects to the initial host. CORS probes are
opt-in, uncredentialed and limited to two GET samples plus one OPTIONS
preflight; they never follow redirects.

`--max-requests` reserves worst-case operations before any request. Without a
trace, the base cost is one GET; with a trace it is `max_redirects + 1` GETs.
Add three for CORS probing. Defaults are 10 redirects and a 16-request budget;
hard caps are 20 and 24. The scanner is serial with one scan-wide deadline.
`--timeout` defaults to 15 seconds (maximum 60); `--connect-timeout` defaults
to 3 seconds (maximum 10); `--max-response-bytes` defaults to 2 MiB (maximum
8 MiB). The report records these effective limits without recording the
target's path, query, CA file path or PEM contents.

HTTPS on Windows/macOS/iOS requires `--ca-file` (PEM, maximum 1 MiB) so Go's
offline verifier can operate without native issuer retrieval outside the
network boundary. On other platforms, the system trust store is used unless a
bundle is supplied. A supplied bundle replaces system roots for that scan;
certificate verification is never disabled. Keep the bundle current.

Formats are `terminal` (default), `json`, `markdown` and `html`. JSON is the
authoritative interchange format. Without `--output`, bytes go to stdout.
With it, a private same-directory temp file is synced and atomically linked to
a **new** destination; existing files are never overwritten. Some filesystems
cannot create hard links; in that case the output fails safely. Exit 0 means
the scan and output completed; 2 means invalid invocation; 3 means incomplete
scan (a partial report may still be written); 4 means report/output failure.
Stderr contains only stable error codes, never raw URLs or response content.
On Windows the temporary report receives a protected ACL for the current user,
SYSTEM and Administrators before any report bytes are written; on POSIX-like
systems it uses mode `0600`. The committed file keeps those permissions.

A trace response is header-only; its chosen primary response need not include
the entity body. A partial report is an observation of operations actually
attempted, not proof that the target lacks a control. The CLI does not retain
credentials or cookies and cannot prove exploitability.

`--lang en|es|ru|zh-CN` changes human-facing help, safe error descriptions,
terminal/Markdown/HTML reports and terminal diffs. It may appear before or
after a command. JSON remains canonical and independent of locale. Unsupported
language values fail with a safe invocation error. The dashboard has its own
browser language selector. See [localization](i18n.md).
