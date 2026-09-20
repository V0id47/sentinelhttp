# Implemented transport and analysis threat model — through Phase 21

Assets: operator/private services, approved connections, bounded resources,
URL/header/body secrets and correct evidence. See ssrf-model.md for Phase 3.

| Threat | Control | Evidence / limit |
|---|---|---|
| Malicious HTTP | net/http parser, safe error codes | Raw invalid fixtures; stdlib grammar tolerance remains |
| Proxy scope escape | Proxy=nil | HTTP/HTTPS traps see zero requests |
| Redirect to private host | RoundTrip only | Private/malformed redirects preserve one exchange |
| Large body / lying length | max+1 limited reader, no length-based allocation | Fixed/chunked/exact-bound/huge-length cases |
| Large headers | Explicit initial-header byte cap | Raw oversized fixture; no separate count cap |
| Slow headers/body/TLS | Layered contexts, deadline, cancellation close | Stalling fixtures and observed closure |
| Decompression bomb | No automatic decompression | Invalid gzip retained encoded |
| Hostile headers | Private storage, no raw default output | Canary strings omitted; raw accessors require care |
| Partial response | Partial evidence plus error/completeness | Abrupt close and huge length tests |
| TLS spoofing | Strict trust/name/validity, TLS1.2 minimum | Trusted/untrusted/mismatch/expired/future fixtures |
| Native AIA fetching | Explicit pools on native-verifier platforms | Missing-issuer AIA trap stays untouched |
| Hidden retry/reuse | Ephemeral transport and single-use lease | Fresh peers, failed second lease, no retry |
| Cancellation leaks | Close TCP/body in all return paths | Slow/cancel/truncate fixtures; not a universal leak proof |
| Mutable evidence | Deep-copy nested metadata and accessor values | Mutation regression |
| Rejected input leakage | Validated method only, safe target/codes | Method/query/header canaries |
| Header absence after failed exchange | Explicit capture state | Pre-header failures return no per-field conclusions |
| Header/context confusion | Status, Content-Type, scheme, TLS and IP applicability | HTML/JSON/redirect/no-content/unknown cases |
| Duplicate/malformed policy fields | Field-specific processing rules | HSTS, XCTO, XFO, Referrer, Structured Fields cases |
| Header evidence amplification | 16 values/field, 4 KiB/value, 32 KiB aggregate | Oversize and global-budget regressions |
| Hostile display text | Control/format replacement and explicit raw accessor | Unit tests plus arbitrary-input fuzzing |
| Banner overclaim | Server is only an observed untrusted claim | No product/version/CVE inference |
| Cookie value disclosure | Values and extension values never enter cookie reports | JSON/fmt canaries; raw HeaderValues remains explicit/sensitive |
| Set-Cookie comma confusion | Each captured field parsed independently | Expires comma and multiple-field regressions |
| Cookie scope confusion | Canonical emitter, ordered Domain/Path processing and pinned PSL | Empty/parent/public/unrelated/non-ASCII domain, escaped-path and prefix cases |
| Cookie parser amplification | Field/count/segment/name/unknown/aggregate bounds | Oversize regression and arbitrary-input fuzzing |
| Cookie purpose overclaim | Separate low/medium session-like inference | No authentication, account or exploitability claim |
| CSP policy conflation | Separate enforced/report-only sets and per-field/list-member policies | Multiple policies never unioned; per-policy controls stay separate |
| CSP fallback confusion | Fixed CSP3 control chains; navigation directives have no `default-src` fallback | Focused fallback and malformed-candidate regressions |
| CSP evidence disclosure | Redacted nonce/hash sources; no raw field, report-endpoint or opaque value retention | JSON/fmt privacy regressions and nonce/hash fuzz target |
| CSP parser amplification | Field/aggregate/policy/directive/token/source/observation caps with explicit truncation | Bounds regressions and arbitrary-input fuzz target |
| XFO precedence overclaim | Applicable-HTML framing relation only, using enforced `frame-ancestors` | CSP/XFO correlation tests; no clickjacking finding |
| CORS pre-header false absence | Unavailable capture state; analysis runs before body read | Pre-header and body-failure regressions |
| CORS probe scope escape | Fresh approval and verified dial for every fixed attempt | Local connection-count, out-of-scope and redirect fixtures |
| Probe credential/body leakage | Fixed uncredentialed headers; close each response at headers | Request assertions and stalled/oversized-body fixtures |
| CORS evidence overclaim | Exact two-origin samples, strict preflight parsing, contextual cache/Vary assessment | Duplicate, malformed, truncated, wildcard/ACAC and s-maxage regressions |
| CORS input amplification | 16 values per field, 4 KiB per value, 32 KiB total; no raw invalid retention | Bound regressions and arbitrary-input fuzzing |
| Redirect-based scope escape | Parse each next target, fresh approval and verified dial for every attempt | Local cross-host denial, multi-hop peer assertions and no implicit `Do` redirect |
| HTTPS downgrade | Detect and stop before DNS/dial | Local TLS-to-HTTP trap stays untouched |
| Redirect loop/amplification | Exact normalized URL loop check, 10 default / 20 hard redirect cap, shared deadline | Loop, limit and cancellation fixtures |
| Malformed or repeated Location | One bounded URI-reference; strict parse; duplicates ambiguous | Table tests and arbitrary-input fuzzing |
| Redirect secret disclosure | Redacted target/trace output; raw Location only through explicit accessor | JSON/fmt path/query canaries |
| Finding false absence from partial capture | Rules require complete, applicable upstream evidence | Pre-header failure, body failure and truncated-field regressions |
| Finding overclaim | Fixed predicates, conditional wording and initial INFO/LOW catalog | Positive/negative rule fixtures; no exploit or authenticated exposure assertion |
| Mutable probe/trace summary | Recompute CORS samples; validate terminal redirect Location and stop context | Tampered summary/target/overlong trace regressions; caller provenance is not attested |
| Finding amplification | 256 inspected exchange positions, 32 distinct exchanges, 21 trace hops, 256 findings and 16 refs/finding | Cap and arbitrary-input fuzz regressions; omissions counted |
| Finding output disclosure | Origin-only target, validated opaque IDs, fixed codes and static catalog prose | Hostile path/query/header/cookie/CSP/certificate JSON/fmt canaries |
| Score inflation from absent evidence | Explicit assessed/unavailable/not-applicable components; nullable result and minimum coverage | Empty/pre-header/truncated local regressions and fixed arithmetic tests |
| Score disclosure through source text | Only safe origin, fixed labels/rule IDs and numeric contributions enter score report | JSON/fmt path/query/header/cookie/CSP/certificate canaries |
| Report secret disclosure | Explicit narrow projection; no raw response/body/header accessor in renderer path | Local path/query/Location/cookie/body/nonce canaries in JSON |
| Hostile report file | Streaming token preflight before typed decode, then strict schema/version/size/array/string/identity validation | Excess arrays/depth/members, unknown/trailing JSON and malformed document regressions |
| Ambiguous JSON members | Preflight rejects duplicate and case-folded object keys before Go's last-value decoding | Exact/case-folded nested and top-level regressions |
| Report evidence drift | Chain continuity, exact evidence indices, deterministic finding IDs and fixed score catalog validation | Tampered redirect/probe/scoring fixtures |
| Analyzer omission hidden in report | Cookie field/omission metadata and top-level partial flag include analyzer truncation | 130-cookie local fixture and rendered omission count |
| Terminal/Markdown/HTML injection | Control replacement, Markdown text escaping, `html/template` and no-script CSP | ANSI, Unicode format, Markdown structure and HTML payload regressions |
| Report authenticity confusion | Structural validation only; no signature or provenance claim | Contract and documentation; later consumers must treat files as untrusted |
| CLI request amplification | Reserve worst-case trace + probe cost before network I/O; one serial scan deadline | Opt-in local fixture counts and invalid-budget preflight test |
| CLI private-target misuse | Default scope denial; explicit `--allow-private` lab option uses same boundary | Loopback blocked with zero HTTP hits, lab opt-in test |
| CLI raw URL disclosure | Parse target before scan; safe error codes; report origin-only projection | Userinfo/query canary and blocked-request report tests |
| CLI output clobber or partial publication | Private same-directory temporary file, sync/close, atomic hard-link into a new name | Preexisting-file no-clobber and temp cleanup test |
| Native TLS trust escape | Fail closed without explicit PEM bundle on Windows/macOS/iOS | No-bundle preflight and existing HTTPS/AIA tests |
| False diff resolution | Require successful equivalent primary coverage and complete finding sets | Failed-primary, truncation and path-identity regressions |
| Redacted cookie/redirect identity | Scoped paths and incomplete traces produce unknown, not semantic-change claims | Ambiguous-cookie and failed-trace regressions |
| Diff report disclosure | Origin-redacted display, escaped terminal output and private no-clobber files | Hostile-text, oversized-input and output-conflict regressions |
| Dashboard external exposure | Fixed `tcp4` bind to `127.0.0.1:0`; exact Host/Origin check and no CORS grant | Local listener and foreign-host/origin tests |
| Dashboard arbitrary file read | CLI validates one explicit report and optional baseline before bind; server holds bytes and has fixed routes | Invalid/oversized input, path/query rejection tests |
| Browser execution from backend | Bundled static UI and strict CSP/no-sniff/frame denial | Security-header, route and frontend sink review |
| Malicious report text in browser | React text rendering, no report-controlled links, fixed routes | Browser adversarial fixture and source review |
| Catalog translation confusion | Match rule ID, version and complete canonical prose; translate known limitations only | Altered-prose browser and Go tests; visible fallback |
| Language-dependent evidence drift | Canonical JSON and protocol tokens stay unchanged across locales | Locale CLI tests and catalog audit |
| Generated frontend/catalog drift | CI rebuilds both catalogs and embedded assets and requires a clean generated diff | Local SHA-256 repeatability and actionlint; CI run pending |
| Dependency vulnerabilities | Pinned Go and npm manifests plus online npm and govulncheck audits in CI | Phase 20 point-in-time audits found none; future advisories remain possible |
| Operator misreads scope or local exposure | Four language READMEs and focused security/install guides state authorization, CA, report privacy, score and dashboard limits | Phase 21 link/command checks; documentation does not enforce behavior |

Boundary, Go runtime and OS remain trusted. Peer equality cannot attest routing
behind NAT/VPN/translation. Types/source guards do not sandbox malicious Go code.
Tests use local fixtures, not Internet targets. I/O limits are not strict CPU/RSS
ceilings for parsers/verifiers/resolvers. Trailers have runtime limits and are not
retained. Revocation is not assessed; CA-bundle maintenance is the operator's duty.

No authenticated requests are implemented. The CLI's scan
orchestration is serial and bounded; output files may still contain sensitive
host/certificate/cookie-name metadata and require local file protection.
The Phase 13 report is a bounded snapshot of admitted evidence; it does not
attest who captured it. Certificate text and normalized analyzer strings that
appear in the document remain potentially sensitive and untrusted.
Phase 12 scores only one captured response and exposes its evidence coverage.
The diff retains only a coarse root-or-redacted target scope. Redacted paths
and queries cannot be matched automatically, while even root reports remain
sensitive local artifacts. Reports make no authenticity claim.
The local dashboard is unauthenticated; another process on the operator's
machine can reach its loopback port during a session. The UI must not imply
that report validation proves source authenticity.
Phase 11 findings describe individual captured evidence with
conservative confidence; they do not attest site-wide state or source
authenticity. CORS probes sample only two fixed origins and one preflight; they
do not execute a browser or establish exploitability. Redirect tracing follows
only GET/HTTP(S) status redirects and does not parse HTML, JavaScript or bodies.
CSP analysis is
header-delivered only: it does not parse
meta CSP, bodies or DOM, fetch resource URLs, execute a browser, intersect arbitrary
multi-policy source sets, verify nonce quality/reuse or make XSS/clickjacking
claims. Cookie analysis has no jar and never sends cookies. Future consumers must
not treat raw accessors or parsed header/cookie/CSP/CORS strings as presentation-ready
data.
