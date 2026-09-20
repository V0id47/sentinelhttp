# SSRF and rebinding model

Protected assets: operator machine and internal services, target scope decisions,
connection provenance and URL secrets. Untrusted inputs: URLs, DNS answers and
future redirect locations. Trusted computing base: this package, IDNA dependency,
Go resolver/dialer, OS networking and caller lifecycle handling.

Threat: hostname validated public, then resolved again by a client to private.
Defense: Approve resolves once and validates the entire answer set. Dial accepts
only a single-use capability and connects to its literal IP:port. There is no
second hostname resolution in Dial. TestApprovalAndRebinding changes fake DNS from
public to loopback; first dial uses the approved public address without querying
DNS again, and the second approval is denied. No real public connection is made.

Fresh resolution per request is different from implicit resolution during dial:
the former is required, the latter prohibited. Even the same hostname must acquire
a new approval for another operation. A malicious mixed A/AAAA set is denied as a
whole. The lack of public-only fallback intentionally sacrifices availability.

| Threat | Control | Test evidence |
|---|---|---|
| Private/local access | netip predicates, explicit policy | TestAddressPolicy, TestLocalhostAndMetadata |
| Mixed DNS | All addresses evaluated; no capability on deny | TestDeniedResolutionNeverDials |
| Rebinding/TOCTOU | Literal IP dial, fresh approval per operation | TestApprovalAndRebinding |
| Approval forgery/replay | Private fields, owner pointer, shared atomic consumption | TestApprovalCapability, TestPublicAPICannotForgeApproval |
| IPv4-mapped ambiguity | Unmap before classification/dial/peer | TestAddressPolicy, FuzzMappedPolicy |
| Host parsing tricks | IDNA/strict host and port parsing | TestInvalidTargets, FuzzParseTarget |
| Port substitution | IP and port equality | TestPeerVerificationAndCleanup |
| Peer confusion | Typed TCP address validation and close | TestInvalidPeers |
| Cancellation race | Check before/after dependencies, propagate original context | TestCancelledApprovalAndLateDial, TestOriginalContextCancelledDuringDial |
| Expired approval | Ten-second expiry, no retry | TestApprovalExpiry |
| Oversized DNS | Bound answer processing | TestResolutionLimitsAndEvidence |
| Secret in debug/error | Origin-only display, no raw causes | TestTargetPrivacy, TestBoundaryPrivacy, TestFaultPrivacy |
| Alternate socket API | Source ownership guard + review | TestSocketOwnership |

The opt-in redirect journey, `TraceRedirects`, parses each next
target, blocks HTTPS-to-HTTP downgrades before dialing, and routes each
permitted hop through a fresh approval and verified peer. Default boundary
policy permits public cross-host targets; private opt-in forces SameHost, and
the journey's own SameHost option can only tighten this. A cross-host change
does not establish authorization to assess that host. The one-exchange `Do`
and CORS probes still never follow redirects. See redirect-analysis.md and
threat-model.md for details and limits.
`SameHost` means canonical hostname or IP equality, not same port, origin or
service. Use a stricter caller authorization boundary when a single port or
service is the permitted scope.

## Explicit limits

- Peer matching sees the kernel socket destination, not physical routing behind
  NAT, VPN, transparent proxies, custom NAT64 or compromised host networking.
- The system resolver can use cache/hosts/search suffixes and OS-managed workers.
  Deadline adherence is tested with cooperative fakes and local sockets, not a
  guarantee about every platform resolver implementation. No custom DNS transport.
- No current public-IP reachability claim, routing verification or DNSSEC validation.
- `allow_private` permits loopback services and private hosts deliberately, including
  a DNS answer that changes within allowed classes. It is not safe for arbitrary
  untrusted lab names; the opt-in changes the threat boundary.
- Metadata deny names/IPs are non-exhaustive. Global-looking vendor-specific
  metadata services or routes cannot all be identified by address classification.
- Go types make accidental misuse difficult, not malicious application code
  impossible. Unsafe, reflective corruption or adding independent network imports
  is outside capability enforcement and must be caught by review/tooling.
- Context cancellation after successful ownership transfer does not close the
  returned socket. The HTTP protocol operation supplies deadlines and closure.
- Go statement coverage is not branch coverage. Race testing was attempted but
  cannot run on this host without a cgo-compatible C compiler.

Reference: [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
