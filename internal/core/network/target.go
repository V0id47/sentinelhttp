package network

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Target can only be made usable by ParseTarget. Its zero value is rejected.
// RequestURL is explicitly sensitive. Default formatting and JSON expose origin only.
type Target struct {
	scheme, host, authority, request string
	port                             uint16
	valid                            bool
}

func (t Target) Scheme() string    { return t.scheme }
func (t Target) Host() string      { return t.host }
func (t Target) Port() uint16      { return t.port }
func (t Target) Authority() string { return t.authority }

// TLSName is the canonical logical host. A future TLS client validates IP SANs
// for literals (crypto/tls omits SNI for IPs), not a substituted resolved DNS IP.
func (t Target) TLSName() string    { return t.host }
func (t Target) RequestURL() string { return t.request }

// SafeURL omits all path/query/fragment data, including potentially secret keys.
func (t Target) SafeURL() string {
	if !t.valid {
		return "[invalid-target]"
	}
	return t.scheme + "://" + t.authority + "/[REDACTED]"
}
func (t Target) String() string               { return t.SafeURL() }
func (t Target) GoString() string             { return t.SafeURL() }
func (t Target) MarshalJSON() ([]byte, error) { return json.Marshal(t.SafeURL()) }

func ParseTarget(raw string) (Target, error) {
	bad := func() (Target, error) { return Target{}, fail(TargetInvalid) }
	if len(raw) == 0 || len(raw) > 8192 || !utf8.ValidString(raw) {
		return bad()
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\\' {
			return bad()
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad()
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fail(SchemeUnsupported)
	}
	if u.User != nil {
		return Target{}, fail(UserinfoRejected)
	}
	// net/url intentionally leaves RawQuery uninterpreted; reject malformed escapes
	// without decoding/re-encoding the query used by the future request.
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return bad()
	}
	if u.Opaque != "" || u.Host == "" || strings.Contains(u.Host, "%") {
		return bad()
	}
	host := u.Hostname()
	if host == "" {
		return bad()
	}
	// Strict authority shape, rather than accepting url.Parse's permissive bracket handling.
	if strings.HasPrefix(u.Host, "[") {
		end := strings.IndexByte(u.Host, ']')
		if end < 0 {
			return bad()
		}
		rest := u.Host[end+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return bad()
		}
		ip, e := netip.ParseAddr(host)
		if e != nil || !ip.Is6() || ip.Zone() != "" {
			return bad()
		}
	} else if strings.ContainsAny(host, ":[]") {
		return bad()
	}
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	explicit := strings.HasSuffix(u.Host, ":") || u.Port() != ""
	if explicit {
		p := u.Port()
		if p == "" || len(p) > 5 || len(p) > 1 && p[0] == '0' {
			return bad()
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return bad()
			}
		}
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || n == 0 {
			return bad()
		}
		port = uint16(n)
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return bad()
		}
		host = ip.Unmap().String()
	} else {
		// Lookup profile handles IDNA normalization; strict ASCII label checks follow it.
		ascii, e := idna.Lookup.ToASCII(host)
		if e != nil {
			return bad()
		}
		host = strings.ToLower(ascii)
		host = strings.TrimSuffix(host, ".")
		if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
			return bad()
		}
		// Reject historical numeric forms instead of implementing conversion or relying
		// on platform resolver interpretation. IDNA-mapped numeric forms are included.
		if _, e := netip.ParseAddr(host); e == nil {
			return bad()
		}
		labels := strings.Split(host, ".")
		numeric := true
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return bad()
			}
			n := true
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return bad()
				}
				if c < '0' || c > '9' {
					n = false
				}
			}
			if !n && !(strings.HasPrefix(label, "0x") && isHex(label[2:])) {
				numeric = false
			}
		}
		if numeric {
			return bad()
		}
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if explicit {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	u.Host = authority
	u.Fragment = ""
	u.RawFragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return Target{scheme: u.Scheme, host: host, authority: authority, port: port, request: u.String(), valid: true}, nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
