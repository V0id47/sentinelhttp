package httpclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"sentinelhttp/internal/core/cookieanalysis"
	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/cspanalysis"
	"sentinelhttp/internal/core/headeranalysis"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/tlsanalysis"
)

type TLSMetadata struct {
	Version                        uint16
	CipherSuite                    uint16
	ServerName, NegotiatedProtocol string
	Verified                       bool
}
type Metadata struct {
	ID, Target                          string
	Method                              Method
	StartedAt, EndedAt                  time.Time
	Duration                            time.Duration
	RequestAttempts, ConnectionAttempts int
	StatusCode                          int
	Protocol                            string
	DeclaredContentLength               int64
	BytesRead                           int64 // Entity bytes read, including the one-byte limit lookahead; not wire bytes.
	BodyTruncated, BodyComplete         bool
	Result                              Code
	Resolution                          network.ResolutionRecord
	Peer                                network.PeerRecord
	TLS                                 *TLSMetadata
}
type transient struct {
	headers http.Header
	body    []byte
}

// Response is caller-owned, not shared mutable state. Raw accessors are sensitive.
// No raw body/header value is exported by default formatting or JSON.
type Response struct {
	meta         Metadata
	raw          *transient
	tlsEvidence  tlsanalysis.Evidence
	headerReport headeranalysis.Report
	cookieReport cookieanalysis.Report
	cspReport    cspanalysis.Report
	corsReport   corsanalysis.Report
}

// TLSAnalysis explicitly exposes bounded certificate-controlled evidence.
// Callers must treat all text as untrusted and escape for their output context.
func (r Response) TLSAnalysis() tlsanalysis.Evidence { return r.tlsEvidence.Clone() }

// HeaderAnalysis exposes bounded parsed results. Values remains an explicit
// untrusted evidence accessor on the returned, independently owned report.
func (r Response) HeaderAnalysis() headeranalysis.Report { return r.headerReport.Clone() }

// CookieAnalysis exposes bounded policy results without cookie values. Cookie
// names and effective paths/domains remain untrusted explicit evidence.
func (r Response) CookieAnalysis() cookieanalysis.Report { return r.cookieReport.Clone() }

// CSPAnalysis exposes bounded, parsed CSP evidence. Callers must treat retained
// directive and host-source text as untrusted and escape it for their output context.
func (r Response) CSPAnalysis() cspanalysis.Report { return r.cspReport.Clone() }

// CORSAnalysis exposes bounded response-header evidence. Any retained valid
// origin is untrusted text and must be escaped for its output context.
func (r Response) CORSAnalysis() corsanalysis.Report { return r.corsReport.Clone() }

func (r Response) Metadata() Metadata {
	m := r.meta
	m.Resolution.Addresses = append([]network.AddressRecord(nil), r.meta.Resolution.Addresses...)
	if r.meta.TLS != nil {
		tls := *r.meta.TLS
		m.TLS = &tls
	}
	return m
}
func (r Response) String() string {
	return fmt.Sprintf("HTTP exchange %s: status=%d result=%s", r.meta.ID, r.meta.StatusCode, r.meta.Result)
}
func (r Response) GoString() string             { return r.String() }
func (r Response) MarshalJSON() ([]byte, error) { return json.Marshal(r.meta) }
func (r Response) HeaderValues(name string) []string {
	if r.raw == nil {
		return nil
	}
	return append([]string(nil), r.raw.headers.Values(name)...)
}
func (r Response) Body() []byte {
	if r.raw == nil {
		return nil
	}
	return append([]byte(nil), r.raw.body...)
}
func (r *Response) DiscardBody() {
	if r != nil && r.raw != nil {
		clear(r.raw.body)
		r.raw.body = nil
	}
}

type HeaderInfo struct {
	Name      string
	Count     int
	Sensitive bool
}

func (r Response) HeaderInfo() []HeaderInfo {
	if r.raw == nil {
		return nil
	}
	out := make([]HeaderInfo, 0, len(r.raw.headers))
	for n, v := range r.raw.headers {
		out = append(out, HeaderInfo{n, len(v), IsSensitiveHeader(n)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func IsSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token", "authentication-info", "proxy-authentication-info":
		return true
	}
	return false
}
