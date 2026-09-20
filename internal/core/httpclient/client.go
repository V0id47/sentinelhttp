// Package httpclient performs one bounded HTTP exchange through network.Boundary.
package httpclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/netip"
	"runtime"
	"time"

	"sentinelhttp/internal/core/cookieanalysis"
	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/cspanalysis"
	"sentinelhttp/internal/core/headeranalysis"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/tlsanalysis"
)

type Client struct {
	boundary *network.Boundary
	config   Config
	roots    *x509.CertPool
}

func New(b *network.Boundary, c Config) (*Client, error) {
	if b == nil {
		return nil, fault(ConfigInvalid)
	}
	cfg, roots, e := normalize(c)
	if e != nil {
		return nil, e
	}
	return &Client{b, cfg, roots}, nil
}

// Do returns metadata even on failure. No raw stdlib error (which can embed the
// request URL) is retained. Body/headers are transient, opt-in sensitive accessors.
func (c *Client) Do(ctx context.Context, target network.Target, method Method) (*Response, error) {
	return c.do(ctx, target, method, exchangeProfile{})
}

type exchangeProfile struct {
	probe       corsanalysis.ProbeKind
	headersOnly bool
}

func (c *Client) do(ctx context.Context, target network.Target, method Method, profile exchangeProfile) (result *Response, err error) {
	started := time.Now()
	r := &Response{meta: Metadata{Target: target.SafeURL(), StartedAt: started.UTC(), DeclaredContentLength: -1}, raw: &transient{}}
	_, hostParseError := netip.ParseAddr(target.Host())
	hostIsIP := hostParseError == nil
	r.headerReport = headeranalysis.Analyze(headeranalysis.Input{Scheme: target.Scheme(), HostIsIP: hostIsIP})
	r.cookieReport = cookieanalysis.Analyze(cookieanalysis.Input{Scheme: target.Scheme(), Host: target.Host()})
	r.cspReport = cspanalysis.Analyze(cspanalysis.Input{})
	r.corsReport = corsanalysis.Analyze(corsanalysis.Input{})
	r.tlsEvidence = tlsanalysis.Evidence{Status: "unavailable", ObservedAt: started.UTC()}
	if target.Scheme() == "http" {
		r.tlsEvidence.Status = "not_applicable"
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	r.meta.ID = hex.EncodeToString(id[:])
	defer func() {
		r.meta.EndedAt = time.Now().UTC()
		r.meta.Duration = time.Since(started)
		r.meta.Result = ErrorCode(err)
	}()
	bad := func(code Code) (*Response, error) { return r, fault(code) }
	if c == nil || c.boundary == nil || ctx == nil {
		return bad(ConfigInvalid)
	}
	if method != GET && method != HEAD && method != OPTIONS {
		return bad(MethodRejected)
	}
	r.meta.Method = method
	// Platform verification may fetch AIA/roots outside our transport. An explicit
	// pool selects Go's offline verifier; never fall back to native chain building.
	if target.Scheme() == "https" && c.roots == nil && (runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios") {
		return bad(CABundleRequired)
	}
	op, cancel := context.WithTimeout(ctx, c.config.TotalTimeout)
	defer cancel()
	req, e := http.NewRequestWithContext(op, string(method), target.RequestURL(), nil)
	if e != nil {
		return bad(BuildFailed)
	}
	req.Host = target.Authority()
	req.Close = true
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	switch profile.probe {
	case "":
	case corsanalysis.FirstGET:
		req.Header.Set("Origin", corsanalysis.ProbeOriginA)
	case corsanalysis.SecondGET:
		req.Header.Set("Origin", corsanalysis.ProbeOriginB)
	case corsanalysis.Preflight:
		req.Header.Set("Origin", corsanalysis.ProbeOriginA)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "X-SentinelHTTP-Probe")
	default:
		return bad(ConfigInvalid)
	}
	approval, resolution, e := c.boundary.Approve(op, target)
	r.meta.Resolution = resolution
	if e != nil {
		return bad(Code(network.ErrorCode(e)))
	}
	r.meta.ConnectionAttempts = 1
	conn, peer, e := c.boundary.Dial(op, approval)
	r.meta.Peer = peer
	if e != nil {
		return bad(Code(network.ErrorCode(e)))
	}
	defer conn.Close()
	// A context deadline and explicit cancellation closure cover TLS, HTTP and body
	// reads, including peers that stall. Boundary owns establishment; we own lifetime.
	deadline, _ := op.Deadline()
	if e = conn.SetDeadline(deadline); e != nil {
		return bad(TransportInvariant)
	}
	tcpConn := conn // immutable capture; conn is replaced with the TLS wrapper below.
	stop := context.AfterFunc(op, func() { _ = tcpConn.Close() })
	defer stop()
	if target.Scheme() == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: target.TLSName(), RootCAs: c.roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: false})
		handshake, hcancel := context.WithTimeout(op, c.config.TLSHandshakeTimeout)
		e = tlsConn.HandshakeContext(handshake)
		r.tlsEvidence = tlsanalysis.Capture(tlsConn.ConnectionState(), e, started)
		if e != nil {
			code := tlsError(handshake, e)
			hcancel()
			return bad(code)
		}
		hcancel()
		state := tlsConn.ConnectionState()
		r.meta.TLS = &TLSMetadata{state.Version, state.CipherSuite, target.TLSName(), state.NegotiatedProtocol, len(state.VerifiedChains) > 0}
		conn = tlsConn
	}
	tr := singleTransport(conn, target, c.config)
	defer tr.CloseIdleConnections()
	r.meta.RequestAttempts = 1
	// RoundTrip has no redirect layer. Client.Do parses Location before
	// CheckRedirect and discards otherwise valid responses on malformed Location.
	response, e := tr.RoundTrip(req)
	if e != nil {
		return bad(httpError(op, e, false))
	}
	defer response.Body.Close()
	r.meta.StatusCode = response.StatusCode
	r.meta.Protocol = response.Proto
	r.meta.DeclaredContentLength = response.ContentLength
	r.raw.headers = response.Header.Clone()
	tlsVerified := r.meta.TLS != nil && r.meta.TLS.Verified
	r.headerReport = headeranalysis.Analyze(headeranalysis.Input{
		Captured: true, Scheme: target.Scheme(), TLSVerified: tlsVerified,
		HostIsIP: hostIsIP, StatusCode: response.StatusCode, Headers: response.Header,
	})
	r.cspReport = cspanalysis.Analyze(cspanalysis.Input{
		Captured:              true,
		DocumentApplicability: cspApplicability(r.headerReport.Context),
		EnforcedFields:        response.Header.Values("Content-Security-Policy"),
		ReportOnlyFields:      response.Header.Values("Content-Security-Policy-Report-Only"),
		XFrameOptions:         cspXFOEvidence(r.headerReport),
	})
	r.corsReport = corsanalysis.Analyze(corsanalysis.Input{
		Captured: true, StatusCode: response.StatusCode, Headers: response.Header,
	})
	r.cookieReport = cookieanalysis.Analyze(cookieanalysis.Input{
		Captured: true, Scheme: target.Scheme(), Host: target.Host(),
		EmitterResource: target.SafeURL(), RequestPath: req.URL.EscapedPath(),
		ObservedAt: time.Now().UTC(), Fields: response.Header.Values("Set-Cookie"),
	})
	if profile.headersOnly {
		return r, nil
	}
	// The extra byte establishes actual exceedance. Content-Length never controls
	// allocation. No decompression occurs; these are transfer-decoded entity bytes.
	body, e := io.ReadAll(io.LimitReader(response.Body, c.config.MaxResponseBytes+1))
	r.meta.BytesRead = int64(len(body))
	r.meta.BodyTruncated = int64(len(body)) > c.config.MaxResponseBytes
	if r.meta.BodyTruncated {
		body = body[:c.config.MaxResponseBytes]
	}
	r.raw.body = body
	if e != nil {
		return bad(httpError(op, e, true))
	}
	r.meta.BodyComplete = !r.meta.BodyTruncated
	return r, nil
}
