package httpclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"

	"sentinelhttp/internal/core/network"
)

// A transport can borrow exactly one already-approved, peer-verified connection.
// Neither callback has a socket primitive, resolver or fallback.
func singleTransport(conn net.Conn, t network.Target, c Config) *http.Transport {
	var used atomic.Bool
	expected := net.JoinHostPort(t.Host(), strconv.Itoa(int(t.Port())))
	take := func(ctx context.Context, n, addr string) (net.Conn, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if n != "tcp" || addr != expected || !used.CompareAndSwap(false, true) {
			return nil, fault(TransportInvariant)
		}
		return conn, nil
	}
	no := func(context.Context, string, string) (net.Conn, error) { return nil, fault(TransportInvariant) }
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tr := &http.Transport{
		Proxy: nil, DialContext: no, DialTLSContext: no,
		DisableKeepAlives: true, DisableCompression: true,
		MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: c.TotalTimeout,
		TLSHandshakeTimeout: c.TLSHandshakeTimeout, ResponseHeaderTimeout: c.ResponseHeaderTimeout,
		ExpectContinueTimeout: 0, MaxResponseHeaderBytes: c.MaxResponseHeaderBytes,
		ForceAttemptHTTP2: false, Protocols: protocols, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	if t.Scheme() == "https" {
		tr.DialTLSContext = take
	} else {
		tr.DialContext = take
	}
	return tr
}
