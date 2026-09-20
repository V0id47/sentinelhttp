package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(c context.Context, n, h string) ([]netip.Addr, error) {
	return f(c, n, h)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(c context.Context, n, a string) (net.Conn, error) { return f(c, n, a) }

type fakeConn struct {
	net.Conn
	peer   net.Addr
	closed atomic.Bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.peer }
func (c *fakeConn) Close() error         { c.closed.Store(true); return nil }
func connection(a string) *fakeConn {
	ap := netip.MustParseAddrPort(a)
	return &fakeConn{peer: net.TCPAddrFromAddrPort(ap)}
}
func target(t *testing.T, s string) Target {
	t.Helper()
	v, e := ParseTarget(s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func boundary(t *testing.T, p Policy) *Boundary {
	t.Helper()
	b, e := NewBoundary(target(t, "https://example.test"), p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func answers(ips ...string) resolverFunc {
	return func(context.Context, string, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, len(ips))
		for i, ip := range ips {
			out[i] = netip.MustParseAddr(ip)
		}
		return out, nil
	}
}
func expectCode(t *testing.T, e error, c Code) {
	t.Helper()
	if ErrorCode(e) != c {
		t.Fatalf("got %v want %s", e, c)
	}
}

func TestApprovalAndRebinding(t *testing.T) {
	b := boundary(t, Policy{})
	calls := 0
	b.resolver = resolverFunc(func(ctx context.Context, n, h string) ([]netip.Addr, error) {
		calls++
		if h != "example.test" || n != "ip" {
			t.Fatal("wrong DNS")
		}
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	dials := 0
	b.dialer = dialFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
		dials++
		if n != "tcp" || a != "93.184.216.34:443" {
			t.Fatalf("not pinned %s", a)
		}
		return connection(a), nil
	})
	v := target(t, "https://example.test/path?secret=x")
	ep, record, e := b.Approve(context.Background(), v)
	if e != nil {
		t.Fatal(e)
	}
	if !record.Decision.Allowed || record.Chosen.String() != "93.184.216.34:443" || record.Host != "example.test" || record.StartedAt.IsZero() {
		t.Fatal("missing evidence")
	}
	// Mutable evidence is not capability state.
	record.Addresses[0].Normalized = netip.MustParseAddr("127.0.0.1")
	c, peer, e := b.Dial(context.Background(), ep)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if !peer.Verified || calls != 1 || dials != 1 || ep.Target().Host() != "example.test" {
		t.Fatal("implicit lookup or wrong identity")
	}
	_, _, e = b.Dial(context.Background(), ep)
	expectCode(t, e, ApprovalUsed)
	_, _, e = b.Approve(context.Background(), v)
	expectCode(t, e, Code("scope_loopback_blocked"))
	if calls != 2 || dials != 1 {
		t.Fatal("new operation escaped scope")
	}
}

func TestDeniedResolutionNeverDials(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []string
		code Code
	}{
		{"mixed", []string{"93.184.216.34", "127.0.0.1"}, MixedResolution},
		{"private", []string{"10.1.1.1"}, "scope_private_blocked"},
		{"mapped", []string{"::ffff:127.0.0.1"}, "scope_loopback_blocked"},
		{"empty", nil, DNSNoAddresses},
		{"ipv6", []string{"fc00::1"}, "scope_private_blocked"},
		{"docs", []string{"192.0.2.1"}, "scope_documentation_blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := boundary(t, Policy{})
			b.resolver = answers(tc.ips...)
			b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { t.Fatal("unexpected dial"); return nil, nil })
			ep, r, e := b.Approve(context.Background(), target(t, "https://example.test"))
			expectCode(t, e, tc.code)
			if ep != nil || r.Decision.Allowed {
				t.Fatal("false approval")
			}
			_, _, e = b.Dial(context.Background(), ep)
			expectCode(t, e, ApprovalInvalid)
		})
	}
}

func TestLiteralAndIPv6(t *testing.T) {
	for _, raw := range []string{"https://93.184.216.34:8443", "https://[2606:4700:4700::1111]:8443"} {
		t.Run(raw, func(t *testing.T) {
			v := target(t, raw)
			b, _ := NewBoundary(v, Policy{})
			b.resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { t.Fatal("literal DNS"); return nil, nil })
			b.dialer = dialFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
				ap, e := netip.ParseAddrPort(a)
				if e != nil || ap.Port() != 8443 {
					t.Fatal("hostname dial")
				}
				return connection(a), nil
			})
			ep, r, e := b.Approve(context.Background(), v)
			if e != nil {
				t.Fatal(e)
			}
			if r.Source != "literal" {
				t.Fatal("wrong source")
			}
			c, _, e := b.Dial(context.Background(), ep)
			if e != nil {
				t.Fatal(e)
			}
			c.Close()
		})
	}
}

func TestDNSFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code Code
	}{
		{"nxdomain", &net.DNSError{IsNotFound: true}, DNSNotFound}, {"temporary", &net.DNSError{IsTemporary: true}, DNSTemporary}, {"timeout", &net.DNSError{IsTimeout: true}, DNSTimeout}, {"failure", errors.New("SECRET"), DNSFailed}, {"cancel", context.Canceled, Cancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := boundary(t, Policy{})
			b.resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nil, tc.err })
			_, _, e := b.Approve(context.Background(), target(t, "https://example.test"))
			expectCode(t, e, tc.code)
			if fmt.Sprintf("%#v", e) == "SECRET" {
				t.Fatal("leak")
			}
		})
	}
}

func TestContextDeadlines(t *testing.T) {
	b := boundary(t, Policy{DNSTimeout: time.Millisecond})
	b.resolver = resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() })
	_, _, e := b.Approve(context.Background(), target(t, "https://example.test"))
	expectCode(t, e, DNSTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, e = b.Approve(ctx, target(t, "https://example.test"))
	expectCode(t, e, Cancelled)
	b = boundary(t, Policy{ConnectTimeout: time.Millisecond})
	b.resolver = answers("93.184.216.34")
	b.dialer = dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
	ep, _, e := b.Approve(context.Background(), target(t, "https://example.test"))
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = b.Dial(context.Background(), ep)
	expectCode(t, e, DialTimeout)
}

func TestPeerVerificationAndCleanup(t *testing.T) {
	for _, peer := range []string{"93.184.216.35:443", "93.184.216.34:8080", "127.0.0.1:443"} {
		t.Run(peer, func(t *testing.T) {
			b := boundary(t, Policy{})
			b.resolver = answers("93.184.216.34")
			conn := connection(peer)
			b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
			ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
			c, r, e := b.Dial(context.Background(), ep)
			expectCode(t, e, PeerMismatch)
			if c != nil || r.Verified || !conn.closed.Load() {
				t.Fatal("socket leaked/unverified")
			}
		})
	}
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	conn := connection("[::ffff:93.184.216.34]:443")
	b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
	ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
	c, _, e := b.Dial(context.Background(), ep)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
}

func TestApprovalCapability(t *testing.T) {
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	var count atomic.Int32
	b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) {
		count.Add(1)
		return connection("93.184.216.34:443"), nil
	})
	_, _, e := b.Dial(context.Background(), &ApprovedEndpoint{})
	expectCode(t, e, ApprovalInvalid)
	ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
	other := boundary(t, Policy{})
	_, _, e = other.Dial(context.Background(), ep)
	expectCode(t, e, ApprovalInvalid)
	copied := *ep
	var wg sync.WaitGroup
	for _, capability := range []*ApprovedEndpoint{ep, &copied} {
		wg.Add(1)
		go func(p *ApprovedEndpoint) {
			defer wg.Done()
			c, _, e := b.Dial(context.Background(), p)
			if e == nil {
				c.Close()
			} else if ErrorCode(e) != ApprovalUsed {
				t.Error(e)
			}
		}(capability)
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("reused copied capability")
	}
}

func TestCancelledApprovalAndLateDial(t *testing.T) {
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	ctx, cancel := context.WithCancel(context.Background())
	ep, _, _ := b.Approve(ctx, target(t, "https://example.test"))
	cancel()
	b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("cancelled approval dial")
		return nil, nil
	})
	_, _, e := b.Dial(context.Background(), ep)
	expectCode(t, e, Cancelled)
	b = boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	ctx, cancel = context.WithCancel(context.Background())
	conn := connection("93.184.216.34:443")
	b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { cancel(); return conn, nil })
	ep, _, _ = b.Approve(context.Background(), target(t, "https://example.test"))
	c, _, e := b.Dial(ctx, ep)
	expectCode(t, e, Cancelled)
	if c != nil || !conn.closed.Load() {
		t.Fatal("late socket leaked")
	}
}

func TestDialErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code Code
	}{{errors.New("SECRET"), DialFailed}, {context.DeadlineExceeded, DialTimeout}, {context.Canceled, Cancelled}} {
		b := boundary(t, Policy{})
		b.resolver = answers("93.184.216.34")
		conn := connection("93.184.216.34:443")
		b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, tc.err })
		ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
		c, _, e := b.Dial(context.Background(), ep)
		expectCode(t, e, tc.code)
		if c != nil || !conn.closed.Load() {
			t.Fatal("error socket leaked")
		}
	}
}

func TestSameHostAndPrivateMode(t *testing.T) {
	for _, p := range []Policy{{SameHost: true}, {AllowPrivate: true}} {
		b := boundary(t, p)
		b.resolver = answers("93.184.216.34")
		_, _, e := b.Approve(context.Background(), target(t, "https://other.test"))
		expectCode(t, e, HostChanged)
		_, _, e = b.Approve(context.Background(), target(t, "https://EXAMPLE.test.:8443/new"))
		if e != nil {
			t.Fatal(e)
		}
	}
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	_, _, e := b.Approve(context.Background(), target(t, "http://other.test"))
	if e != nil {
		t.Fatal(e)
	}
}

func TestLoopbackIntegration(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	v := target(t, "http://"+listener.Addr().String())
	blocked, _ := NewBoundary(v, Policy{})
	_, _, e = blocked.Approve(context.Background(), v)
	expectCode(t, e, "scope_loopback_blocked")
	b, _ := NewBoundary(v, Policy{AllowPrivate: true})
	ep, _, e := b.Approve(context.Background(), v)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, r, e := b.Dial(ctx, ep)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !r.Verified {
		t.Fatal("peer unchecked")
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	server, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	server.Close()
}
