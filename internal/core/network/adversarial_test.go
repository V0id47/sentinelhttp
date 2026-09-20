package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundaryPrivacy(t *testing.T) {
	b, e := NewBoundary(target(t, "https://example.test/SECRET?token=SECRET"), Policy{})
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{fmt.Sprintf("%v", b), fmt.Sprintf("%+v", b), fmt.Sprintf("%#v", b), fmt.Sprintf("%+v", *b)} {
		if strings.Contains(s, "SECRET") {
			t.Fatal("boundary formatting leaks sensitive initial target")
		}
	}
}

func TestMalformedEscapes(t *testing.T) {
	for _, s := range []string{"https://example.test/?token=%zz", "https://example.test/?x=%"} {
		if _, e := ParseTarget(s); e == nil {
			t.Fatal("malformed query escape accepted")
		}
	}
}

func TestSpecialRangeBoundaries(t *testing.T) {
	for _, r := range special {
		first := r.prefix.Masked().Addr()
		last := first
		// Produce last address by setting every host bit in the byte array.
		if first.Is4() {
			bytes := first.As4()
			for i := r.prefix.Bits(); i < 32; i++ {
				bytes[i/8] |= 1 << uint(7-i%8)
			}
			last = netip.AddrFrom4(bytes)
		} else {
			bytes := first.As16()
			for i := r.prefix.Bits(); i < 128; i++ {
				bytes[i/8] |= 1 << uint(7-i%8)
			}
			last = netip.AddrFrom16(bytes)
		}
		for _, a := range []netip.Addr{first, last} {
			if (Policy{AllowPrivate: true}).Evaluate(a).Allowed {
				t.Fatalf("special boundary allowed %s", a)
			}
		}
	}
}

func TestNetipLegacyNumericBehavior(t *testing.T) {
	for _, s := range []string{"2130706433", "0177.0.0.1", "0x7f000001", "127.1"} {
		if _, e := netip.ParseAddr(s); e == nil {
			t.Fatalf("runtime accepts legacy numeric %s", s)
		}
	}
}

func TestResolutionLimitsAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []netip.Addr
		code Code
	}{
		{"invalid", []netip.Addr{{}}, "scope_invalid_blocked"},
		{"zone", []netip.Addr{netip.MustParseAddr("fe80::1%SECRET")}, "scope_invalid_blocked"},
		{"limit", make([]netip.Addr, 65), DNSLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := boundary(t, Policy{})
			b.resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return tc.ips, nil })
			_, r, e := b.Approve(context.Background(), target(t, "https://example.test"))
			expectCode(t, e, tc.code)
			data, _ := json.Marshal(r)
			if strings.Contains(string(data), "SECRET") {
				t.Fatal("zone leak")
			}
		})
	}
	b := boundary(t, Policy{})
	b.resolver = answers("2606:4700:4700::1111", "93.184.216.35", "93.184.216.34", "93.184.216.34")
	ep, r, e := b.Approve(context.Background(), target(t, "https://example.test"))
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Addresses) != 4 || ep.Address().String() != "93.184.216.34:443" {
		t.Fatal("lost answers or nondeterministic choice")
	}
}

func TestLocalhostAndMetadata(t *testing.T) {
	for _, name := range []string{"localhost", "LOCALHOST.", "loopback.test"} {
		for _, lab := range []bool{false, true} {
			v := target(t, "http://"+name)
			b, _ := NewBoundary(v, Policy{AllowPrivate: lab})
			b.resolver = answers("127.0.0.1", "::1")
			ep, _, e := b.Approve(context.Background(), v)
			if lab && e != nil {
				t.Fatal(e)
			}
			if !lab && (e == nil || ep != nil) {
				t.Fatal("localhost allowed")
			}
		}
	}
	for _, name := range []string{"metadata.google.internal", "metadata.goog", "instance-data.ec2.internal", "a.metadata.google.internal"} {
		v := target(t, "http://"+name)
		b, _ := NewBoundary(v, Policy{AllowPrivate: true})
		b.resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			t.Fatal("known metadata resolution")
			return nil, nil
		})
		_, _, e := b.Approve(context.Background(), v)
		expectCode(t, e, HostBlocked)
	}
}

func TestInvalidConstruction(t *testing.T) {
	if _, e := NewBoundary(Target{}, Policy{}); e == nil {
		t.Fatal("invalid initial target")
	}
	for _, p := range []Policy{{DNSTimeout: -time.Second}, {DNSTimeout: 11 * time.Second}, {ConnectTimeout: -1}, {ConnectTimeout: 11 * time.Second}} {
		_, e := NewBoundary(target(t, "https://example.test"), p)
		expectCode(t, e, ConfigInvalid)
	}
	var b *Boundary
	_, _, e := b.Approve(context.Background(), Target{})
	expectCode(t, e, TargetInvalid)
	_, _, e = b.Dial(context.Background(), nil)
	expectCode(t, e, ApprovalInvalid)
	b = &Boundary{}
	_, _, e = b.Approve(context.Background(), Target{})
	expectCode(t, e, TargetInvalid)
	b = boundary(t, Policy{})
	_, _, e = b.Approve(nil, target(t, "https://example.test"))
	expectCode(t, e, TargetInvalid)
}

func TestApprovalExpiry(t *testing.T) {
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	instant := time.Now()
	b.now = func() time.Time { return instant }
	ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
	instant = instant.Add(approvalLifetime)
	b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { t.Fatal("expired dial"); return nil, nil })
	_, _, e := b.Dial(context.Background(), ep)
	expectCode(t, e, ApprovalExpired)
}

func TestOriginalContextCancelledDuringDial(t *testing.T) {
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ep, _, _ := b.Approve(ctx, target(t, "https://example.test"))
	b.dialer = dialFunc(func(c context.Context, _, _ string) (net.Conn, error) { cancel(); <-c.Done(); return nil, c.Err() })
	_, _, e := b.Dial(context.Background(), ep)
	expectCode(t, e, Cancelled)
}

func TestLateResolverResult(t *testing.T) {
	b := boundary(t, Policy{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	ep, _, e := b.Approve(ctx, target(t, "https://example.test"))
	expectCode(t, e, Cancelled)
	if ep != nil {
		t.Fatal("late approval")
	}
}

func TestInvalidPeers(t *testing.T) {
	for _, p := range []net.Addr{nil, &net.UDPAddr{}, (*net.TCPAddr)(nil), &net.TCPAddr{IP: net.IP{1, 2}, Port: 443}, &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 0}, &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 65536}, &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443, Zone: "bad"}} {
		b := boundary(t, Policy{})
		b.resolver = answers("93.184.216.34")
		c := &fakeConn{peer: p}
		b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return c, nil })
		ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
		_, _, e := b.Dial(context.Background(), ep)
		expectCode(t, e, PeerMismatch)
		if !c.closed.Load() {
			t.Fatal("leaked bad peer")
		}
	}
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	b.dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, nil })
	ep, _, _ := b.Approve(context.Background(), target(t, "https://example.test"))
	_, _, e := b.Dial(context.Background(), ep)
	expectCode(t, e, DialFailed)
}

func TestConcurrentOperations(t *testing.T) {
	b := boundary(t, Policy{})
	b.resolver = answers("93.184.216.34")
	var calls atomic.Int32
	b.dialer = dialFunc(func(_ context.Context, _, a string) (net.Conn, error) { calls.Add(1); return connection(a), nil })
	v := target(t, "https://example.test")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ep, _, e := b.Approve(context.Background(), v)
			if e != nil {
				t.Error(e)
				return
			}
			c, _, e := b.Dial(context.Background(), ep)
			if e != nil {
				t.Error(e)
				return
			}
			c.Close()
		}()
	}
	wg.Wait()
	if calls.Load() != 32 {
		t.Fatal("missing operation")
	}
}

func TestFaultPrivacy(t *testing.T) {
	err := operationError(context.Background(), fmt.Errorf("https://user:SECRET@evil: %w", errors.New("SECRET")), true)
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "SECRET") {
		t.Fatal("raw error retained")
	}
	if err.(*Fault).Code() != DNSFailed {
		t.Fatal("code lost")
	}
}

func TestPublicAPICannotForgeApproval(t *testing.T) {
	typ := reflect.TypeFor[ApprovedEndpoint]()
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Fatal("forgeable endpoint")
		}
	}
	b := boundary(t, Policy{})
	ep := &ApprovedEndpoint{}
	if e := json.Unmarshal([]byte(`{"Address":"127.0.0.1:80","Allowed":true}`), ep); e != nil {
		t.Fatal(e)
	}
	_, _, e := b.Dial(context.Background(), ep)
	expectCode(t, e, ApprovalInvalid)
}

// Regression guard for future packages: target socket construction is owned by
// boundary.go. This is a code architecture check, not a sandbox against hostile Go code.
func TestSocketOwnership(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			return e
		}
		imports := map[string]string{}
		for _, im := range f.Imports {
			pkg := strings.Trim(im.Path.Value, `"`)
			alias := filepath.Base(pkg)
			if im.Name != nil {
				alias = im.Name.Name
			}
			imports[alias] = pkg
			rel, _ := filepath.Rel(root, path)
			adapter := filepath.ToSlash(rel) == "internal/core/httpclient/client.go" || filepath.ToSlash(rel) == "internal/core/httpclient/transport.go" || filepath.ToSlash(rel) == "internal/core/httpclient/model.go"
			// The Windows output adapter uses syscall only to set a protected
			// report-file DACL before writing data; it has no socket API.
			aclAdapter := filepath.ToSlash(rel) == "internal/cli/output_windows.go"
			// The dashboard's sole inbound socket is a fixed loopback listener.
			dashboardAdapter := filepath.ToSlash(rel) == "internal/dashboard/server.go"
			if pkg == "net/http" && !adapter && !dashboardAdapter || (pkg == "syscall" || pkg == "unsafe") && !aclAdapter || strings.Contains(pkg, "/sys/") {
				t.Errorf("unexpected network bypass import %s in %s", pkg, path)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			s, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := s.X.(*ast.Ident)
			if !ok {
				return true
			}
			pkg := imports[ident.Name]
			if pkg == "net/http" && (s.Sel.Name == "Get" || s.Sel.Name == "DefaultClient" || s.Sel.Name == "DefaultTransport" || s.Sel.Name == "ProxyFromEnvironment") {
				t.Errorf("implicit HTTP networking forbidden: %s in %s", s.Sel.Name, path)
			}
			if pkg == "crypto/tls" && strings.HasPrefix(s.Sel.Name, "Dial") {
				t.Errorf("TLS socket bypass: %s", path)
			}
			if pkg == "net" && (strings.HasPrefix(s.Sel.Name, "Dial") || strings.HasPrefix(s.Sel.Name, "Listen")) {
				rel, _ := filepath.Rel(root, path)
				if filepath.ToSlash(rel) != "internal/core/network/boundary.go" && filepath.ToSlash(rel) != "internal/dashboard/server.go" {
					t.Errorf("socket primitive outside boundary: %s", path)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
