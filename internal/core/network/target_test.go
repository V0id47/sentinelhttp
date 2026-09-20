package network

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		raw, host, authority string
		port                 uint16
	}{
		{"http://example.com", "example.com", "example.com", 80},
		{"https://EXAMPLE.com./app/login?token=SECRET#hidden", "example.com", "example.com", 443},
		{"https://example.com:8443", "example.com", "example.com:8443", 8443},
		{"http://192.0.2.1", "192.0.2.1", "192.0.2.1", 80},
		{"https://[2001:db8::1]", "2001:db8::1", "[2001:db8::1]", 443},
		{"https://[::ffff:127.0.0.1]:8443", "127.0.0.1", "127.0.0.1:8443", 8443},
		{"https://bücher.example", "xn--bcher-kva.example", "xn--bcher-kva.example", 443},
		{"https://example.com:65535", "example.com", "example.com:65535", 65535},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			v, err := ParseTarget(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if v.Host() != tc.host || v.Port() != tc.port || v.Authority() != tc.authority {
				t.Fatalf("wrong canonical target: %v", v)
			}
			if strings.Contains(v.RequestURL(), "#") {
				t.Fatal("fragment retained")
			}
		})
	}
}

func TestInvalidTargets(t *testing.T) {
	for _, raw := range []string{"", "example.com", "file:///etc/passwd", "ftp://example.com", "gopher://example.com", "ws://example.com", "wss://example.com", "data:text/plain,x", "javascript:alert(1)", "https://user:SECRET@example.com", "https://", "https:///path", "https://[::1", "https://[example.com]", "https://[::1]suffix", "https://example.com:0", "https://example.com:65536", "https://example.com:-1", "https://example.com:", "https://example.com:0443", "https://example.com:abc", "https://[fe80::1%25eth0]", "https://ex%61mple.com", "https://a\\b", "https://a\nb", "https://-bad.example", "https://a..b", "https://example.com..", "https://a_b.example", "https://2130706433", "https://0177.0.0.1", "https://0x7f000001", "https://127.1", "https://127.0.0.1.", "https://ｅxample.com/\x00"} {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseTarget(raw)
			if err == nil {
				t.Fatal("accepted malformed/unsupported target")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("secret in error")
			}
		})
	}
}

func TestTargetPrivacy(t *testing.T) {
	v, err := ParseTarget("https://example.com/reset/SECRET?token=SECRET&SECRET=value#SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.RequestURL(), "SECRET") {
		t.Fatal("request semantics lost")
	}
	b, _ := json.Marshal(v)
	for _, s := range []string{v.String(), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), string(b)} {
		if strings.Contains(s, "SECRET") {
			t.Fatal("display leaked secret")
		}
	}
	if v.Scheme() != "https" || v.TLSName() != "example.com" {
		t.Fatal("logical identity lost")
	}
}

func TestAddressPolicy(t *testing.T) {
	for _, tc := range []struct {
		ip    string
		class Class
		lab   bool
	}{
		{"93.184.216.34", Public, true}, {"2606:4700:4700::1111", Public, true},
		{"127.0.0.1", Loopback, true}, {"127.255.255.255", Loopback, true},
		{"10.0.0.1", Private, true}, {"172.16.0.1", Private, true}, {"172.31.255.255", Private, true}, {"192.168.1.1", Private, true},
		{"169.254.169.254", LinkLocal, false}, {"169.254.1.1", LinkLocal, false},
		{"0.0.0.0", Unspecified, false}, {"0.1.2.3", Reserved, false}, {"224.0.0.1", Multicast, false},
		{"::1", Loopback, true}, {"fc00::1", Private, true}, {"fd00::1", Private, true}, {"fe80::1", LinkLocal, false}, {"ff02::1", Multicast, false}, {"::", Unspecified, false},
		{"::ffff:127.0.0.1", Loopback, true}, {"::ffff:10.0.0.1", Private, true}, {"::ffff:93.184.216.34", Public, true},
		{"192.0.2.1", Documentation, false}, {"198.51.100.1", Documentation, false}, {"203.0.113.1", Documentation, false}, {"2001:db8::1", Documentation, false}, {"3fff::1", Documentation, false},
		{"100.100.100.200", OtherNonGlobal, false}, {"198.18.0.1", OtherNonGlobal, false}, {"240.0.0.1", Reserved, false}, {"255.255.255.255", Reserved, false},
		{"64:ff9b::7f00:1", OtherNonGlobal, false}, {"2002:7f00:1::", OtherNonGlobal, false}, {"2001::1", OtherNonGlobal, false}, {"fec0::1", OtherNonGlobal, false},
		{"fd00:ec2::254", Metadata, false}, {"192.0.0.9", Reserved, false},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			a := netip.MustParseAddr(tc.ip)
			if got := Classify(a); got != tc.class {
				t.Fatalf("got %s want %s", got, tc.class)
			}
			if got := (Policy{}).Evaluate(a); got.Allowed != (tc.class == Public) {
				t.Fatalf("default %v", got)
			}
			if got := (Policy{AllowPrivate: true}).Evaluate(a); got.Allowed != tc.lab {
				t.Fatalf("lab %v", got)
			}
		})
	}
	for _, a := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		if (Policy{AllowPrivate: true}).Evaluate(a).Allowed {
			t.Fatal("invalid/zone allowed")
		}
	}
}

func FuzzParseTarget(f *testing.F) {
	for _, s := range []string{"https://example.com/a?token=x", "https://[::ffff:127.0.0.1]", "http://2130706433", "https://bücher.example", "https://a..b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseTarget(s)
		if err != nil {
			return
		}
		again, err := ParseTarget(v.RequestURL())
		if err != nil || again.Host() != v.Host() || again.Port() != v.Port() {
			t.Fatal("unstable normalization")
		}
		if strings.ContainsAny(v.Host(), "%/@\\\r\n") || v.Port() == 0 {
			t.Fatal("ambiguous host")
		}
	})
}

func FuzzMappedPolicy(f *testing.F) {
	f.Add(byte(127), byte(0), byte(0), byte(1))
	f.Add(byte(93), byte(184), byte(216), byte(34))
	f.Fuzz(func(t *testing.T, a, b, c, d byte) {
		v4 := netip.AddrFrom4([4]byte{a, b, c, d})
		v6 := netip.AddrFrom16(v4.As16())
		if Classify(v4) != Classify(v6) {
			t.Fatal("mapped bypass")
		}
	})
}
