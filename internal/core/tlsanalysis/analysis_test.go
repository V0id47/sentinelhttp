package tlsanalysis

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func TestCertificateEvidence(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		delta  time.Duration
		days   int64
		status string
	}{
		{"expired fraction", -time.Second, -1, "expired"}, {"exact expiry", 0, 0, "expiring_soon"},
		{"near", 30 * 24 * time.Hour, 30, "expiring_soon"}, {"beyond", 30*24*time.Hour + time.Second, 30, "valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &x509.Certificate{Raw: []byte("fixture"), Subject: pkix.Name{CommonName: "lab"}, DNSNames: []string{"lab.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(tc.delta)}
			e := Capture(tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}, nil, now)
			sum := sha256.Sum256(c.Raw)
			if e.Status != "verified" || len(e.Presented) != 1 || len(e.VerifiedChains) != 1 || e.Presented[0].SHA256 != hex.EncodeToString(sum[:]) || e.Presented[0].DaysRemaining != tc.days || e.Presented[0].Validity != tc.status {
				t.Fatalf("wrong evidence: %+v", e)
			}
			c.DNSNames[0] = "mutated"
			if e.Presented[0].SANs[0].Value != "lab.test" {
				t.Fatal("retained input alias")
			}
			copy := e.Clone()
			copy.Presented[0].SANs[0].Value = "copy"
			copy.VerifiedChains[0][0].Subject = "copy"
			if e.Presented[0].SANs[0].Value != "lab.test" || e.VerifiedChains[0][0].Subject == "copy" {
				t.Fatal("clone alias")
			}
		})
	}
}

func TestSANTypesAndLongValidity(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 1, time.UTC)
	c := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, EmailAddresses: []string{"lab@example.test"}, URIs: []*url.URL{{Scheme: "https", Host: "example.test"}, nil}}
	e := Capture(tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil, c}}, nil, now)
	if len(e.Presented) != 1 || !e.Truncated || e.Presented[0].DaysRemaining < 2000000 || len(e.Presented[0].SANs) != 3 || e.Presented[0].SANs[0].Kind != "ip" || e.Presented[0].SANs[1].Kind != "email" || e.Presented[0].SANs[2].Kind != "uri" {
		t.Fatalf("bad SAN/dates %+v", e)
	}
	c.NotAfter = now.Add(-time.Nanosecond)
	e = Capture(tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}, nil, now)
	if e.Presented[0].DaysRemaining != -1 {
		t.Fatal("fractional day rounded incorrectly")
	}
}

func FuzzDisplayText(f *testing.F) {
	for _, s := range []string{"normal", "\x1b[31m\u202e", "\xff", strings.Repeat("界", 500)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, _ := displayText(s)
		if len(out) > 1024 || !utf8.ValidString(out) {
			t.Fatal("invalid bounded text")
		}
		for _, r := range out {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatal("unsafe control")
			}
		}
	})
}

func TestFailureAndUnavailable(t *testing.T) {
	now := time.Now()
	c := &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}
	e := Capture(tls.ConnectionState{}, &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{c}, Err: errors.New("SECRET")}, now)
	if e.Status != "unverified" || e.Presented[0].Validity != "not_yet_valid" || len(e.VerifiedChains) != 0 || e.Version != 0 {
		t.Fatalf("bad failure evidence: %+v", e)
	}
	for _, err := range []error{nil, errors.New("SECRET")} {
		if Capture(tls.ConnectionState{}, err, now).Status != "unavailable" {
			t.Fatal("invented evidence")
		}
	}
}

func TestHostileEvidenceBounds(t *testing.T) {
	c := &x509.Certificate{Subject: pkix.Name{CommonName: strings.Repeat("x", 3000) + "\x1b\n\u202e"}, DNSNames: make([]string, 300)}
	for i := range c.DNSNames {
		c.DNSNames[i] = strings.Repeat("a", 2000) + "\x1b"
	}
	chain := make([]*x509.Certificate, 30)
	for i := range chain {
		chain[i] = c
	}
	e := Capture(tls.ConnectionState{HandshakeComplete: true, PeerCertificates: chain, VerifiedChains: [][]*x509.Certificate{chain, chain, chain, chain, chain}}, nil, time.Now())
	if !e.Truncated || len(e.Presented) != 16 || len(e.VerifiedChains) != 4 || e.PresentedCount != 30 || e.VerifiedChainCount != 5 {
		t.Fatal("chain bounds")
	}
	cert := e.Presented[0]
	if !cert.Truncated || len(cert.Subject) > 1024 || len(cert.SANs) != 128 || cert.SANCount != 300 || len(cert.SANs[0].Value) > 1024 {
		t.Fatal("certificate bounds")
	}
	c.Subject.CommonName = "a\x1b\n\u202eb"
	e = Capture(tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}, errors.New("fail"), time.Now())
	if strings.ContainsAny(e.Presented[0].Subject, "\x1b\n\u202e") {
		t.Fatal("unsafe display text")
	}
}
