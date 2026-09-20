package httpclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSAnalysisIntegration(t *testing.T) {
	for _, tc := range []struct {
		name, host, status string
		offset             time.Duration
		code               Code
	}{
		{"trusted", "localhost", "verified", 0, OK},
		{"unknown", "localhost", "unverified", 0, TLSUnknownAuthority},
		{"mismatch", "private-canary.test", "unverified", 0, TLSHostnameMismatch},
		{"expired", "localhost", "unverified", -4 * time.Hour, TLSExpired},
		{"future", "localhost", "unverified", 4 * time.Hour, TLSNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().Add(tc.offset)
			cert, ca := labCertificate(t, tc.host, now.Add(-time.Hour), now.Add(time.Hour))
			var hits atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			s.StartTLS()
			defer s.Close()
			if tc.name == "unknown" {
				_, ca = labCertificate(t, "unrelated", now.Add(-time.Hour), now.Add(time.Hour))
			}
			target := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
			c := makeClient(t, target, true, Config{LabCAPEM: ca})
			r, err := c.Do(context.Background(), parse(t, target), GET)
			if ErrorCode(err) != tc.code {
				t.Fatal(err)
			}
			evidence := r.TLSAnalysis()
			if evidence.Status != tc.status || len(evidence.Presented) != 2 || evidence.Presented[0].SANs[0].Value != tc.host {
				t.Fatalf("missing evidence %+v", evidence)
			}
			if tc.code != OK && (hits.Load() != 0 || r.Metadata().RequestAttempts != 0 || len(evidence.VerifiedChains) != 0) {
				t.Fatal("HTTP or trust after failure")
			}
			if tc.code == OK && (hits.Load() != 1 || len(evidence.VerifiedChains) != 1 || evidence.Version == 0) {
				t.Fatal("missing authenticated evidence")
			}
			evidence.Presented[0].SANs[0].Value = "changed"
			if r.TLSAnalysis().Presented[0].SANs[0].Value != tc.host {
				t.Fatal("alias")
			}
			encoded, _ := json.Marshal(r)
			formatted := string(encoded) + fmt.Sprintf("%v %+v %#v", r, r, r)
			if strings.Contains(formatted, "private-canary") || strings.Contains(formatted, "SentinelHTTP ephemeral") {
				t.Fatal("certificate text leaked by default")
			}
		})
	}
}

func TestTLSCertificateResourceBounds(t *testing.T) {
	for _, tc := range []struct {
		name         string
		sans, copies int
		oversized    bool
	}{
		{"many_sans_and_presented_certificates", 300, 20, false},
		{"runtime_certificate_message_limit", 4000, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			template := &x509.Certificate{SerialNumber: big.NewInt(30), Subject: pkix.Name{CommonName: "local resource fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
			for i := 1; i < tc.sans; i++ {
				labelSize := 10
				if tc.oversized {
					labelSize = 60
				}
				template.DNSNames = append(template.DNSNames, fmt.Sprintf("%d.%s.test", i, strings.Repeat("a", labelSize)))
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			cert := tls.Certificate{PrivateKey: key}
			for i := 0; i < tc.copies; i++ {
				cert.Certificate = append(cert.Certificate, der)
			}
			// Keep the accepted fixture below Go's 256 KiB Certificate-message ceiling.
			// The oversized case verifies rejection by the actual local TLS runtime.
			if !tc.oversized && len(der)*tc.copies > 262000 {
				t.Fatal("accepted fixture exceeds runtime limit")
			}
			var hits atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			s.StartTLS()
			defer s.Close()
			target := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			c := makeClient(t, target, true, Config{LabCAPEM: ca})
			r, err := c.Do(context.Background(), parse(t, target), GET)
			if tc.oversized {
				if ErrorCode(err) != TLSHandshakeFailed || hits.Load() != 0 || r.Metadata().RequestAttempts != 0 {
					t.Fatal("oversized certificate not rejected before HTTP", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				e := r.TLSAnalysis()
				if e.Status != "verified" || !e.Truncated || e.PresentedCount != tc.copies || len(e.Presented) != 16 || e.Presented[0].SANCount != tc.sans || len(e.Presented[0].SANs) != 128 || hits.Load() != 1 {
					t.Fatal("unbounded/incomplete evidence", e.Status)
				}
			}
		})
	}
}

func TestHTTPHasNoTLSAnalysis(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, e := c.Do(context.Background(), parse(t, s.URL), GET)
	if e != nil || r.TLSAnalysis().Status != "not_applicable" {
		t.Fatal("HTTP TLS state", e)
	}
}
