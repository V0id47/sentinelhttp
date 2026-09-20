package httpclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func labCertificate(t *testing.T, name string, start, end time.Time) (tls.Certificate, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SentinelHTTP ephemeral test CA"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	leafPub, leafKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestHTTPSValidation(t *testing.T) {
	for _, tc := range []struct {
		name, certHost string
		trust          bool
		offset         time.Duration
		code           Code
	}{
		{"trusted", "localhost", true, 0, OK}, {"unknown", "localhost", false, 0, TLSUnknownAuthority}, {"mismatch", "other.test", true, 0, TLSHostnameMismatch}, {"expired", "localhost", true, -4 * time.Hour, TLSExpired}, {"future", "localhost", true, 4 * time.Hour, TLSNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().Add(tc.offset)
			cert, ca := labCertificate(t, tc.certHost, now.Add(-time.Hour), now.Add(time.Hour))
			var requests atomic.Int32
			var sni atomic.Value
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if !strings.HasPrefix(r.Host, "localhost:") {
					t.Error("wrong logical Host")
				}
				fmt.Fprint(w, "ok")
			}))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) { sni.Store(info.ServerName); return nil, nil }}
			s.StartTLS()
			defer s.Close()
			url := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
			cfg := Config{}
			if tc.trust {
				cfg.LabCAPEM = ca
			} else {
				_, cfg.LabCAPEM = labCertificate(t, "unrelated.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			}
			c := makeClient(t, url, true, cfg)
			r, e := c.Do(context.Background(), parse(t, url), GET)
			if ErrorCode(e) != tc.code {
				t.Fatalf("got %v want %s", e, tc.code)
			}
			if tc.code == OK {
				if requests.Load() != 1 || sni.Load() != "localhost" || r.Metadata().TLS == nil || !r.Metadata().TLS.Verified || r.Metadata().TLS.ServerName != "localhost" {
					t.Fatal("lost TLS identity")
				}
			} else if requests.Load() != 0 || r.Metadata().RequestAttempts != 0 {
				t.Fatal("HTTP sent after failed TLS")
			}
		})
	}
}

func TestHTTPSProxyIgnored(t *testing.T) {
	var hits atomic.Int32
	p := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer p.Close()
	t.Setenv("HTTPS_PROXY", p.URL)
	cert, ca := labCertificate(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()
	url := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
	c := makeClient(t, url, true, Config{LabCAPEM: ca})
	_, e := c.Do(context.Background(), parse(t, url), GET)
	if e != nil || hits.Load() != 0 {
		t.Fatal("HTTPS proxy used", e)
	}
}

// A server-controlled AIA URL must never turn certificate validation into an
// independent HTTP client. Supply only the leaf, deliberately omitting its issuer.
func TestExplicitRootsNeverFetchIssuer(t *testing.T) {
	var aiaHits atomic.Int32
	aia := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { aiaHits.Add(1) }))
	defer aia.Close()
	now := time.Now()
	rootPub, rootKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, rootPub, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	issuerPub, issuerKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "missing intermediate"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: root.NotBefore, NotAfter: root.NotAfter}
	issuerDER, e := x509.CreateCertificate(rand.Reader, issuer, root, issuerPub, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	issuer, e = x509.ParseCertificate(issuerDER)
	if e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(12), DNSNames: []string{"localhost"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IssuingCertificateURL: []string{aia.URL}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, issuer, pub, issuerKey)
	if e != nil {
		t.Fatal(e)
	}
	var requests atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	defer s.Close()
	url := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	c := makeClient(t, url, true, Config{LabCAPEM: ca})
	_, e = c.Do(context.Background(), parse(t, url), GET)
	if ErrorCode(e) != TLSUnknownAuthority || aiaHits.Load() != 0 || requests.Load() != 0 {
		t.Fatal("missing issuer was fetched or HTTP sent", e)
	}
}
