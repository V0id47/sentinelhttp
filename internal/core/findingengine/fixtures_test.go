package findingengine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
)

func fixtureTarget(t *testing.T, raw string) network.Target {
	t.Helper()
	target, err := network.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func fixtureClient(t *testing.T, raw string, ca []byte) *httpclient.Client {
	t.Helper()
	boundary, err := network.NewBoundary(fixtureTarget(t, raw), network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{LabCAPEM: ca, TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func tlsFixture(t *testing.T, h http.Handler, notAfter time.Time) (string, *httpclient.Client) {
	t.Helper()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SentinelHTTP test CA"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Subject: pkix.Name{CommonName: "SECRET-certificate-subject"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	url := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	return url, fixtureClient(t, url, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func httpFixture(t *testing.T, h http.Handler) (string, *httpclient.Client) {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server.URL, fixtureClient(t, server.URL, nil)
}

func hasRule(report Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}
