package httpclient

import (
	"crypto/x509"
	"time"
)

const UserAgent = "SentinelHTTP/0.1.0 Security Assessment"

type Method string

const (
	GET     Method = "GET"
	HEAD    Method = "HEAD"
	OPTIONS Method = "OPTIONS"
)

// Config is copied; CA bytes are parsed once into a private trust pool. A supplied
// lab CA replaces system roots for this client, rather than weakening verification.
type Config struct {
	TLSHandshakeTimeout, ResponseHeaderTimeout, TotalTimeout time.Duration
	MaxResponseBytes, MaxResponseHeaderBytes                 int64
	LabCAPEM                                                 []byte
}

func normalize(c Config) (Config, *x509.CertPool, error) {
	if c.TLSHandshakeTimeout == 0 {
		c.TLSHandshakeTimeout = 5 * time.Second
	}
	if c.ResponseHeaderTimeout == 0 {
		c.ResponseHeaderTimeout = 10 * time.Second
	}
	if c.TotalTimeout == 0 {
		c.TotalTimeout = 15 * time.Second
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 2 << 20
	}
	if c.MaxResponseHeaderBytes == 0 {
		c.MaxResponseHeaderBytes = 64 << 10
	}
	if c.TLSHandshakeTimeout < 0 || c.TLSHandshakeTimeout > 10*time.Second || c.ResponseHeaderTimeout < 0 || c.ResponseHeaderTimeout > 30*time.Second || c.TotalTimeout < 0 || c.TotalTimeout > 60*time.Second || c.MaxResponseBytes < 1 || c.MaxResponseBytes > 8<<20 || c.MaxResponseHeaderBytes < 128 || c.MaxResponseHeaderBytes > 128<<10 || len(c.LabCAPEM) > 1<<20 {
		return Config{}, nil, fault(ConfigInvalid)
	}
	var roots *x509.CertPool
	if len(c.LabCAPEM) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(c.LabCAPEM) {
			return Config{}, nil, fault(CAInvalid)
		}
	}
	c.LabCAPEM = nil
	return c, roots, nil
}
