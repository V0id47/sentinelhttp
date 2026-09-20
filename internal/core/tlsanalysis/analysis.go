// Package tlsanalysis extracts bounded evidence without I/O or trust decisions.
package tlsanalysis

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxCertificates = 16
	maxChains       = 4
	maxSANs         = 128
	maxTextBytes    = 1024
)

type SAN struct{ Kind, Value string }
type Certificate struct {
	Subject, Issuer, SHA256 string
	NotBefore, NotAfter     time.Time
	DaysRemaining           int64
	Validity                string
	SANs                    []SAN
	SANCount                int
	Truncated               bool
}

// Status describes authentication, not the security of the remote service.
// Certificate-controlled text is untrusted even after display normalization.
type Evidence struct {
	Status                                           string
	ObservedAt                                       time.Time
	Version, CipherSuite                             uint16
	VersionName, CipherSuiteName, NegotiatedProtocol string
	Presented                                        []Certificate
	VerifiedChains                                   [][]Certificate
	PresentedCount, VerifiedChainCount               int
	Truncated                                        bool
	RevocationChecked                                bool // Always false: no OCSP, CRL or AIA fetching.
}

// Capture only labels a completed, verified handshake as verified. On failure,
// certificates exposed by Go are observations and never authenticated evidence.
// The caller supplies the scan instant for deterministic validity calculations.
func Capture(state tls.ConnectionState, err error, at time.Time) Evidence {
	e := Evidence{Status: "unavailable", ObservedAt: at.UTC()}
	certs := state.PeerCertificates
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) && verification != nil {
		certs = verification.UnverifiedCertificates
	}
	if len(certs) > 0 {
		e.Status = "unverified"
	}
	if err == nil && state.HandshakeComplete && len(state.VerifiedChains) > 0 {
		e.Status = "verified"
		e.VerifiedChainCount = len(state.VerifiedChains)
		for i, chain := range state.VerifiedChains {
			if i == maxChains {
				e.Truncated = true
				break
			}
			summaries, truncated := summarizeChain(chain, at)
			e.VerifiedChains = append(e.VerifiedChains, summaries)
			e.Truncated = e.Truncated || truncated
		}
	}
	// Failed handshakes do not imply an established negotiated session.
	if err == nil && state.HandshakeComplete {
		e.Version = state.Version
		e.CipherSuite = state.CipherSuite
		e.VersionName = tls.VersionName(state.Version)
		e.CipherSuiteName = tls.CipherSuiteName(state.CipherSuite)
		var cut bool
		e.NegotiatedProtocol, cut = displayText(state.NegotiatedProtocol)
		e.Truncated = e.Truncated || cut
	}
	e.PresentedCount = len(certs)
	var cut bool
	e.Presented, cut = summarizeChain(certs, at)
	e.Truncated = e.Truncated || cut
	return e
}

func summarizeChain(chain []*x509.Certificate, at time.Time) ([]Certificate, bool) {
	var out []Certificate
	cut := len(chain) > maxCertificates
	for i, c := range chain {
		if i == maxCertificates {
			break
		}
		if c == nil {
			cut = true
			continue
		}
		s := Certificate{NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), Validity: "valid"}
		sum := sha256.Sum256(c.Raw)
		s.SHA256 = hex.EncodeToString(sum[:])
		var clipped bool
		s.Subject, clipped = displayText(c.Subject.String())
		s.Truncated = clipped
		s.Issuer, clipped = displayText(c.Issuer.String())
		s.Truncated = s.Truncated || clipped
		seconds := c.NotAfter.Unix() - at.Unix()
		if c.NotAfter.Nanosecond() < at.Nanosecond() {
			seconds--
		}
		s.DaysRemaining = seconds / 86400
		if seconds < 0 && seconds%86400 != 0 {
			s.DaysRemaining--
		}
		switch {
		case at.Before(c.NotBefore):
			s.Validity = "not_yet_valid"
		case at.After(c.NotAfter):
			s.Validity = "expired"
		case !c.NotAfter.After(at.Add(30 * 24 * time.Hour)):
			s.Validity = "expiring_soon"
		}
		s.SANCount = len(c.DNSNames) + len(c.IPAddresses) + len(c.EmailAddresses) + len(c.URIs)
		add := func(kind, value string) {
			v, short := displayText(value)
			s.SANs = append(s.SANs, SAN{kind, v})
			s.Truncated = s.Truncated || short
		}
		for _, v := range c.DNSNames {
			if len(s.SANs) == maxSANs {
				break
			}
			add("dns", v)
		}
		for _, v := range c.IPAddresses {
			if len(s.SANs) == maxSANs {
				break
			}
			add("ip", v.String())
		}
		for _, v := range c.EmailAddresses {
			if len(s.SANs) == maxSANs {
				break
			}
			add("email", v)
		}
		for _, v := range c.URIs {
			if len(s.SANs) == maxSANs {
				break
			}
			if v == nil {
				s.Truncated = true
				continue
			}
			add("uri", v.String())
		}
		s.Truncated = s.Truncated || s.SANCount > len(s.SANs)
		out = append(out, s)
		cut = cut || s.Truncated
	}
	return out, cut
}

// Strip control/format characters, preserve valid UTF-8, stop allocating at cap.
// This is display normalization, not HTML escaping or secret redaction.
func displayText(value string) (string, bool) {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = '\uFFFD'
		}
		if b.Len()+utf8.RuneLen(r) > maxTextBytes {
			return b.String(), true
		}
		b.WriteRune(r)
	}
	return b.String(), false
}

func (e Evidence) Clone() Evidence {
	cloneChain := func(in []Certificate) []Certificate {
		out := append([]Certificate(nil), in...)
		for i := range out {
			out[i].SANs = append([]SAN(nil), in[i].SANs...)
		}
		return out
	}
	e.Presented = cloneChain(e.Presented)
	chains := make([][]Certificate, len(e.VerifiedChains))
	for i := range chains {
		chains[i] = cloneChain(e.VerifiedChains[i])
	}
	e.VerifiedChains = chains
	return e
}
