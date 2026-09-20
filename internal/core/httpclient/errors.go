package httpclient

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

type Code string

const (
	OK                  Code = "ok"
	ConfigInvalid       Code = "http_config_invalid"
	CAInvalid           Code = "lab_ca_invalid"
	CABundleRequired    Code = "tls_ca_bundle_required"
	MethodRejected      Code = "http_method_rejected"
	BuildFailed         Code = "http_build_failed"
	Cancelled           Code = "context_cancelled"
	Timeout             Code = "http_timeout"
	HeaderTimeout       Code = "http_header_timeout"
	HeaderLimit         Code = "http_header_limit"
	ProtocolError       Code = "http_protocol_error"
	BodyReadFailed      Code = "http_body_incomplete"
	TLSHandshakeFailed  Code = "tls_handshake_failed"
	TLSHandshakeTimeout Code = "tls_handshake_timeout"
	TLSUnknownAuthority Code = "tls_unknown_authority"
	TLSHostnameMismatch Code = "tls_hostname_mismatch"
	TLSExpired          Code = "tls_certificate_expired"
	TLSNotYetValid      Code = "tls_certificate_not_yet_valid"
	TransportInvariant  Code = "http_transport_invariant"
)

type Fault struct{ code Code }

func (e *Fault) Error() string    { return string(e.code) }
func (e *Fault) GoString() string { return e.Error() }
func (e *Fault) Code() Code       { return e.code }
func fault(c Code) error          { return &Fault{c} }
func ErrorCode(e error) Code {
	if e == nil {
		return OK
	}
	var f *Fault
	if errors.As(e, &f) {
		return f.code
	}
	return ProtocolError
}
func timedOut(e error) bool {
	var n net.Error
	return errors.Is(e, context.DeadlineExceeded) || errors.As(e, &n) && n.Timeout()
}
func tlsError(ctx context.Context, e error) Code {
	if errors.Is(ctx.Err(), context.Canceled) {
		return Cancelled
	}
	if ctx.Err() != nil || timedOut(e) {
		return TLSHandshakeTimeout
	}
	var h x509.HostnameError
	if errors.As(e, &h) {
		return TLSHostnameMismatch
	}
	var a x509.UnknownAuthorityError
	if errors.As(e, &a) {
		return TLSUnknownAuthority
	}
	var c x509.CertificateInvalidError
	if errors.As(e, &c) && c.Reason == x509.Expired {
		if c.Cert != nil && time.Now().Before(c.Cert.NotBefore) {
			return TLSNotYetValid
		}
		return TLSExpired
	}
	return TLSHandshakeFailed
}
func httpError(ctx context.Context, e error, body bool) Code {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(e, context.Canceled) {
		return Cancelled
	}
	if ctx.Err() != nil {
		return Timeout
	}
	if timedOut(e) {
		if body {
			return Timeout
		}
		return HeaderTimeout
	}
	var u *url.Error
	if errors.As(e, &u) {
		e = u.Err
	}
	// Go does not expose a typed response-header-limit error. Narrow runtime-specific
	// prefix match; never surface this raw string. Covered by a raw TCP regression.
	for cause := e; cause != nil; cause = errors.Unwrap(cause) {
		if strings.HasPrefix(cause.Error(), "net/http: server response headers exceeded") {
			return HeaderLimit
		}
	}
	if body {
		return BodyReadFailed
	}
	return ProtocolError
}
