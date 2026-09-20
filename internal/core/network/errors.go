package network

import (
	"context"
	"errors"
	"net"
)

// Code is stable machine-readable output. Error strings never contain input or causes.
type Code string

const (
	TargetInvalid     Code = "target_invalid"
	SchemeUnsupported Code = "scheme_unsupported"
	UserinfoRejected  Code = "target_userinfo_rejected"
	ConfigInvalid     Code = "config_invalid"
	DNSFailed         Code = "dns_failed"
	DNSNotFound       Code = "dns_not_found"
	DNSTemporary      Code = "dns_temporary"
	DNSTimeout        Code = "dns_timeout"
	DNSNoAddresses    Code = "dns_no_addresses"
	DNSLimit          Code = "dns_address_limit"
	MixedResolution   Code = "mixed_scope_resolution"
	HostBlocked       Code = "scope_host_blocked"
	HostChanged       Code = "scope_host_changed"
	Cancelled         Code = "context_cancelled"
	DialTimeout       Code = "dial_timeout"
	DialFailed        Code = "dial_failed"
	PeerMismatch      Code = "peer_mismatch"
	ApprovalInvalid   Code = "approval_invalid"
	ApprovalUsed      Code = "approval_used"
	ApprovalExpired   Code = "approval_expired"
	Allowed           Code = "allowed"
)

// Fault deliberately has no Unwrap: arbitrary resolver/dialer error text may carry secrets.
// Cause categories are preserved through Code. Raw causes are never retained.
type Fault struct{ code Code }

func (e *Fault) Error() string    { return string(e.code) }
func (e *Fault) Code() Code       { return e.code }
func (e *Fault) GoString() string { return e.Error() }
func fail(c Code) error           { return &Fault{code: c} }
func ErrorCode(err error) Code {
	var f *Fault
	if errors.As(err, &f) {
		return f.code
	}
	if err == nil {
		return Allowed
	}
	return "internal_error"
}

func operationError(ctx context.Context, err error, dns bool) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return fail(Cancelled)
	}
	timeout := errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		timeout = true
	}
	if timeout {
		if dns {
			return fail(DNSTimeout)
		}
		return fail(DialTimeout)
	}
	if dns {
		var de *net.DNSError
		if errors.As(err, &de) {
			if de.IsNotFound {
				return fail(DNSNotFound)
			}
			if de.IsTemporary {
				return fail(DNSTemporary)
			}
		}
		return fail(DNSFailed)
	}
	return fail(DialFailed)
}
