// Package network owns target validation, resolution approval and outbound TCP.
// Future protocol clients must obtain single-use approvals from this boundary.
package network

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const maxAddresses = 64
const approvalLifetime = 10 * time.Second

// Dependencies are deliberately unexported. Production callers cannot install
// a resolver/dialer that bypasses policy. Tests in this package supply fakes.
type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Boundary is configured once and safe for concurrent use. Do not copy it.
type Boundary struct {
	initialHost string
	policy      Policy
	resolver    resolver
	dialer      dialer
	now         func() time.Time
	valid       bool
}

func NewBoundary(initial Target, p Policy) (*Boundary, error) {
	if !initial.valid {
		return nil, fail(TargetInvalid)
	}
	if p.DNSTimeout == 0 {
		p.DNSTimeout = 3 * time.Second
	}
	if p.ConnectTimeout == 0 {
		p.ConnectTimeout = 3 * time.Second
	}
	if p.DNSTimeout < 0 || p.DNSTimeout > 10*time.Second || p.ConnectTimeout < 0 || p.ConnectTimeout > 10*time.Second {
		return nil, fail(ConfigInvalid)
	}
	if p.AllowPrivate {
		p.SameHost = true
	}
	return &Boundary{initialHost: initial.host, policy: p, resolver: net.DefaultResolver, dialer: &net.Dialer{}, now: time.Now, valid: true}, nil
}

type AddressRecord struct {
	Returned, Normalized netip.Addr
	ZoneRejected         bool
	Decision             Decision
}
type ResolutionRecord struct {
	Host                   string
	Source                 string
	PolicyVersion          string
	StartedAt, CompletedAt time.Time
	Addresses              []AddressRecord
	Chosen                 netip.AddrPort
	Decision               Decision
}
type PeerRecord struct {
	Expected, Observed netip.AddrPort
	Verified           bool
	Decision           Code
}

// A copied ApprovedEndpoint shares consumption state. No public fields,
// deserializer or constructor can create a usable capability.
type ApprovedEndpoint struct{ state *approval }
type approval struct {
	owner   *Boundary
	target  Target
	address netip.AddrPort
	expires time.Time
	ctx     context.Context
	used    atomic.Bool
}

func (e *ApprovedEndpoint) Target() Target {
	if e == nil || e.state == nil {
		return Target{}
	}
	return e.state.target
}
func (e *ApprovedEndpoint) Address() netip.AddrPort {
	if e == nil || e.state == nil {
		return netip.AddrPort{}
	}
	return e.state.address
}
func (e *ApprovedEndpoint) String() string   { return e.Target().SafeURL() }
func (e *ApprovedEndpoint) GoString() string { return e.String() }

// Approve resolves afresh for every operation (or classifies a literal without
// DNS). It never opens a target socket. Returned evidence is not approval state.
func (b *Boundary) Approve(ctx context.Context, t Target) (*ApprovedEndpoint, ResolutionRecord, error) {
	r := ResolutionRecord{Host: t.host, PolicyVersion: PolicyVersion}
	deny := func(c Code) (*ApprovedEndpoint, ResolutionRecord, error) {
		r.Decision = Decision{Reason: c}
		if b != nil && b.now != nil {
			r.CompletedAt = b.now().UTC()
		}
		return nil, r, fail(c)
	}
	if b == nil || !b.valid || ctx == nil || !t.valid {
		return deny(TargetInvalid)
	}
	r.StartedAt = b.now().UTC()
	if err := ctx.Err(); err != nil {
		return deny(ErrorCode(operationError(ctx, err, true)))
	}
	if b.policy.SameHost && t.host != b.initialHost {
		return deny(HostChanged)
	}
	if metadataHost(t.host) {
		return deny(HostBlocked)
	}
	resolveCtx, cancel := context.WithTimeout(ctx, b.policy.DNSTimeout)
	defer cancel()
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(t.host); err == nil {
		r.Source = "literal"
		addresses = []netip.Addr{literal}
	} else {
		r.Source = "system_resolver"
		var err error
		addresses, err = b.resolver.LookupNetIP(resolveCtx, "ip", t.host)
		if err != nil {
			return deny(ErrorCode(operationError(resolveCtx, err, true)))
		}
	}
	if err := resolveCtx.Err(); err != nil {
		return deny(ErrorCode(operationError(resolveCtx, err, true)))
	}
	if len(addresses) == 0 {
		return deny(DNSNoAddresses)
	}
	if len(addresses) > maxAddresses {
		return deny(DNSLimit)
	}
	allowed, blocked := 0, 0
	var chosen netip.Addr
	var blockedDecision Decision
	for _, a := range addresses {
		d := b.policy.Evaluate(a)
		normal := a.Unmap()
		zone := a.Zone() != ""
		r.Addresses = append(r.Addresses, AddressRecord{Returned: a.WithZone(""), Normalized: normal.WithZone(""), ZoneRejected: zone, Decision: d})
		if !d.Allowed {
			blocked++
			if blocked == 1 {
				blockedDecision = d
			}
			continue
		}
		allowed++
		if !chosen.IsValid() || normal.Less(chosen) {
			chosen = normal
		}
	}
	if blocked > 0 {
		if allowed > 0 {
			return deny(MixedResolution)
		}
		_, r, e := deny(blockedDecision.Reason)
		r.Decision.Class = blockedDecision.Class
		return nil, r, e
	}
	r.Chosen = netip.AddrPortFrom(chosen, t.port)
	r.Decision = Decision{Allowed: true, Reason: Allowed, Class: Classify(chosen)}
	r.CompletedAt = b.now().UTC()
	ep := &ApprovedEndpoint{state: &approval{owner: b, target: t, address: r.Chosen, expires: b.now().Add(approvalLifetime), ctx: ctx}}
	return ep, r, nil
}

func metadataHost(h string) bool {
	for _, name := range []string{"metadata.google.internal", "metadata.goog", "instance-data.ec2.internal"} {
		if h == name || strings.HasSuffix(h, "."+name) {
			return true
		}
	}
	return false
}

// Dial consumes the approval even if connection fails. No fallback, retry or
// hostname lookup occurs here. Caller owns successful connections and must close
// them. The boundary closes every returned connection on any failure.
// Context cancellation governs establishing the connection, not its future I/O.
func (b *Boundary) Dial(ctx context.Context, ep *ApprovedEndpoint) (net.Conn, PeerRecord, error) {
	r := PeerRecord{}
	reject := func(c Code) (net.Conn, PeerRecord, error) { r.Decision = c; return nil, r, fail(c) }
	if b == nil || !b.valid || ctx == nil || ep == nil || ep.state == nil || ep.state.owner != b {
		return reject(ApprovalInvalid)
	}
	a := ep.state
	r.Expected = a.address
	if !a.used.CompareAndSwap(false, true) {
		return reject(ApprovalUsed)
	}
	if !b.now().Before(a.expires) {
		return reject(ApprovalExpired)
	}
	if err := a.ctx.Err(); err != nil {
		return reject(ErrorCode(operationError(a.ctx, err, false)))
	}
	if err := ctx.Err(); err != nil {
		return reject(ErrorCode(operationError(ctx, err, false)))
	}
	dialCtx, cancel := context.WithTimeout(ctx, b.policy.ConnectTimeout)
	defer cancel()
	if deadline, ok := a.ctx.Deadline(); ok {
		var c context.CancelFunc
		dialCtx, c = context.WithDeadline(dialCtx, deadline)
		defer c()
	}
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	conn, err := b.dialer.DialContext(dialCtx, "tcp", a.address.String())
	closeReject := func(code Code) (net.Conn, PeerRecord, error) {
		if conn != nil {
			_ = conn.Close()
		}
		return reject(code)
	}
	if e := a.ctx.Err(); e != nil {
		return closeReject(ErrorCode(operationError(a.ctx, e, false)))
	}
	if e := dialCtx.Err(); e != nil {
		return closeReject(ErrorCode(operationError(dialCtx, e, false)))
	}
	if err != nil {
		return closeReject(ErrorCode(operationError(dialCtx, err, false)))
	}
	if conn == nil {
		return reject(DialFailed)
	}
	peer, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || peer == nil || peer.Zone != "" || peer.Port < 1 || peer.Port > 65535 {
		return closeReject(PeerMismatch)
	}
	ip, ok := netip.AddrFromSlice(peer.IP)
	if !ok {
		return closeReject(PeerMismatch)
	}
	r.Observed = netip.AddrPortFrom(ip.Unmap(), uint16(peer.Port))
	if r.Observed != a.address {
		return closeReject(PeerMismatch)
	}
	r.Verified = true
	r.Decision = Allowed
	return conn, r, nil
}
