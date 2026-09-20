package network

import (
	"net/netip"
	"time"
)

type Class string

const (
	Public         Class = "public"
	Private        Class = "private"
	Loopback       Class = "loopback"
	LinkLocal      Class = "link_local"
	Multicast      Class = "multicast"
	Unspecified    Class = "unspecified"
	Documentation  Class = "documentation"
	Reserved       Class = "reserved"
	OtherNonGlobal Class = "other_non_global"
	Metadata       Class = "cloud_metadata"
	Invalid        Class = "invalid"
)
const PolicyVersion = "scope-v1"

// Policy is copied on construction. Zero timeout means a bounded three-second default.
type Policy struct {
	AllowPrivate, SameHost     bool
	DNSTimeout, ConnectTimeout time.Duration
}
type Decision struct {
	Allowed bool
	Reason  Code
	Class   Class
}

func (p Policy) Evaluate(a netip.Addr) Decision {
	c := Classify(a)
	ok := c == Public || p.AllowPrivate && (c == Private || c == Loopback)
	reason := Code("scope_" + string(c) + "_blocked")
	if ok {
		reason = Allowed
	}
	return Decision{ok, reason, c}
}

// Extra ranges supplement netip predicates. This intentionally denies special
// assignments even where IANA permits global routing; see docs/network-safety.md.
// Array values are package-private and never modified after initialization.
var special = [...]struct {
	prefix netip.Prefix
	class  Class
}{
	{netip.MustParsePrefix("0.0.0.0/8"), Reserved},
	{netip.MustParsePrefix("100.64.0.0/10"), OtherNonGlobal},
	{netip.MustParsePrefix("192.0.0.0/24"), Reserved},
	{netip.MustParsePrefix("192.0.2.0/24"), Documentation},
	{netip.MustParsePrefix("192.31.196.0/24"), Reserved},
	{netip.MustParsePrefix("192.52.193.0/24"), Reserved},
	{netip.MustParsePrefix("192.88.99.0/24"), OtherNonGlobal},
	{netip.MustParsePrefix("192.175.48.0/24"), Reserved},
	{netip.MustParsePrefix("198.18.0.0/15"), OtherNonGlobal},
	{netip.MustParsePrefix("198.51.100.0/24"), Documentation},
	{netip.MustParsePrefix("203.0.113.0/24"), Documentation},
	{netip.MustParsePrefix("240.0.0.0/4"), Reserved},
	{netip.MustParsePrefix("2001:db8::/32"), Documentation},
	{netip.MustParsePrefix("3fff::/20"), Documentation},
	{netip.MustParsePrefix("2001::/23"), OtherNonGlobal},
	{netip.MustParsePrefix("2002::/16"), OtherNonGlobal},
	{netip.MustParsePrefix("2620:4f:8000::/48"), Reserved},
}
var publicV6 = netip.MustParsePrefix("2000::/3")
var metadataV6 = netip.MustParseAddr("fd00:ec2::254")

func Classify(a netip.Addr) Class {
	if !a.IsValid() || a.Zone() != "" {
		return Invalid
	}
	a = a.Unmap()
	if a == metadataV6 {
		return Metadata
	}
	if a.IsUnspecified() {
		return Unspecified
	}
	if a.IsLoopback() {
		return Loopback
	}
	if a.IsPrivate() {
		return Private
	}
	if a.IsLinkLocalUnicast() {
		return LinkLocal
	}
	if a.IsMulticast() {
		return Multicast
	}
	for _, r := range special {
		if r.prefix.Contains(a) {
			return r.class
		}
	}
	if !a.IsGlobalUnicast() || a.Is6() && !publicV6.Contains(a) {
		return OtherNonGlobal
	}
	return Public
}
