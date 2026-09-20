package reporting

import (
	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
)

// Probe failure codes are fixed machine codes, never target-controlled text.
func validProbeFailureCode(code string) bool {
	switch httpclient.Code(code) {
	case httpclient.ConfigInvalid, httpclient.CAInvalid, httpclient.CABundleRequired,
		httpclient.MethodRejected, httpclient.BuildFailed, httpclient.Cancelled,
		httpclient.Timeout, httpclient.HeaderTimeout, httpclient.HeaderLimit,
		httpclient.ProtocolError, httpclient.BodyReadFailed, httpclient.TLSHandshakeFailed,
		httpclient.TLSHandshakeTimeout, httpclient.TLSUnknownAuthority,
		httpclient.TLSHostnameMismatch, httpclient.TLSExpired, httpclient.TLSNotYetValid,
		httpclient.TransportInvariant:
		return true
	}
	switch network.Code(code) {
	case network.TargetInvalid, network.SchemeUnsupported, network.UserinfoRejected,
		network.ConfigInvalid, network.DNSFailed, network.DNSNotFound,
		network.DNSTemporary, network.DNSTimeout, network.DNSNoAddresses,
		network.DNSLimit, network.MixedResolution, network.HostBlocked,
		network.HostChanged, network.DialTimeout, network.DialFailed,
		network.PeerMismatch, network.ApprovalInvalid, network.ApprovalUsed,
		network.ApprovalExpired:
		return true
	}
	for _, class := range [...]network.Class{network.Public, network.Private, network.Loopback,
		network.LinkLocal, network.Multicast, network.Unspecified, network.Documentation,
		network.Reserved, network.OtherNonGlobal, network.Metadata, network.Invalid} {
		if code == "scope_"+string(class)+"_blocked" {
			return true
		}
	}
	return false
}
