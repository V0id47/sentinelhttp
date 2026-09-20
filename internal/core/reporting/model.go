// Package reporting builds and renders a bounded, privacy-minimized evidence
// document. It does not perform network, filesystem or clock I/O.
package reporting

import (
	"fmt"
	"time"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/scoring"
)

const SchemaVersion = "1.0"
const Tool = "SentinelHTTP"
const ToolVersion = "0.1.0"
const MaxDocumentBytes = 8 << 20

type Input struct {
	InitialTarget network.Target
	StartedAt     time.Time
	CompletedAt   time.Time
	Config        ScanConfig
	Primary       *httpclient.Response
	Exchanges     []*httpclient.Response
	Trace         *httpclient.RedirectTrace
	CORSProbe     *httpclient.CORSProbeResult
}

type ScanConfig struct {
	AllowPrivate         bool  `json:"allow_private"`
	SameHost             bool  `json:"same_host"`
	TraceEnabled         bool  `json:"trace_enabled"`
	MaxRedirects         int   `json:"max_redirects"`
	MaxRequests          int   `json:"max_requests"`
	TimeoutMillis        int64 `json:"timeout_millis"`
	ConnectTimeoutMillis int64 `json:"connect_timeout_millis"`
	MaxResponseBytes     int64 `json:"max_response_bytes"`
	CORSProbeEnabled     bool  `json:"cors_probe_enabled"`
	TrustBundleProvided  bool  `json:"trust_bundle_provided"`
}

type Document struct {
	SchemaVersion    string                  `json:"schema_version"`
	Tool             string                  `json:"tool"`
	ToolVersion      string                  `json:"tool_version"`
	StartedAt        time.Time               `json:"started_at"`
	CompletedAt      time.Time               `json:"completed_at"`
	Target           string                  `json:"target"`
	TargetScope      string                  `json:"target_scope"`
	FinalTarget      string                  `json:"final_target"`
	PrimaryRequestID string                  `json:"primary_request_id"`
	ScanConfig       ScanConfig              `json:"scan_config"`
	Requests         []RequestSummary        `json:"requests"`
	Redirects        []RedirectSummary       `json:"redirects"`
	RedirectStop     string                  `json:"redirect_stop"`
	CORSProbe        *ProbeSummary           `json:"cors_probe"`
	Findings         []findingengine.Finding `json:"findings"`
	Score            scoring.Report          `json:"score"`
	Truncated        bool                    `json:"truncated"`
	OmittedInputs    int                     `json:"omitted_inputs"`
	OmittedFindings  int                     `json:"omitted_findings"`
	OmittedEvidence  int                     `json:"omitted_evidence"`
	SkippedInputs    int                     `json:"skipped_inputs"`
	Limitations      []string                `json:"limitations"`
}

func (d Document) String() string {
	return fmt.Sprintf("SentinelHTTP report: requests=%d findings=%d truncated=%t", len(d.Requests), len(d.Findings), d.Truncated)
}

func (d Document) GoString() string { return d.String() }

type AddressSummary struct {
	Returned   string          `json:"returned"`
	Normalized string          `json:"normalized"`
	Decision   DecisionSummary `json:"decision"`
}

type DecisionSummary struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Class   string `json:"class"`
}

type ResolutionSummary struct {
	Host          string           `json:"host"`
	Source        string           `json:"source"`
	PolicyVersion string           `json:"policy_version"`
	Chosen        string           `json:"chosen"`
	Decision      DecisionSummary  `json:"decision"`
	Addresses     []AddressSummary `json:"addresses"`
}

type PeerSummary struct {
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Verified bool   `json:"verified"`
	Decision string `json:"decision"`
}

type SANSummary struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type CertificateSummary struct {
	Subject       string       `json:"subject"`
	Issuer        string       `json:"issuer"`
	SHA256        string       `json:"sha256"`
	NotBefore     time.Time    `json:"not_before"`
	NotAfter      time.Time    `json:"not_after"`
	DaysRemaining int64        `json:"days_remaining"`
	Validity      string       `json:"validity"`
	SANs          []SANSummary `json:"sans"`
	Truncated     bool         `json:"truncated"`
}

type TLSSummary struct {
	Status             string               `json:"status"`
	Version            string               `json:"version"`
	CipherSuite        string               `json:"cipher_suite"`
	NegotiatedProtocol string               `json:"negotiated_protocol"`
	Certificates       []CertificateSummary `json:"certificates"`
	Truncated          bool                 `json:"truncated"`
}

type HeaderSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Occurrences   int    `json:"occurrences"`
	Applicability string `json:"applicability"`
	Status        string `json:"status"`
	Effective     string `json:"effective"`
	Truncated     bool   `json:"truncated"`
}

type CookieSummary struct {
	Position         int    `json:"position"`
	Name             string `json:"name"`
	Parse            string `json:"parse"`
	Acceptance       string `json:"acceptance"`
	Secure           bool   `json:"secure"`
	SecureStatus     string `json:"secure_status"`
	HTTPOnly         bool   `json:"http_only"`
	HTTPOnlyStatus   string `json:"http_only_status"`
	SameSite         string `json:"same_site"`
	Domain           string `json:"domain"`
	DomainHostOnly   bool   `json:"domain_host_only"`
	PathScope        string `json:"path_scope"`
	SessionLike      bool   `json:"session_like"`
	IdentityRepeated bool   `json:"identity_repeated"`
	Truncated        bool   `json:"truncated"`
}

type CSPSourceSummary struct {
	Kind              string `json:"kind"`
	Keyword           string `json:"keyword"`
	Scheme            string `json:"scheme"`
	Host              string `json:"host"`
	Port              string `json:"port"`
	SubdomainWildcard bool   `json:"subdomain_wildcard"`
	Redacted          bool   `json:"redacted"`
}

type CSPDirectiveSummary struct {
	Name    string             `json:"name"`
	Kind    string             `json:"kind"`
	Status  string             `json:"status"`
	Sources []CSPSourceSummary `json:"sources"`
}

type CSPPolicySummary struct {
	Disposition string                `json:"disposition"`
	FieldIndex  int                   `json:"field_index"`
	MemberIndex int                   `json:"member_index"`
	Parse       string                `json:"parse"`
	Directives  []CSPDirectiveSummary `json:"directives"`
	Truncated   bool                  `json:"truncated"`
}

type CSPSummary struct {
	Capture       string             `json:"capture"`
	Applicability string             `json:"applicability"`
	Policies      []CSPPolicySummary `json:"policies"`
	Observations  []string           `json:"observations"`
	Truncated     bool               `json:"truncated"`
}

type CORSSummary struct {
	Capture            string   `json:"capture"`
	OriginStatus       string   `json:"origin_status"`
	OriginKind         string   `json:"origin_kind"`
	OriginValue        string   `json:"origin_value"`
	CredentialsStatus  string   `json:"credentials_status"`
	CredentialsEnabled bool     `json:"credentials_enabled"`
	VaryStatus         string   `json:"vary_status"`
	VaryOrigin         bool     `json:"vary_origin"`
	CacheStatus        string   `json:"cache_status"`
	CacheFreshShared   bool     `json:"cache_fresh_shared"`
	Observations       []string `json:"observations"`
	Truncated          bool     `json:"truncated"`
}

type RequestSummary struct {
	ID                   string            `json:"id"`
	Target               string            `json:"target"`
	Method               string            `json:"method"`
	StatusCode           int               `json:"status_code"`
	Result               string            `json:"result"`
	Protocol             string            `json:"protocol"`
	DurationMillis       int64             `json:"duration_millis"`
	Resolution           ResolutionSummary `json:"resolution"`
	Peer                 PeerSummary       `json:"peer"`
	TLS                  TLSSummary        `json:"tls"`
	Headers              []HeaderSummary   `json:"headers"`
	Cookies              []CookieSummary   `json:"cookies"`
	CookieCapture        string            `json:"cookie_capture"`
	CookieFieldCount     int               `json:"cookie_field_count"`
	CookieAnalyzedFields int               `json:"cookie_analyzed_fields"`
	CookieOmittedFields  int               `json:"cookie_omitted_fields"`
	CookieTruncated      bool              `json:"cookie_truncated"`
	CSP                  CSPSummary        `json:"csp"`
	CORS                 CORSSummary       `json:"cors"`
}

type RedirectSummary struct {
	HopIndex       int    `json:"hop_index"`
	ResponseID     string `json:"response_id"`
	Target         string `json:"target"`
	StatusCode     int    `json:"status_code"`
	LocationStatus string `json:"location_status"`
	NextTarget     string `json:"next_target"`
}

type ProbeAttemptSummary struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	Origin     string      `json:"origin"`
	State      string      `json:"state"`
	Code       string      `json:"code"`
	StatusCode int         `json:"status_code"`
	Target     string      `json:"target"`
	CORS       CORSSummary `json:"cors"`
}

type ProbeSummary struct {
	Attempts []ProbeAttemptSummary `json:"attempts"`
}
