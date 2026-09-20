// Package headeranalysis evaluates bounded HTTP response-header evidence.
// It is deterministic and performs no I/O.
package headeranalysis

import "fmt"

type CaptureStatus string

const (
	CaptureUnavailable CaptureStatus = "capture_unavailable"
	CaptureComplete    CaptureStatus = "capture_complete"
)

type Representation string

const (
	RepresentationUnknown   Representation = "unknown"
	RepresentationHTML      Representation = "html"
	RepresentationJSON      Representation = "json"
	RepresentationOther     Representation = "other"
	RepresentationRedirect  Representation = "redirect"
	RepresentationNoContent Representation = "no_content"
)

type ContextStatus string

const (
	ContextMissing   ContextStatus = "missing"
	ContextValid     ContextStatus = "valid"
	ContextInvalid   ContextStatus = "invalid"
	ContextAmbiguous ContextStatus = "ambiguous"
	ContextTruncated ContextStatus = "truncated"
)

type Applicability string

const (
	Applicable           Applicability = "applicable"
	NotApplicable        Applicability = "not_applicable"
	ApplicabilityUnknown Applicability = "unknown"
)

type ResultStatus string

const (
	StatusAbsent       ResultStatus = "absent"
	StatusValid        ResultStatus = "valid"
	StatusInvalid      ResultStatus = "invalid"
	StatusAmbiguous    ResultStatus = "ambiguous"
	StatusIgnored      ResultStatus = "ignored"
	StatusObserved     ResultStatus = "observed"
	StatusDeferred     ResultStatus = "deferred"
	StatusTruncated    ResultStatus = "truncated"
	StatusUnrecognized ResultStatus = "unrecognized"
)

type HeaderID string

const (
	ContentSecurityPolicy     HeaderID = "content_security_policy"
	StrictTransportSecurity   HeaderID = "strict_transport_security"
	XContentTypeOptions       HeaderID = "x_content_type_options"
	ReferrerPolicy            HeaderID = "referrer_policy"
	PermissionsPolicy         HeaderID = "permissions_policy"
	XFrameOptions             HeaderID = "x_frame_options"
	CrossOriginOpenerPolicy   HeaderID = "cross_origin_opener_policy"
	CrossOriginResourcePolicy HeaderID = "cross_origin_resource_policy"
	CrossOriginEmbedderPolicy HeaderID = "cross_origin_embedder_policy"
	Server                    HeaderID = "server"
)

var allHeaderIDs = []HeaderID{
	ContentSecurityPolicy, StrictTransportSecurity, XContentTypeOptions,
	ReferrerPolicy, PermissionsPolicy, XFrameOptions, CrossOriginOpenerPolicy,
	CrossOriginResourcePolicy, CrossOriginEmbedderPolicy, Server,
}

var names = map[HeaderID]string{
	ContentSecurityPolicy:     "Content-Security-Policy",
	StrictTransportSecurity:   "Strict-Transport-Security",
	XContentTypeOptions:       "X-Content-Type-Options",
	ReferrerPolicy:            "Referrer-Policy",
	PermissionsPolicy:         "Permissions-Policy",
	XFrameOptions:             "X-Frame-Options",
	CrossOriginOpenerPolicy:   "Cross-Origin-Opener-Policy",
	CrossOriginResourcePolicy: "Cross-Origin-Resource-Policy",
	CrossOriginEmbedderPolicy: "Cross-Origin-Embedder-Policy",
	Server:                    "Server",
}

type Input struct {
	Captured    bool
	Scheme      string
	TLSVerified bool
	HostIsIP    bool
	StatusCode  int
	Headers     map[string][]string
}

type ResponseContext struct {
	Scheme            string
	TLSVerified       bool
	HostIsIP          bool
	StatusCode        int
	MediaType         string
	ContentTypeStatus ContextStatus
	Representation    Representation
}

type Result struct {
	ID            HeaderID
	Name          string
	Occurrences   int
	Applicability Applicability
	Status        ResultStatus
	Effective     string
	Tokens        []string
	Directives    []Directive
	Truncated     bool
}

type Directive struct {
	Name           string
	Status         ResultStatus
	Items          []DirectiveItem
	Repeated       bool
	IgnoredItems   int
	ReportToStatus ResultStatus
}

type DirectiveItemKind string

const (
	DirectiveToken  DirectiveItemKind = "token"
	DirectiveString DirectiveItemKind = "string"
)

type DirectiveItem struct {
	Kind  DirectiveItemKind
	Value string
}

type Report struct {
	Capture CaptureStatus
	Context ResponseContext
	Results []Result
	values  map[HeaderID][]string
}

func (r Report) String() string {
	return fmt.Sprintf("header analysis: capture=%s results=%d", r.Capture, len(r.Results))
}

func (r Report) GoString() string { return r.String() }

func (r Report) Result(id HeaderID) (Result, bool) {
	for _, result := range r.Results {
		if result.ID == id {
			result.Tokens = append([]string(nil), result.Tokens...)
			result.Directives = cloneDirectives(result.Directives)
			return result, true
		}
	}
	return Result{}, false
}

func (r Report) Values(id HeaderID) []string {
	return append([]string(nil), r.values[id]...)
}

func (r Report) Clone() Report {
	r.Results = append([]Result(nil), r.Results...)
	for i := range r.Results {
		r.Results[i].Tokens = append([]string(nil), r.Results[i].Tokens...)
		r.Results[i].Directives = cloneDirectives(r.Results[i].Directives)
	}
	if r.values != nil {
		values := make(map[HeaderID][]string, len(r.values))
		for id, v := range r.values {
			values[id] = append([]string(nil), v...)
		}
		r.values = values
	}
	return r
}

func cloneDirectives(in []Directive) []Directive {
	out := append([]Directive(nil), in...)
	for i := range out {
		out[i].Items = append([]DirectiveItem(nil), in[i].Items...)
	}
	return out
}
