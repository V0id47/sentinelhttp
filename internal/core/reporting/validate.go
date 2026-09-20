package reporting

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/scoring"
)

var ErrReportMalformed = errors.New("report_json_malformed")
var ErrReportUnsupported = errors.New("report_version_unsupported")
var ErrReportInvalid = errors.New("report_document_invalid")

// Parse is the ingress for untrusted report files. Decoder errors are mapped
// to safe sentinels so an offending value is never reflected in an error.
func Parse(data []byte) (Document, error) {
	if err := preflightJSON(data); err != nil {
		return Document{}, err
	}
	var doc Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, ErrReportMalformed
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Document{}, ErrReportMalformed
	}
	if err := Validate(doc); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// Validate checks structural safety and internal consistency. It does not
// authenticate a report or infer that the recorded observations are true.
func Validate(doc Document) error {
	if doc.SchemaVersion != SchemaVersion || doc.Tool != Tool || doc.ToolVersion != ToolVersion {
		return ErrReportUnsupported
	}
	if !validUTCTime(doc.StartedAt) || !validUTCTime(doc.CompletedAt) || doc.CompletedAt.Before(doc.StartedAt) {
		return ErrReportInvalid
	}
	if !safeReportOrigin(doc.Target) || doc.TargetScope != "root" && doc.TargetScope != "redacted" || doc.FinalTarget != "" && !safeReportOrigin(doc.FinalTarget) || !validTexts(64, doc.PrimaryRequestID, doc.RedirectStop) || !validRedirectStop(doc.RedirectStop) {
		return ErrReportInvalid
	}
	if doc.ScanConfig.MaxRedirects < 0 || doc.ScanConfig.MaxRedirects > 20 || doc.ScanConfig.MaxRequests < 0 || doc.ScanConfig.MaxRequests > 24 || doc.ScanConfig.TimeoutMillis < 0 || doc.ScanConfig.ConnectTimeoutMillis < 0 || doc.ScanConfig.ConnectTimeoutMillis > 10000 || doc.ScanConfig.MaxResponseBytes < 0 || !validBudgetConfig(doc.ScanConfig) {
		return ErrReportInvalid
	}
	if doc.ScanConfig.CORSProbeEnabled != (doc.CORSProbe != nil) {
		return ErrReportInvalid
	}
	if len(doc.Requests) > 32 || len(doc.Redirects) > 21 || len(doc.Findings) > 256 || len(doc.Limitations) > 64 {
		return ErrReportLimit
	}
	if doc.OmittedInputs < 0 || doc.OmittedFindings < 0 || doc.OmittedEvidence < 0 || doc.SkippedInputs != 0 ||
		!doc.Truncated && (doc.OmittedInputs != 0 || doc.OmittedFindings != 0 || doc.OmittedEvidence != 0) {
		return ErrReportInvalid
	}
	if !validTextSlice(doc.Limitations, 64, 4096) {
		return ErrReportLimit
	}
	journeyTargets := map[string]bool{doc.Target: true}
	for _, hop := range doc.Redirects {
		if safeReportOrigin(hop.Target) {
			journeyTargets[hop.Target] = true
		}
	}
	requestIDs := make(map[string]RequestSummary, len(doc.Requests))
	for _, request := range doc.Requests {
		if !validRequest(request) || !journeyTargets[request.Target] {
			return ErrReportInvalid
		}
		if _, exists := requestIDs[request.ID]; exists {
			return ErrReportInvalid
		}
		requestIDs[request.ID] = request
	}
	if anyEvidenceTruncated(doc.Requests) && !doc.Truncated {
		return ErrReportInvalid
	}
	if doc.PrimaryRequestID == "" {
		if doc.FinalTarget != "" || doc.Score.Target != "" || doc.Score.Status == scoring.ScoreAvailable {
			return ErrReportInvalid
		}
	} else {
		primary, exists := requestIDs[doc.PrimaryRequestID]
		if !validReportID(doc.PrimaryRequestID) || !exists || doc.FinalTarget != primary.Target || doc.Score.Target != primary.Target {
			return ErrReportInvalid
		}
	}
	for i, hop := range doc.Redirects {
		if i == 0 && hop.Target != doc.Target || i > 0 && doc.Redirects[i-1].NextTarget != hop.Target {
			return ErrReportInvalid
		}
		if !validRedirect(i, hop, requestIDs) {
			return ErrReportInvalid
		}
	}
	probeTarget := doc.Target
	if doc.FinalTarget != "" {
		probeTarget = doc.FinalTarget
	}
	if doc.CORSProbe != nil && !validProbe(*doc.CORSProbe, probeTarget, requestIDs) {
		return ErrReportInvalid
	}
	if doc.ScanConfig.MaxRequests > 0 {
		attempted := len(doc.Requests)
		if doc.CORSProbe != nil {
			for _, attempt := range doc.CORSProbe.Attempts {
				if attempt.State != "not_run" {
					attempted++
				}
			}
		}
		if attempted > doc.ScanConfig.MaxRequests || !doc.ScanConfig.TraceEnabled && len(doc.Redirects) > 0 || doc.ScanConfig.TraceEnabled && len(doc.Redirects) > doc.ScanConfig.MaxRedirects+1 {
			return ErrReportInvalid
		}
	}
	findings := make(map[string]bool, len(doc.Findings))
	for _, finding := range doc.Findings {
		if !validFinding(finding, requestIDs, doc.Redirects, doc.CORSProbe) || findings[finding.FindingID] {
			return ErrReportInvalid
		}
		findings[finding.FindingID] = true
	}
	if !validScore(doc.Score) {
		return ErrReportInvalid
	}
	if doc.Score.Status == scoring.ScoreAvailable && !doc.Truncated && !scoreMatchesPrimaryFindings(doc) {
		return ErrReportInvalid
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return ErrReportInvalid
	}
	if len(encoded) > MaxDocumentBytes {
		return ErrReportLimit
	}
	return nil
}

func validBudgetConfig(config ScanConfig) bool {
	// Zero means an older in-process producer did not declare a CLI budget.
	if config.MaxRequests == 0 {
		return true
	}
	needed := 1
	if config.TraceEnabled {
		needed = config.MaxRedirects + 1
	}
	if config.CORSProbeEnabled {
		needed += 3
	}
	return needed <= config.MaxRequests
}

func validUTCTime(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0 && value.Year() >= 1 && value.Year() <= 9999
}

func validTexts(max int, values ...string) bool {
	for _, value := range values {
		if len(value) > max || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

func validTextSlice(values []string, maxItems, maxBytes int) bool {
	if len(values) > maxItems {
		return false
	}
	for _, value := range values {
		if !validTexts(maxBytes, value) {
			return false
		}
	}
	return true
}

func validOptionalSafeOrigin(value string) bool { return value == "" || safeReportOrigin(value) }

func validRedirectStop(value string) bool {
	switch value {
	case "", "terminal_response", "location_missing", "location_ambiguous", "location_invalid", "target_invalid", "downgrade_blocked", "same_host_blocked", "loop_detected", "redirect_limit", "request_failed":
		return true
	default:
		return false
	}
}

func validLocationStatus(value string) bool {
	switch value {
	case "not_applicable", "missing", "valid", "ambiguous", "invalid":
		return true
	default:
		return false
	}
}

// CORS ACAO is a bare serialized origin. A path, query, fragment, userinfo or
// noncanonical host would otherwise leak a raw URL into this field.
func validBareOrigin(value string) bool {
	if value == "" {
		return true
	}
	return corsanalysis.ValidSerializedOrigin(value)
}

func validIP(value string) bool {
	if value == "" {
		return true
	}
	_, err := netip.ParseAddr(value)
	return err == nil
}

func validAddrPort(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := netip.ParseAddrPort(value)
	return err == nil && parsed.String() == value
}

func validDecision(value DecisionSummary) bool {
	return validTexts(64, value.Reason, value.Class)
}

func validResolution(value ResolutionSummary) bool {
	if !validTexts(253, value.Host) || !validTexts(64, value.Source, value.PolicyVersion) || !validAddrPort(value.Chosen) || !validDecision(value.Decision) || len(value.Addresses) > 64 {
		return false
	}
	for _, address := range value.Addresses {
		if !validIP(address.Returned) || !validIP(address.Normalized) || !validDecision(address.Decision) {
			return false
		}
	}
	return true
}

func validTLS(value TLSSummary) bool {
	if !validTexts(128, value.Status, value.Version, value.CipherSuite, value.NegotiatedProtocol) || len(value.Certificates) > 16 {
		return false
	}
	for _, cert := range value.Certificates {
		if !validTexts(4096, cert.Subject, cert.Issuer) || !validTexts(128, cert.SHA256, cert.Validity) || cert.DaysRemaining < -10000000 || cert.DaysRemaining > 10000000 || len(cert.SANs) > 128 {
			return false
		}
		if !cert.NotBefore.IsZero() && !validUTCTime(cert.NotBefore) || !cert.NotAfter.IsZero() && !validUTCTime(cert.NotAfter) || !cert.NotBefore.IsZero() && !cert.NotAfter.IsZero() && cert.NotAfter.Before(cert.NotBefore) {
			return false
		}
		for _, san := range cert.SANs {
			if !validTexts(64, san.Kind) || !validTexts(1024, san.Value) || san.Kind != "dns" && san.Kind != "ip" && san.Value != "[REDACTED]" {
				return false
			}
		}
	}
	return true
}

func validHeaders(values []HeaderSummary) bool {
	if len(values) > 10 {
		return false
	}
	names := map[string]string{
		"content_security_policy":      "Content-Security-Policy",
		"strict_transport_security":    "Strict-Transport-Security",
		"x_content_type_options":       "X-Content-Type-Options",
		"referrer_policy":              "Referrer-Policy",
		"permissions_policy":           "Permissions-Policy",
		"x_frame_options":              "X-Frame-Options",
		"cross_origin_opener_policy":   "Cross-Origin-Opener-Policy",
		"cross_origin_resource_policy": "Cross-Origin-Resource-Policy",
		"cross_origin_embedder_policy": "Cross-Origin-Embedder-Policy",
		"server":                       "Server",
	}
	ids := make(map[string]bool, len(values))
	for _, header := range values {
		if !validTexts(64, header.ID, header.Applicability, header.Status, header.Effective) || !validTexts(128, header.Name) || header.Occurrences < 0 || header.Occurrences > 1000000 || ids[header.ID] || names[header.ID] != header.Name {
			return false
		}
		switch header.ID {
		case "strict_transport_security":
			if header.Effective != "" && header.Effective != "active" && header.Effective != "inactive" {
				return false
			}
		case "x_content_type_options":
			if header.Effective != "" && header.Effective != "nosniff" {
				return false
			}
		case "x_frame_options":
			if header.Effective != "" && header.Effective != "DENY" && header.Effective != "SAMEORIGIN" {
				return false
			}
		default:
			if header.Effective != "" {
				return false
			}
		}
		ids[header.ID] = true
	}
	return true
}

func validCookies(values []CookieSummary) bool {
	if len(values) > 128 {
		return false
	}
	for _, cookie := range values {
		if cookie.Position < 0 || cookie.Position > 1000000 || !validTexts(256, cookie.Name, cookie.Domain) || !validTexts(64, cookie.Parse, cookie.Acceptance, cookie.SameSite, cookie.PathScope, cookie.SecureStatus, cookie.HTTPOnlyStatus) || strings.ContainsAny(cookie.Domain, "/?#") || cookie.PathScope != "root" && cookie.PathScope != "scoped" && cookie.PathScope != "unknown" || !validCookieAttributeStatus(cookie.SecureStatus) || !validCookieAttributeStatus(cookie.HTTPOnlyStatus) {
			return false
		}
	}
	return true
}

func validCookieAttributeStatus(value string) bool {
	switch value {
	case "absent", "valid", "invalid", "duplicate", "truncated":
		return true
	default:
		return false
	}
}

func validCookieSection(value RequestSummary) bool {
	if value.CookieFieldCount < 0 || value.CookieFieldCount > 1000000 || value.CookieAnalyzedFields < 0 || value.CookieAnalyzedFields > 128 || value.CookieOmittedFields < 0 || value.CookieOmittedFields > 1000000 || value.CookieAnalyzedFields != len(value.Cookies) || value.CookieFieldCount != value.CookieAnalyzedFields+value.CookieOmittedFields {
		return false
	}
	if value.CookieCapture == "capture_unavailable" {
		return value.CookieFieldCount == 0 && !value.CookieTruncated
	}
	if value.CookieCapture != "capture_complete" {
		return false
	}
	if value.CookieOmittedFields > 0 && !value.CookieTruncated {
		return false
	}
	for _, cookie := range value.Cookies {
		if cookie.Truncated && !value.CookieTruncated {
			return false
		}
	}
	return true
}

func validCSP(value CSPSummary) bool {
	if !validTexts(64, value.Capture, value.Applicability) || len(value.Policies) > 64 || !validTextSlice(value.Observations, 64, 64) {
		return false
	}
	for _, policy := range value.Policies {
		if !validTexts(64, policy.Disposition, policy.Parse) || policy.FieldIndex < -1 || policy.MemberIndex < -1 || len(policy.Directives) > 64 {
			return false
		}
		for _, directive := range policy.Directives {
			if !validTexts(1024, directive.Name) || directive.Name != safeDirectiveName(directive.Name) || !validTexts(128, directive.Kind, directive.Status) || len(directive.Sources) > 256 {
				return false
			}
			for _, source := range directive.Sources {
				if !validCSPSource(source) {
					return false
				}
			}
		}
	}
	return true
}

func validCSPSource(source CSPSourceSummary) bool {
	if !validTexts(64, source.Kind, source.Keyword) || !validTexts(256, source.Scheme, source.Host, source.Port) || strings.ContainsAny(source.Host, "/?#") || strings.ContainsAny(source.Scheme, "/?#") || strings.ContainsAny(source.Port, "/?#") {
		return false
	}
	switch source.Kind {
	case "keyword":
		if source.Scheme != "" || source.Host != "" || source.Port != "" || source.Redacted || source.SubdomainWildcard {
			return false
		}
		switch source.Keyword {
		case "self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic", "unsafe-hashes", "report-sample", "unsafe-allow-redirects", "wasm-unsafe-eval", "trusted-types-eval", "report-sha256", "report-sha384", "report-sha512", "unsafe-webtransport-hashes":
			return true
		default:
			return false
		}
	case "scheme":
		return source.Scheme != "" && source.Keyword == "" && source.Host == "" && source.Port == "" && !source.Redacted && !source.SubdomainWildcard
	case "host":
		return source.Host != "" && source.Keyword == "" && !source.Redacted
	case "nonce", "hash":
		return source.Redacted && source.Keyword == "" && source.Scheme == "" && source.Host == "" && source.Port == "" && !source.SubdomainWildcard
	case "wildcard", "invalid":
		return source.Keyword == "" && source.Scheme == "" && source.Host == "" && source.Port == "" && !source.Redacted && !source.SubdomainWildcard
	default:
		return false
	}
}

func validCORS(value CORSSummary) bool {
	if !validTexts(64, value.Capture, value.OriginStatus, value.OriginKind, value.CredentialsStatus, value.VaryStatus, value.CacheStatus) ||
		!validTexts(4096, value.OriginValue) || !validBareOrigin(value.OriginValue) || !validTextSlice(value.Observations, 64, 64) {
		return false
	}
	return (value.OriginStatus == "valid" && value.OriginKind == "explicit") == (value.OriginValue != "")
}

func validRequest(value RequestSummary) bool {
	if !validReportID(value.ID) || !safeReportOrigin(value.Target) || !validTexts(16, value.Method) || !validTexts(64, value.Result, value.Protocol) || value.StatusCode < 0 || value.StatusCode > 599 || value.DurationMillis < 0 || value.DurationMillis > 86400000 || !validResolution(value.Resolution) || !validAddrPort(value.Peer.Expected) || !validAddrPort(value.Peer.Observed) || !validTexts(64, value.Peer.Decision) || !validTLS(value.TLS) || !validHeaders(value.Headers) || !validCookies(value.Cookies) || !validCookieSection(value) || !validCSP(value.CSP) || !validCORS(value.CORS) {
		return false
	}
	return true
}

func validRedirect(index int, value RedirectSummary, requests map[string]RequestSummary) bool {
	if value.HopIndex != index || !safeReportOrigin(value.Target) || !validOptionalSafeOrigin(value.NextTarget) || !validLocationStatus(value.LocationStatus) || value.StatusCode < 0 || value.StatusCode > 599 {
		return false
	}
	followStatus := value.StatusCode == 301 || value.StatusCode == 302 || value.StatusCode == 303 || value.StatusCode == 307 || value.StatusCode == 308
	if value.NextTarget != "" && (!followStatus || value.LocationStatus != "valid") || !followStatus && value.LocationStatus != "not_applicable" {
		return false
	}
	if value.ResponseID == "" {
		return value.StatusCode == 0 && value.LocationStatus == "not_applicable" && value.NextTarget == ""
	}
	request, exists := requests[value.ResponseID]
	return validReportID(value.ResponseID) && exists && request.Target == value.Target && request.StatusCode == value.StatusCode
}

func validProbe(value ProbeSummary, expectedTarget string, requests map[string]RequestSummary) bool {
	if len(value.Attempts) != 3 {
		return false
	}
	kinds := [...]string{"first_get", "second_get", "preflight"}
	origins := [...]string{"https://sentinelhttp-probe-a.invalid", "https://sentinelhttp-probe-b.invalid", "https://sentinelhttp-probe-a.invalid"}
	seen := make(map[string]bool, len(value.Attempts))
	for i, attempt := range value.Attempts {
		if attempt.Kind != kinds[i] || attempt.Origin != origins[i] || !validTexts(64, attempt.State, attempt.Code) || attempt.StatusCode < 0 || attempt.StatusCode > 599 || !validOptionalSafeOrigin(attempt.Target) || !validCORS(attempt.CORS) {
			return false
		}
		if attempt.State != "captured" && attempt.State != "failed" && attempt.State != "not_run" || attempt.State == "captured" && (attempt.Target != expectedTarget || !validReportID(attempt.ID) || seen[attempt.ID] || attempt.Code != "ok" || attempt.CORS.Capture != "capture_complete") || attempt.State != "captured" && (attempt.ID != "" || attempt.Target != "" || attempt.StatusCode != 0 || !reflect.DeepEqual(attempt.CORS, CORSSummary{})) || attempt.State == "not_run" && attempt.Code != "" || attempt.State == "failed" && !validProbeFailureCode(attempt.Code) {
			return false
		}
		if attempt.State == "captured" {
			if _, exists := requests[attempt.ID]; exists {
				return false
			}
			seen[attempt.ID] = true
		}
	}
	return true
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func validCode(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func validFinding(value findingengine.Finding, requests map[string]RequestSummary, redirects []RedirectSummary, probe *ProbeSummary) bool {
	if !validHex(value.FindingID, 64) || !validCode(value.RuleID, 128) || value.FindingID != findingengine.StableFindingID(value.RuleID, value.Target) || !validTexts(32, value.RuleVersion) || !validTexts(64, string(value.Category), string(value.Severity), string(value.Confidence)) || !safeReportOrigin(value.Target) || !validTexts(4096, value.Observation, value.Inference, value.Hypothesis, value.Impact, value.Remediation) || len(value.Evidence) == 0 || len(value.Evidence) > 16 || !validTextSlice(value.References, 16, 2048) || !validTextSlice(value.Limitations, 16, 4096) {
		return false
	}
	for _, reference := range value.References {
		u, err := url.Parse(reference)
		if err != nil || u == nil || u.Host == "" || u.User != nil || u.Scheme != "https" && u.Scheme != "http" {
			return false
		}
	}
	for _, ref := range value.Evidence {
		if !validReportID(ref.ExchangeID) || !validCode(ref.Code, 64) || ref.HopIndex < -1 || ref.ItemIndex < -1 || ref.HopIndex > 20 || ref.ItemIndex > 1000000 {
			return false
		}
		switch ref.Source {
		case findingengine.TLSEvidence, findingengine.HeaderEvidence, findingengine.CookieEvidence, findingengine.CSPEvidence:
			request, ok := requests[ref.ExchangeID]
			if !ok || request.Target != value.Target || ref.HopIndex != -1 {
				return false
			}
			switch ref.Source {
			case findingengine.TLSEvidence:
				if ref.ItemIndex != 0 || len(request.TLS.Certificates) == 0 {
					return false
				}
			case findingengine.HeaderEvidence:
				if ref.ItemIndex != -1 {
					return false
				}
			case findingengine.CookieEvidence:
				if ref.ItemIndex < 0 || ref.ItemIndex >= len(request.Cookies) || !validCookieEvidence(value.RuleID, ref.Code, request.Cookies[ref.ItemIndex]) {
					return false
				}
			case findingengine.CSPEvidence:
				if ref.ItemIndex < 0 || ref.ItemIndex >= len(request.CSP.Observations) || request.CSP.Observations[ref.ItemIndex] != ref.Code || !validCSPEvidence(value.RuleID, ref.Code) {
					return false
				}
			}
		case findingengine.RedirectEvidence:
			found := false
			for i, hop := range redirects {
				if i == ref.HopIndex && ref.ItemIndex == -1 && hop.ResponseID == ref.ExchangeID && hop.Target == value.Target {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case findingengine.CORSProbeEvidence:
			matched := false
			if probe != nil {
				for i, attempt := range probe.Attempts {
					if ref.HopIndex == -1 && ref.ItemIndex == i && attempt.State == "captured" && attempt.ID == ref.ExchangeID && attempt.Target == value.Target {
						matched = true
						break
					}
				}
			}
			if !matched {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validCookieEvidence(ruleID, code string, cookie CookieSummary) bool {
	if cookie.Parse != "valid" || cookie.Acceptance != "accepted" || cookie.Truncated || cookie.IdentityRepeated || !cookie.SessionLike {
		return false
	}
	switch ruleID {
	case "cookies.session_like_no_secure":
		return code == "secure_absent" && cookie.SecureStatus == "absent" && !cookie.Secure
	case "cookies.session_like_no_httponly":
		return code == "httponly_absent" && cookie.HTTPOnlyStatus == "absent" && !cookie.HTTPOnly
	default:
		return false
	}
}

func validCSPEvidence(ruleID, code string) bool {
	switch ruleID {
	case "csp.no_complete_enforcement":
		return code == "enforcement_absent"
	case "csp.unsafe_inline_observed":
		return code == "unsafe_inline_effective"
	case "csp.unsafe_eval_observed":
		return code == "unsafe_eval_present"
	default:
		return false
	}
}

// Scores are derived from the primary response. When no findings were omitted,
// every catalog finding on that response must have exactly one matching penalty.
func scoreMatchesPrimaryFindings(doc Document) bool {
	if doc.PrimaryRequestID == "" {
		return false
	}
	expected := make(map[string]bool)
	assessed := make(map[scoring.Domain]bool)
	for _, component := range doc.Score.Components {
		if component.Status == scoring.ComponentAssessed {
			assessed[component.Domain] = true
		}
	}
	for _, finding := range doc.Findings {
		if finding.Target != doc.FinalTarget || finding.RuleVersion != "1" {
			continue
		}
		domain, _, ok := scoring.CatalogPenalty(finding.RuleID)
		if !ok || !assessed[domain] {
			continue
		}
		for _, ref := range finding.Evidence {
			if ref.ExchangeID == doc.PrimaryRequestID {
				expected[finding.RuleID] = true
				break
			}
		}
	}
	actual := make(map[string]bool)
	for _, component := range doc.Score.Components {
		for _, penalty := range component.Penalties {
			actual[penalty.RuleID] = true
		}
	}
	return reflect.DeepEqual(expected, actual)
}

func validScore(value scoring.Report) bool {
	if value.ModelVersion != scoring.ModelVersion || value.Label != scoring.Label || value.Status != scoring.ScoreAvailable && value.Status != scoring.ScoreInsufficientEvidence || !validOptionalSafeOrigin(value.Target) || !validTextSlice(value.Limitations, 16, 4096) || len(value.Components) != 4 || value.AssessedWeight < 0 || value.PossibleWeight < 0 || value.CoveragePercent < 0 || value.CoveragePercent > 100 {
		return false
	}
	weights := map[scoring.Domain]int{scoring.DomainTLS: 20, scoring.DomainHeaders: 30, scoring.DomainCookies: 20, scoring.DomainCSP: 30}
	seen := make(map[scoring.Domain]bool, 4)
	assessed, possible, penaltyTotal, assessedDomains := 0, 0, 0, 0
	order := [...]scoring.Domain{scoring.DomainTLS, scoring.DomainHeaders, scoring.DomainCookies, scoring.DomainCSP}
	for index, component := range value.Components {
		weight, ok := weights[component.Domain]
		if !ok || component.Domain != order[index] || seen[component.Domain] || component.Weight != weight || len(component.Penalties) > 16 {
			return false
		}
		seen[component.Domain] = true
		if component.Status != scoring.ComponentAssessed && component.Status != scoring.ComponentNotApplicable && component.Status != scoring.ComponentUnavailable {
			return false
		}
		if component.Status != scoring.ComponentNotApplicable {
			possible += weight
		}
		if component.Status == scoring.ComponentAssessed {
			assessed += weight
			assessedDomains++
		} else if len(component.Penalties) != 0 {
			return false
		}
		seenPenalty := make(map[string]bool, len(component.Penalties))
		componentPenalty := 0
		for _, penalty := range component.Penalties {
			catalogDomain, catalogPoints, catalogOK := scoring.CatalogPenalty(penalty.RuleID)
			if !catalogOK || catalogDomain != component.Domain || catalogPoints != penalty.Points || seenPenalty[penalty.RuleID] {
				return false
			}
			seenPenalty[penalty.RuleID] = true
			componentPenalty += penalty.Points
		}
		if componentPenalty > weight {
			componentPenalty = weight
		}
		penaltyTotal += componentPenalty
	}
	if value.AssessedWeight != assessed || value.PossibleWeight != possible {
		return false
	}
	coverage := 0
	if possible > 0 {
		coverage = (100*assessed + possible/2) / possible
	}
	if value.CoveragePercent != coverage {
		return false
	}
	if value.Status == scoring.ScoreAvailable {
		if value.Value == nil || *value.Value < 0 || *value.Value > 100 || assessed < 50 || assessedDomains < 2 {
			return false
		}
		calculated := (100*(assessed-penaltyTotal) + assessed/2) / assessed
		return *value.Value == calculated
	}
	return value.Value == nil
}
