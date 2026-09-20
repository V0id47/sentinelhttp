package diffing

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/reporting"
)

var ErrInvalidReport = errors.New("diff_report_invalid")

// Compare uses only versioned, minimized report DTOs. Missing evidence is
// reported as unknown; no absent control is inferred from a failed capture.
func Compare(before, after reporting.Document) (Result, error) {
	if reporting.Validate(before) != nil || reporting.Validate(after) != nil {
		return Result{}, ErrInvalidReport
	}
	result := Result{DiffVersion: Version, Status: StatusComparable,
		Target: before.Target, BeforeStarted: before.StartedAt, AfterStarted: after.StartedAt,
		Changes: []Change{}, Unknown: []Unknown{}}
	if before.Target != after.Target || before.TargetScope != "root" || after.TargetScope != "root" {
		result.Status = StatusIncomparable
		reason := "target_path_redacted"
		if before.Target != after.Target {
			reason = "target_changed"
		}
		result.Unknown = append(result.Unknown, Unknown{Section: "report", Reason: reason})
		return result, nil
	}
	compareFindings(&result, before, after)
	oldPrimary, oldOK := primary(before)
	newPrimary, newOK := primary(after)
	if !oldOK || !newOK || before.FinalTarget != after.FinalTarget {
		result.Unknown = append(result.Unknown, Unknown{Section: "primary", Reason: "primary_unavailable_or_changed"})
	} else {
		compareHeaders(&result, oldPrimary, newPrimary)
		compareCookies(&result, oldPrimary, newPrimary)
		compareTLS(&result, oldPrimary, newPrimary)
		compareCSP(&result, oldPrimary, newPrimary)
	}
	compareRedirects(&result, before, after)
	if len(result.Unknown) > 0 {
		result.Status = StatusPartial
	}
	sort.Slice(result.Changes, func(i, j int) bool {
		a, b := result.Changes[i], result.Changes[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Key < b.Key
	})
	sort.Slice(result.Unknown, func(i, j int) bool {
		a, b := result.Unknown[i], result.Unknown[j]
		if a.Section != b.Section {
			return a.Section < b.Section
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Reason < b.Reason
	})
	return result, nil
}

func primary(doc reporting.Document) (reporting.RequestSummary, bool) {
	for _, request := range doc.Requests {
		if request.ID == doc.PrimaryRequestID && request.StatusCode != 0 {
			return request, true
		}
	}
	return reporting.RequestSummary{}, false
}

func compareFindings(result *Result, before, after reporting.Document) {
	old := make(map[string]findingengine.Finding, len(before.Findings))
	newer := make(map[string]findingengine.Finding, len(after.Findings))
	for _, finding := range before.Findings {
		old[finding.FindingID] = finding
	}
	for _, finding := range after.Findings {
		newer[finding.FindingID] = finding
	}
	complete := findingSetsComparable(before, after)
	for id, previous := range old {
		current, exists := newer[id]
		if !exists {
			if complete {
				result.Changes = append(result.Changes, Change{Kind: ResolvedFinding, Key: previous.RuleID + "@" + previous.Target, Before: string(previous.Severity)})
			} else {
				result.Unknown = append(result.Unknown, Unknown{Section: "findings", Key: previous.RuleID + "@" + previous.Target, Reason: "incomplete_finding_set"})
			}
			continue
		}
		if previous.RuleVersion != current.RuleVersion || previous.RuleID != current.RuleID {
			result.Unknown = append(result.Unknown, Unknown{Section: "findings", Key: previous.RuleID + "@" + previous.Target, Reason: "rule_version_changed"})
		} else if previous.Severity != current.Severity {
			result.Changes = append(result.Changes, Change{Kind: SeverityChanged, Key: previous.RuleID + "@" + previous.Target, Before: string(previous.Severity), After: string(current.Severity)})
		}
	}
	for id, current := range newer {
		if _, exists := old[id]; exists {
			continue
		}
		if complete {
			result.Changes = append(result.Changes, Change{Kind: NewFinding, Key: current.RuleID + "@" + current.Target, After: string(current.Severity)})
		} else {
			result.Unknown = append(result.Unknown, Unknown{Section: "findings", Key: current.RuleID + "@" + current.Target, Reason: "incomplete_finding_set"})
		}
	}
}

// Findings may be added or resolved only when both scans covered the same
// initial endpoint successfully. Redirect journeys expose only origins in the
// report, so a multi-hop journey cannot establish equivalent path coverage.
func findingSetsComparable(before, after reporting.Document) bool {
	if before.Truncated || after.Truncated || before.OmittedFindings != 0 || after.OmittedFindings != 0 || before.OmittedInputs != 0 || after.OmittedInputs != 0 || before.OmittedEvidence != 0 || after.OmittedEvidence != 0 {
		return false
	}
	if _, ok := primary(before); !ok {
		return false
	}
	if _, ok := primary(after); !ok {
		return false
	}
	if before.FinalTarget != after.FinalTarget || before.ScanConfig.TraceEnabled != after.ScanConfig.TraceEnabled || before.ScanConfig.CORSProbeEnabled || after.ScanConfig.CORSProbeEnabled {
		return false
	}
	if before.ScanConfig.TraceEnabled {
		return before.RedirectStop == "terminal_response" && after.RedirectStop == "terminal_response" && len(before.Redirects) == 1 && len(after.Redirects) == 1
	}
	return true
}

func compareHeaders(result *Result, before, after reporting.RequestSummary) {
	old := map[string]reporting.HeaderSummary{}
	newer := map[string]reporting.HeaderSummary{}
	for _, header := range before.Headers {
		old[header.ID] = header
	}
	for _, header := range after.Headers {
		newer[header.ID] = header
	}
	if len(old) != 10 || len(newer) != 10 {
		result.Unknown = append(result.Unknown, Unknown{Section: "headers", Reason: "header_set_incomplete"})
		return
	}
	for id, a := range old {
		b, ok := newer[id]
		if !ok || a.Truncated || b.Truncated || a.Status == "deferred" || b.Status == "deferred" {
			result.Unknown = append(result.Unknown, Unknown{Section: "headers", Key: id, Reason: "header_unavailable"})
			continue
		}
		switch {
		case a.Occurrences == 0 && b.Occurrences > 0:
			result.Changes = append(result.Changes, Change{Kind: HeaderAdded, Key: id, Before: a.Status, After: b.Status})
		case a.Occurrences > 0 && b.Occurrences == 0:
			result.Changes = append(result.Changes, Change{Kind: HeaderRemoved, Key: id, Before: a.Status, After: b.Status})
		case a.Status != b.Status || a.Effective != b.Effective || a.Applicability != b.Applicability:
			result.Changes = append(result.Changes, Change{Kind: HeaderChanged, Key: id, Before: a.Status + "/" + a.Effective, After: b.Status + "/" + b.Effective})
		}
	}
}

func cookieKey(value reporting.CookieSummary) string {
	return value.Name + "@" + value.Domain + ":" + value.PathScope
}

func compareCookies(result *Result, before, after reporting.RequestSummary) {
	if before.CookieCapture != "capture_complete" || after.CookieCapture != "capture_complete" || before.CookieTruncated || after.CookieTruncated {
		result.Unknown = append(result.Unknown, Unknown{Section: "cookies", Reason: "cookie_capture_incomplete"})
		return
	}
	old := map[string]reporting.CookieSummary{}
	newer := map[string]reporting.CookieSummary{}
	for _, side := range []struct {
		values []reporting.CookieSummary
		dest   map[string]reporting.CookieSummary
	}{
		{before.Cookies, old}, {after.Cookies, newer},
	} {
		for _, cookie := range side.values {
			key := cookieKey(cookie)
			if cookie.Parse != "valid" || cookie.Acceptance != "accepted" || cookie.Truncated || cookie.IdentityRepeated || cookie.PathScope != "root" {
				result.Unknown = append(result.Unknown, Unknown{Section: "cookies", Key: key, Reason: "cookie_path_identity_unavailable"})
				return
			}
			if _, exists := side.dest[key]; exists {
				result.Unknown = append(result.Unknown, Unknown{Section: "cookies", Key: key, Reason: "cookie_identity_repeated"})
				return
			}
			side.dest[key] = cookie
		}
	}
	for key, a := range old {
		b, exists := newer[key]
		if !exists {
			result.Changes = append(result.Changes, Change{Kind: CookieRemoved, Key: key})
			continue
		}
		if a.Secure != b.Secure || a.HTTPOnly != b.HTTPOnly || a.SecureStatus != b.SecureStatus || a.HTTPOnlyStatus != b.HTTPOnlyStatus || a.SameSite != b.SameSite || a.DomainHostOnly != b.DomainHostOnly {
			result.Changes = append(result.Changes, Change{Kind: CookiePolicyChanged, Key: key, Before: cookiePolicy(a), After: cookiePolicy(b)})
		}
	}
	for key := range newer {
		if _, exists := old[key]; !exists {
			result.Changes = append(result.Changes, Change{Kind: CookieAdded, Key: key})
		}
	}
}

func cookiePolicy(value reporting.CookieSummary) string {
	secure, httpOnly := "off", "off"
	if value.Secure {
		secure = "on"
	}
	if value.HTTPOnly {
		httpOnly = "on"
	}
	hostOnly := "off"
	if value.DomainHostOnly {
		hostOnly = "on"
	}
	return "Secure=" + secure + "; HttpOnly=" + httpOnly + "; SameSite=" + value.SameSite + "; HostOnly=" + hostOnly
}

func compareTLS(result *Result, before, after reporting.RequestSummary) {
	a, b := before.TLS, after.TLS
	if a.Truncated || b.Truncated || a.Status == "unavailable" || b.Status == "unavailable" {
		result.Unknown = append(result.Unknown, Unknown{Section: "tls", Reason: "tls_unavailable"})
		return
	}
	if a.Status != b.Status || a.Version != b.Version || a.CipherSuite != b.CipherSuite || a.NegotiatedProtocol != b.NegotiatedProtocol {
		result.Changes = append(result.Changes, Change{Kind: TLSChanged, Key: "negotiated", Before: a.Status + "/" + a.Version + "/" + a.CipherSuite, After: b.Status + "/" + b.Version + "/" + b.CipherSuite})
	}
	if len(a.Certificates) == 0 && len(b.Certificates) == 0 {
		return
	}
	if len(a.Certificates) == 0 || len(b.Certificates) == 0 || a.Certificates[0].Truncated || b.Certificates[0].Truncated {
		result.Unknown = append(result.Unknown, Unknown{Section: "certificate", Reason: "certificate_unavailable"})
		return
	}
	if a.Certificates[0].SHA256 != b.Certificates[0].SHA256 {
		result.Changes = append(result.Changes, Change{Kind: CertificateChanged, Key: "leaf_sha256", Before: a.Certificates[0].SHA256, After: b.Certificates[0].SHA256})
	}
}

func normalizeCSP(value reporting.CSPSummary) reporting.CSPSummary {
	normalized := value
	normalized.Policies = make([]reporting.CSPPolicySummary, len(value.Policies))
	normalized.Observations = make([]string, len(value.Observations))
	copy(normalized.Observations, value.Observations)
	sort.Strings(normalized.Observations)
	for i, policy := range value.Policies {
		policy.FieldIndex, policy.MemberIndex = 0, 0
		policy.Directives = make([]reporting.CSPDirectiveSummary, len(value.Policies[i].Directives))
		for j, directive := range value.Policies[i].Directives {
			directive.Sources = make([]reporting.CSPSourceSummary, len(value.Policies[i].Directives[j].Sources))
			copy(directive.Sources, value.Policies[i].Directives[j].Sources)
			sort.Slice(directive.Sources, func(x, y int) bool {
				a, _ := json.Marshal(directive.Sources[x])
				b, _ := json.Marshal(directive.Sources[y])
				return string(a) < string(b)
			})
			policy.Directives[j] = directive
		}
		normalized.Policies[i] = policy
	}
	sort.Slice(normalized.Policies, func(i, j int) bool {
		a, _ := json.Marshal(normalized.Policies[i])
		b, _ := json.Marshal(normalized.Policies[j])
		return string(a) < string(b)
	})
	return normalized
}

func compareCSP(result *Result, before, after reporting.RequestSummary) {
	a, b := before.CSP, after.CSP
	if a.Capture != "capture_complete" || b.Capture != "capture_complete" || a.Truncated || b.Truncated {
		result.Unknown = append(result.Unknown, Unknown{Section: "csp", Reason: "csp_capture_incomplete"})
		return
	}
	for _, policy := range append(append([]reporting.CSPPolicySummary(nil), a.Policies...), b.Policies...) {
		if policy.Truncated {
			result.Unknown = append(result.Unknown, Unknown{Section: "csp", Reason: "csp_policy_truncated"})
			return
		}
	}
	if !reflect.DeepEqual(normalizeCSP(a), normalizeCSP(b)) {
		result.Changes = append(result.Changes, Change{Kind: CSPChanged, Key: "policy_and_observations"})
	}
}

func compareRedirects(result *Result, before, after reporting.Document) {
	if !before.ScanConfig.TraceEnabled && !after.ScanConfig.TraceEnabled {
		return
	}
	if !before.ScanConfig.TraceEnabled || !after.ScanConfig.TraceEnabled || len(before.Redirects) == 0 || len(after.Redirects) == 0 {
		result.Unknown = append(result.Unknown, Unknown{Section: "redirects", Reason: "trace_coverage_changed"})
		return
	}
	if before.RedirectStop != "terminal_response" || after.RedirectStop != "terminal_response" || before.ScanConfig.MaxRedirects != after.ScanConfig.MaxRedirects || before.ScanConfig.SameHost != after.ScanConfig.SameHost || before.ScanConfig.AllowPrivate != after.ScanConfig.AllowPrivate {
		result.Unknown = append(result.Unknown, Unknown{Section: "redirects", Reason: "trace_incomplete_or_policy_changed"})
		return
	}
	if len(before.Redirects) > 1 || len(after.Redirects) > 1 {
		result.Unknown = append(result.Unknown, Unknown{Section: "redirects", Reason: "redirect_path_redacted"})
		return
	}
	a := append([]reporting.RedirectSummary(nil), before.Redirects...)
	b := append([]reporting.RedirectSummary(nil), after.Redirects...)
	for i := range a {
		a[i].ResponseID = ""
	}
	for i := range b {
		b[i].ResponseID = ""
	}
	if before.RedirectStop != after.RedirectStop || !reflect.DeepEqual(a, b) {
		result.Changes = append(result.Changes, Change{Kind: RedirectChanged, Key: "terminal_status", Before: strconv.Itoa(a[0].StatusCode), After: strconv.Itoa(b[0].StatusCode)})
	}
}
