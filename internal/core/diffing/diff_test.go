package diffing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/reporting"
)

func fixtureReports(t *testing.T) (reporting.Document, reporting.Document) {
	t.Helper()
	var hardened atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if hardened.Load() {
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	target, err := network.ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := network.NewBoundary(target, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	build := func() reporting.Document {
		response, err := client.Do(context.Background(), target, httpclient.GET)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
		doc, err := reporting.Build(reporting.Input{InitialTarget: target, StartedAt: at, CompletedAt: at, Primary: response, Config: reporting.ScanConfig{AllowPrivate: true}})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	before := build()
	hardened.Store(true)
	after := build()
	return before, after
}

func TestCompareFindingsAndHeadersIgnoreExchangeIDs(t *testing.T) {
	before, after := fixtureReports(t)
	result, err := Compare(before, after)
	if err != nil || result.Status != StatusComparable {
		t.Fatalf("comparison failed: %v %+v", err, result)
	}
	for _, kind := range []ChangeKind{ResolvedFinding, HeaderAdded} {
		found := false
		for _, change := range result.Changes {
			if change.Kind == kind {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s change: %+v", kind, result.Changes)
		}
	}
	if result.Target != before.Target {
		t.Fatal("wrong safe target")
	}
}

func TestCompareTruncatedReportDoesNotClaimResolution(t *testing.T) {
	before, after := fixtureReports(t)
	after.Truncated = true
	result, err := Compare(before, after)
	if err != nil || result.Status != StatusPartial {
		t.Fatalf("partial report comparison failed: %v %+v", err, result)
	}
	for _, change := range result.Changes {
		if change.Kind == ResolvedFinding {
			t.Fatal("truncated report claimed resolution")
		}
	}
}

func TestCompareRejectsDifferentInitialTargets(t *testing.T) {
	before, _ := fixtureReports(t)
	_, after := fixtureReports(t)
	result, err := Compare(before, after)
	if err != nil || result.Status != StatusIncomparable || len(result.Changes) != 0 {
		t.Fatalf("different origins were compared: %v %+v", err, result)
	}
}

func cloneDocument(t *testing.T, doc reporting.Document) reporting.Document {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := reporting.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestCompareFindingSeverityAndVersion(t *testing.T) {
	before, _ := fixtureReports(t)
	if len(before.Findings) == 0 {
		t.Fatal("fixture lacks findings")
	}
	after := cloneDocument(t, before)
	after.Findings[0].Severity = "LOW"
	result, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range result.Changes {
		if change.Kind == SeverityChanged {
			found = true
		}
	}
	if !found {
		t.Fatal("severity change missing")
	}
	after.Findings[0].RuleVersion = "2"
	result = Result{}
	compareFindings(&result, before, after)
	for _, change := range result.Changes {
		if change.Kind == SeverityChanged {
			t.Fatal("severity compared across rule versions")
		}
	}
}

func TestCompareCookiePolicyWithoutValues(t *testing.T) {
	before, _ := fixtureReports(t)
	before.Requests[0].Cookies = []reporting.CookieSummary{{Position: 0, Name: "session_id", Parse: "valid", Acceptance: "accepted", SecureStatus: "absent", HTTPOnlyStatus: "absent", PathScope: "root"}}
	before.Requests[0].CookieFieldCount = 1
	before.Requests[0].CookieAnalyzedFields = 1
	after := cloneDocument(t, before)
	after.Requests[0].Cookies[0].Secure = true
	after.Requests[0].Cookies[0].SecureStatus = "valid"
	result, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range result.Changes {
		if change.Kind == CookiePolicyChanged && change.Key == "session_id@:root" {
			return
		}
	}
	t.Fatal("cookie policy change missing")
}

func TestCompareFailedPrimaryDoesNotResolveFinding(t *testing.T) {
	before, after := fixtureReports(t)
	after.Requests[0].StatusCode = 0
	after.Requests[0].Result = "request_failed"
	after.Findings = nil
	result, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range result.Changes {
		if change.Kind == ResolvedFinding {
			t.Fatal("failed primary claimed a resolved finding")
		}
	}
	if result.Status != StatusPartial {
		t.Fatalf("failed primary status = %s", result.Status)
	}
}

func TestCompareDifferentPathsOnSameOrigin(t *testing.T) {
	before, after := fixtureReports(t)
	// The safe display target is intentionally identical, but a redacted path
	// cannot prove endpoint equality.
	after.TargetScope = "redacted"
	result, err := Compare(before, after)
	if err != nil || result.Status != StatusIncomparable || len(result.Changes) != 0 {
		t.Fatalf("same origin with different URL identity compared: %v %+v", err, result)
	}
}

func TestCompareHostOnlyCookieScopeChange(t *testing.T) {
	before, _ := fixtureReports(t)
	before.Requests[0].Cookies = []reporting.CookieSummary{{Position: 0, Name: "sid", Domain: "example.com", DomainHostOnly: true, PathScope: "root", Parse: "valid", Acceptance: "accepted", SecureStatus: "absent", HTTPOnlyStatus: "absent"}}
	before.Requests[0].CookieFieldCount = 1
	before.Requests[0].CookieAnalyzedFields = 1
	after := cloneDocument(t, before)
	after.Requests[0].Cookies[0].DomainHostOnly = false
	result, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range result.Changes {
		if change.Kind == CookiePolicyChanged {
			return
		}
	}
	t.Fatal("host-only cookie scope change was omitted")
}

func TestCompareScopedCookieIdentityIsUnknown(t *testing.T) {
	before, _ := fixtureReports(t)
	before.Requests[0].Cookies = []reporting.CookieSummary{{Position: 0, Name: "session_id", Parse: "valid", Acceptance: "accepted", SecureStatus: "absent", HTTPOnlyStatus: "absent", PathScope: "scoped"}}
	before.Requests[0].CookieFieldCount = 1
	before.Requests[0].CookieAnalyzedFields = 1
	after := cloneDocument(t, before)
	after.Requests[0].Cookies[0].Secure = true
	after.Requests[0].Cookies[0].SecureStatus = "valid"
	result, err := Compare(before, after)
	if err != nil || result.Status != StatusPartial {
		t.Fatalf("scoped cookie comparison: %v %+v", err, result)
	}
	for _, change := range result.Changes {
		if change.Kind == CookiePolicyChanged {
			t.Fatal("different scoped paths treated as identical")
		}
	}
}

func TestCompareIncompleteRedirectTraceIsUnknown(t *testing.T) {
	before, after := fixtureReports(t)
	before.ScanConfig.TraceEnabled, after.ScanConfig.TraceEnabled = true, true
	before.ScanConfig.MaxRedirects, after.ScanConfig.MaxRedirects = 10, 10
	before.RedirectStop, after.RedirectStop = "request_failed", "terminal_response"
	before.Redirects = []reporting.RedirectSummary{{HopIndex: 0, Target: before.Target, LocationStatus: "not_applicable"}}
	after.Redirects = []reporting.RedirectSummary{{HopIndex: 0, Target: after.Target, LocationStatus: "not_applicable"}}
	result := Result{}
	compareRedirects(&result, before, after)
	for _, change := range result.Changes {
		if change.Kind == RedirectChanged {
			t.Fatal("incomplete redirect trace claimed a semantic change")
		}
	}
	if len(result.Unknown) == 0 {
		t.Fatal("missing redirect uncertainty")
	}
}

func TestCompareMultiHopRedirectPathIsUnknown(t *testing.T) {
	before, after := fixtureReports(t)
	before.ScanConfig.TraceEnabled, after.ScanConfig.TraceEnabled = true, true
	before.ScanConfig.MaxRedirects, after.ScanConfig.MaxRedirects = 10, 10
	before.RedirectStop, after.RedirectStop = "terminal_response", "terminal_response"
	for _, doc := range []*reporting.Document{&before, &after} {
		doc.Redirects = []reporting.RedirectSummary{{HopIndex: 0, Target: doc.Target, StatusCode: 302, LocationStatus: "valid", NextTarget: doc.Target}, {HopIndex: 1, Target: doc.Target, StatusCode: 200, LocationStatus: "not_applicable"}}
	}
	result := Result{}
	compareRedirects(&result, before, after)
	if len(result.Changes) != 0 || len(result.Unknown) == 0 {
		t.Fatalf("redacted redirect paths treated as equivalent: %+v", result)
	}
}

func TestCompareControlNormalizationAndUnknown(t *testing.T) {
	var result Result
	before := reporting.RequestSummary{TLS: reporting.TLSSummary{Status: "verified", Version: "TLS1.3", CipherSuite: "A", Certificates: []reporting.CertificateSummary{{SHA256: "first"}}}}
	after := reporting.RequestSummary{TLS: reporting.TLSSummary{Status: "verified", Version: "TLS1.2", CipherSuite: "B", Certificates: []reporting.CertificateSummary{{SHA256: "second"}}}}
	compareTLS(&result, before, after)
	if len(result.Changes) != 2 || result.Changes[0].Kind != TLSChanged || result.Changes[1].Kind != CertificateChanged {
		t.Fatalf("TLS and leaf fingerprint changes missing: %+v", result.Changes)
	}
	result = Result{}
	before.CSP = reporting.CSPSummary{Capture: "capture_complete", Applicability: "applicable", Policies: []reporting.CSPPolicySummary{{Disposition: "enforce", FieldIndex: 0, Directives: []reporting.CSPDirectiveSummary{{Name: "default-src", Sources: []reporting.CSPSourceSummary{{Kind: "keyword", Keyword: "none"}}}}}}}
	after.CSP = before.CSP
	after.CSP.Policies = append([]reporting.CSPPolicySummary(nil), before.CSP.Policies...)
	after.CSP.Policies[0].FieldIndex = 2
	compareCSP(&result, before, after)
	if len(result.Changes) != 0 {
		t.Fatal("CSP field index noise became a semantic change")
	}
	after.CSP.Policies[0].Truncated = true
	compareCSP(&result, before, after)
	if len(result.Unknown) == 0 {
		t.Fatal("truncated CSP was treated as comparable")
	}
}

func TestRenderTerminalEscapesHostileDynamicText(t *testing.T) {
	result := Result{DiffVersion: Version, Status: StatusPartial, Target: "https://example.com/\x1b[31m", Changes: []Change{{Kind: HeaderChanged, Key: "x\nheader", Before: "\x1b[2J", After: "ok"}}, Unknown: []Unknown{{Section: "headers", Key: "\u202e", Reason: "header_unavailable"}}}
	data, err := Render(result, FormatTerminal)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"\x1b", "x\nheader", "\u202e"} {
		if strings.Contains(string(data), unsafe) {
			t.Fatalf("unsafe text in terminal: %q", data)
		}
	}
}
