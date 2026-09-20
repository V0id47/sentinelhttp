package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/scoring"
)

func validReportDocument(t *testing.T) Document {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	target, err := network.ParseTarget(server.URL + "/private?token=secret")
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
	response, err := client.Do(context.Background(), target, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: response, Config: ScanConfig{AllowPrivate: true, MaxRedirects: 10, TimeoutMillis: 2000, MaxResponseBytes: 2 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestParseBuildRoundTrip(t *testing.T) {
	original := validReportDocument(t)
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(encoded)
	if err != nil {
		t.Fatalf("valid Build report rejected: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatal("parsed document differs from Build output")
	}
}

func TestParseRejectsUnknownFieldsTrailingJSONAndOversize(t *testing.T) {
	doc := validReportDocument(t)
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"top-level unknown": []byte(strings.TrimSuffix(string(encoded), "}") + `,"surprise":true}`),
		"nested unknown":    []byte(strings.Replace(string(encoded), `"scan_config":{`, `"scan_config":{"secret":"x",`, 1)),
		"trailing object":   append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"trailing garbage":  append(append([]byte(nil), encoded...), []byte(` x`)...),
		"oversized input":   []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("invalid JSON was accepted")
			}
		})
	}
}

func TestValidateRejectsIdentityTimeAndCountContradictions(t *testing.T) {
	base := validReportDocument(t)
	if err := Validate(base); err != nil {
		t.Fatalf("valid Build report rejected: %v", err)
	}
	cases := map[string]func(*Document){
		"schema":                  func(d *Document) { d.SchemaVersion = "2.0" },
		"tool":                    func(d *Document) { d.Tool = "Other" },
		"tool version":            func(d *Document) { d.ToolVersion = "9.0" },
		"reversed time":           func(d *Document) { d.CompletedAt = d.StartedAt.Add(-time.Second) },
		"non-UTC time":            func(d *Document) { d.StartedAt = d.StartedAt.In(time.FixedZone("offset", 3600)) },
		"unsafe target":           func(d *Document) { d.Target = "http://example.com/private?token=secret" },
		"unsafe final":            func(d *Document) { d.FinalTarget = "http://example.com/private" },
		"missing primary":         func(d *Document) { d.PrimaryRequestID = strings.Repeat("a", 32) },
		"duplicate request":       func(d *Document) { d.Requests = append(d.Requests, d.Requests[0]) },
		"duplicate finding":       func(d *Document) { d.Findings = append(d.Findings, d.Findings[0]) },
		"fabricated finding ID":   func(d *Document) { d.Findings[0].FindingID = strings.Repeat("e", 64) },
		"bad finding target":      func(d *Document) { d.Findings[0].Target = "https://example.com/private" },
		"finding target mismatch": func(d *Document) { d.Findings[0].Target = "https://other.invalid/[REDACTED]" },
		"bad evidence ref":        func(d *Document) { d.Findings[0].Evidence[0].ExchangeID = strings.Repeat("a", 32) },
		"score target":            func(d *Document) { d.Score.Target = "https://example.com/[REDACTED]" },
		"score value":             func(d *Document) { n := 101; d.Score.Value = &n },
		"score coverage":          func(d *Document) { d.Score.CoveragePercent = 101 },
		"score weight":            func(d *Document) { d.Score.AssessedWeight = d.Score.PossibleWeight + 1 },
		"omission count":          func(d *Document) { d.OmittedFindings = -1 },
		"truncation flag":         func(d *Document) { d.Truncated = false; d.OmittedFindings = 1 },
		"skipped input":           func(d *Document) { d.SkippedInputs = 1 },
		"unknown redirect stop":   func(d *Document) { d.RedirectStop = "raw Location: /secret" },
		"redirect first hop": func(d *Document) {
			d.RedirectStop = "terminal_response"
			d.Redirects = []RedirectSummary{{HopIndex: 0, Target: "https://other.invalid/[REDACTED]", LocationStatus: "not_applicable"}}
		},
		"redirect continuity": func(d *Document) {
			d.RedirectStop = "terminal_response"
			d.Redirects = []RedirectSummary{{HopIndex: 0, Target: d.Target, LocationStatus: "valid", NextTarget: "https://other.invalid/[REDACTED]"}, {HopIndex: 1, Target: "https://third.invalid/[REDACTED]", LocationStatus: "not_applicable"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := base
			doc.Requests = append([]RequestSummary(nil), base.Requests...)
			doc.Findings = append(base.Findings[:0:0], base.Findings...)
			if len(doc.Findings) > 0 {
				doc.Findings[0].Evidence = append(doc.Findings[0].Evidence[:0:0], doc.Findings[0].Evidence...)
			}
			mutate(&doc)
			if err := Validate(doc); err == nil {
				t.Fatal("contradictory document was accepted")
			}
		})
	}
}

func TestValidateRejectsRequestOutsideRecordedJourney(t *testing.T) {
	doc := validReportDocument(t)
	doc.Requests[0].Target = "https://other.invalid/[REDACTED]"
	doc.FinalTarget = doc.Requests[0].Target
	doc.Score.Target = doc.Requests[0].Target
	if err := Validate(doc); err == nil {
		t.Fatal("request from an unrecorded origin was accepted")
	}
}

func TestValidateRejectsNestedBoundsAndOriginLeakage(t *testing.T) {
	base := validReportDocument(t)
	cases := map[string]func(*Document){
		"requests": func(d *Document) {
			for len(d.Requests) <= 32 {
				d.Requests = append(d.Requests, d.Requests[0])
			}
		},
		"redirects":      func(d *Document) { d.Redirects = make([]RedirectSummary, 22) },
		"probe attempts": func(d *Document) { d.CORSProbe = &ProbeSummary{Attempts: make([]ProbeAttemptSummary, 4)} },
		"partial probe slots": func(d *Document) {
			d.ScanConfig.CORSProbeEnabled = true
			d.CORSProbe = &ProbeSummary{Attempts: []ProbeAttemptSummary{{Kind: "first_get", Origin: "https://sentinelhttp-probe-a.invalid", State: "not_run"}}}
		},
		"findings": func(d *Document) {
			for len(d.Findings) <= 256 {
				d.Findings = append(d.Findings, d.Findings[0])
			}
		},
		"evidence":    func(d *Document) { d.Findings[0].Evidence = make([]findingengine.EvidenceRef, 17) },
		"limitations": func(d *Document) { d.Limitations = make([]string, 65) },
		"cookie name": func(d *Document) {
			d.Requests[0].Cookies = append(d.Requests[0].Cookies, CookieSummary{Name: strings.Repeat("x", 257)})
		},
		"raw header effective": func(d *Document) { d.Requests[0].Headers[0].Effective = "Bearer SECRET" },
		"TLS subject": func(d *Document) {
			d.Requests[0].TLS.Certificates = append(d.Requests[0].TLS.Certificates, CertificateSummary{Subject: strings.Repeat("x", 4097)})
		},
		"raw URI SAN": func(d *Document) {
			d.Requests[0].TLS.Certificates = []CertificateSummary{{SANs: []SANSummary{{Kind: "uri", Value: "https://example.com/private?token=secret"}}}}
		},
		"raw CSP nonce": func(d *Document) {
			d.Requests[0].CSP.Policies = []CSPPolicySummary{{Directives: []CSPDirectiveSummary{{Sources: []CSPSourceSummary{{Kind: "nonce", Keyword: "SECRET-nonce", Redacted: true}}}}}}
		},
		"CORS origin path":        func(d *Document) { d.Requests[0].CORS.OriginValue = "https://example.com/private?token=secret" },
		"oversized finding prose": func(d *Document) { d.Findings[0].Observation = strings.Repeat("x", 4097) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := base
			doc.Requests = append([]RequestSummary(nil), base.Requests...)
			doc.Findings = append(base.Findings[:0:0], base.Findings...)
			mutate(&doc)
			if err := Validate(doc); err == nil {
				t.Fatal("unbounded or unsafe nested document was accepted")
			}
		})
	}
}

func TestParseReturnsTypedSafeErrors(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version":"2.0"}`)); !errors.Is(err, ErrReportUnsupported) {
		t.Fatalf("unsupported version needs typed error: %v", err)
	}
	if _, err := Parse([]byte(`{"schema_version":`)); !errors.Is(err, ErrReportMalformed) {
		t.Fatalf("malformed JSON needs typed error: %v", err)
	}
	if _, err := Parse([]byte(strings.Repeat("x", MaxDocumentBytes+1))); !errors.Is(err, ErrReportLimit) {
		t.Fatalf("oversized JSON needs typed limit error: %v", err)
	}
}

func TestValidateAcceptsBuildWithoutPrimary(t *testing.T) {
	target, err := network.ParseTarget("https://example.invalid/private?secret=yes")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(doc); err != nil {
		t.Fatalf("Build without a primary response was rejected: %v", err)
	}
}

func TestValidateProbeEvidenceMustReferenceCapturedAttempt(t *testing.T) {
	base := validReportDocument(t)
	probeID := strings.Repeat("b", 32)
	base.ScanConfig.CORSProbeEnabled = true
	base.CORSProbe = &ProbeSummary{Attempts: []ProbeAttemptSummary{
		{ID: probeID, Kind: "first_get", Origin: "https://sentinelhttp-probe-a.invalid", State: "captured", Code: "ok", StatusCode: 200, Target: base.FinalTarget, CORS: CORSSummary{Capture: "capture_complete"}},
		{Kind: "second_get", Origin: "https://sentinelhttp-probe-b.invalid", State: "not_run"},
		{Kind: "preflight", Origin: "https://sentinelhttp-probe-a.invalid", State: "not_run"},
	}}
	finding := base.Findings[0]
	finding.RuleID = "cors.sampled_reflection_with_credentials"
	finding.FindingID = findingengine.StableFindingID(finding.RuleID, finding.Target)
	finding.Evidence = []findingengine.EvidenceRef{{ExchangeID: probeID, Source: findingengine.CORSProbeEvidence, Code: "sampled", HopIndex: -1, ItemIndex: 0}}
	base.Findings = append(base.Findings, finding)
	if err := Validate(base); err != nil {
		t.Fatalf("captured probe evidence rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Document){
		"uncaptured ID":     func(d *Document) { d.CORSProbe.Attempts[0].ID = "" },
		"wrong target":      func(d *Document) { d.CORSProbe.Attempts[0].Target = "https://other.invalid/[REDACTED]" },
		"dangling evidence": func(d *Document) { d.Findings[len(d.Findings)-1].Evidence[0].ExchangeID = strings.Repeat("c", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			doc := base
			probe := *base.CORSProbe
			probe.Attempts = append([]ProbeAttemptSummary(nil), probe.Attempts...)
			doc.CORSProbe = &probe
			doc.Findings = append(base.Findings[:0:0], base.Findings...)
			last := len(doc.Findings) - 1
			doc.Findings[last].Evidence = append([]findingengine.EvidenceRef(nil), doc.Findings[last].Evidence...)
			mutate(&doc)
			if err := Validate(doc); err == nil {
				t.Fatal("probe provenance contradiction was accepted")
			}
		})
	}
}

func TestValidateRejectsRedirectAndAnalyzerEvidenceIndexDrift(t *testing.T) {
	base := validReportDocument(t)
	base.RedirectStop = "terminal_response"
	base.Redirects = []RedirectSummary{{HopIndex: 0, ResponseID: base.Requests[0].ID, Target: base.Target, StatusCode: base.Requests[0].StatusCode, LocationStatus: "not_applicable"}}
	finding := base.Findings[0]
	finding.RuleID = "redirects.loop_or_limit"
	finding.FindingID = findingengine.StableFindingID(finding.RuleID, finding.Target)
	finding.Evidence = []findingengine.EvidenceRef{{ExchangeID: base.Requests[0].ID, Source: findingengine.RedirectEvidence, Code: "redirect_limit", HopIndex: 0, ItemIndex: -1}}
	base.Findings = append(base.Findings, finding)
	if err := Validate(base); err != nil {
		t.Fatalf("valid synthetic redirect reference rejected: %v", err)
	}
	badHop := base
	badHop.Findings = append([]findingengine.Finding(nil), base.Findings...)
	badHop.Findings[len(badHop.Findings)-1].Evidence = append([]findingengine.EvidenceRef(nil), finding.Evidence...)
	badHop.Findings[len(badHop.Findings)-1].Evidence[0].HopIndex = 20
	if err := Validate(badHop); err == nil {
		t.Fatal("redirect evidence accepted an unrelated hop index")
	}
	badItem := base
	badItem.Findings = append([]findingengine.Finding(nil), base.Findings...)
	badItem.Findings[0].Evidence = append([]findingengine.EvidenceRef(nil), base.Findings[0].Evidence...)
	badItem.Findings[0].Evidence[0].ItemIndex = 100
	if err := Validate(badItem); err == nil {
		t.Fatal("analyzer evidence accepted an absent item index")
	}
}

func TestValidateRejectsFabricatedScoreCatalog(t *testing.T) {
	base := validReportDocument(t)
	changed := false
	for i := range base.Score.Components {
		if len(base.Score.Components[i].Penalties) == 0 {
			continue
		}
		base.Score.Components[i].Penalties[0].RuleID = "invented.rule"
		changed = true
		break
	}
	if !changed {
		t.Fatal("fixture lacks a score penalty")
	}
	if err := Validate(base); err == nil {
		t.Fatal("score accepted a noncatalog penalty rule")
	}
}

func TestValidateAcceptsUpstreamCSPBounds(t *testing.T) {
	doc := validReportDocument(t)
	doc.Requests[0].CSP.Policies = make([]CSPPolicySummary, 64)
	for i := range doc.Requests[0].CSP.Policies {
		sources := make([]CSPSourceSummary, 256)
		for j := range sources {
			sources[j].Kind = "invalid"
		}
		doc.Requests[0].CSP.Policies[i] = CSPPolicySummary{Disposition: "enforce", Parse: "valid", Directives: []CSPDirectiveSummary{{Name: "script-src", Kind: "source_list", Status: "valid", Sources: sources}}}
	}
	if err := Validate(doc); err != nil {
		t.Fatalf("upstream CSP array maxima were rejected: %v", err)
	}
}

func TestValidateAcceptsLongCertificateValidity(t *testing.T) {
	doc := validReportDocument(t)
	doc.Requests[0].TLS.Certificates = []CertificateSummary{{DaysRemaining: 2_500_000}}
	if err := Validate(doc); err != nil {
		t.Fatalf("long but valid certificate lifetime was rejected: %v", err)
	}
}

func TestValidateRejectsAvailableScoreWithOneAssessedDomain(t *testing.T) {
	target, err := network.ParseTarget("https://example.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	doc.Score.Status = "available"
	value := 100
	doc.Score.Value = &value
	doc.Score.Components[0].Status = "assessed"
	doc.Score.AssessedWeight = 20
	doc.Score.CoveragePercent = 20
	if err := Validate(doc); err == nil {
		t.Fatal("available score with one assessed domain was accepted")
	}
}

func TestValidateRejectsAvailableScoreWithoutPrimary(t *testing.T) {
	target, err := network.ParseTarget("https://example.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	doc.Score.Status = "available"
	value := 100
	doc.Score.Value = &value
	doc.Score.Components[0].Status = "assessed"
	doc.Score.Components[1].Status = "assessed"
	doc.Score.AssessedWeight = 50
	doc.Score.CoveragePercent = 50
	if err := Validate(doc); err == nil {
		t.Fatal("available score without a primary exchange was accepted")
	}
}

func TestValidateRejectsEvidencePointingAtUnrelatedCookieOrCSPItem(t *testing.T) {
	base := validReportDocument(t)
	base.Requests[0].Cookies = []CookieSummary{
		{Position: 0, Name: "session_id", Parse: "valid", Acceptance: "accepted", SecureStatus: "absent", HTTPOnlyStatus: "absent", SessionLike: true, PathScope: "unknown"},
		{Position: 1, Name: "other", Parse: "valid", Acceptance: "accepted", Secure: true, SecureStatus: "valid", HTTPOnlyStatus: "absent", SessionLike: true, PathScope: "unknown"},
	}
	base.Requests[0].CookieCapture = "capture_complete"
	base.Requests[0].CookieFieldCount = 2
	base.Requests[0].CookieAnalyzedFields = 2
	finding := base.Findings[0]
	finding.RuleID = "cookies.session_like_no_secure"
	finding.FindingID = findingengine.StableFindingID(finding.RuleID, finding.Target)
	finding.Evidence = []findingengine.EvidenceRef{{ExchangeID: base.PrimaryRequestID, Source: findingengine.CookieEvidence, Code: "secure_absent", HopIndex: -1, ItemIndex: 0}}
	base.Findings = append(base.Findings, finding)
	base.Truncated = true // Synthetic finding is intentionally outside the score fixture.
	if err := Validate(base); err != nil {
		t.Fatalf("valid cookie evidence rejected: %v", err)
	}
	base.Findings[len(base.Findings)-1].Evidence[0].ItemIndex = 1
	if err := Validate(base); err == nil {
		t.Fatal("secure cookie accepted as insecure-cookie evidence")
	}

	base = validReportDocument(t)
	for i := range base.Findings {
		for j := range base.Findings[i].Evidence {
			if base.Findings[i].Evidence[j].Source != findingengine.CSPEvidence {
				continue
			}
			base.Requests[0].CSP.Observations = append(base.Requests[0].CSP.Observations, "unsafe_eval_present")
			base.Findings[i].Evidence[j].ItemIndex = len(base.Requests[0].CSP.Observations) - 1
			if err := Validate(base); err == nil {
				t.Fatal("unrelated CSP observation accepted as finding evidence")
			}
			return
		}
	}
	t.Fatal("fixture lacks CSP evidence")
}

func TestValidateRejectsScoreOmittingPrimaryFindingPenalty(t *testing.T) {
	doc := validReportDocument(t)
	found := false
	for i := range doc.Score.Components {
		if len(doc.Score.Components[i].Penalties) == 0 {
			continue
		}
		found = true
		doc.Score.Components[i].Penalties = nil
	}
	if !found {
		t.Fatal("fixture lacks a score penalty")
	}
	value := 100
	doc.Score.Value = &value
	if err := Validate(doc); err == nil {
		t.Fatal("score accepted primary findings without their penalties")
	}
}

func TestValidateRejectsImpossibleFollowedRedirect(t *testing.T) {
	base := validReportDocument(t)
	base.RedirectStop = "terminal_response"
	base.Redirects = []RedirectSummary{
		{HopIndex: 0, ResponseID: base.PrimaryRequestID, Target: base.Target, StatusCode: base.Requests[0].StatusCode, LocationStatus: "not_applicable", NextTarget: base.Target},
		{HopIndex: 1, ResponseID: base.PrimaryRequestID, Target: base.Target, StatusCode: base.Requests[0].StatusCode, LocationStatus: "not_applicable"},
	}
	if err := Validate(base); err == nil {
		t.Fatal("followed redirect after HTTP 200 was accepted")
	}
}

func TestValidateRejectsUncapturedProbeWithCORSObservations(t *testing.T) {
	doc := validReportDocument(t)
	doc.ScanConfig.CORSProbeEnabled = true
	doc.CORSProbe = &ProbeSummary{Attempts: []ProbeAttemptSummary{
		{Kind: "first_get", Origin: "https://sentinelhttp-probe-a.invalid", State: "not_run", CORS: CORSSummary{Capture: "capture_complete"}},
		{Kind: "second_get", Origin: "https://sentinelhttp-probe-b.invalid", State: "not_run"},
		{Kind: "preflight", Origin: "https://sentinelhttp-probe-a.invalid", State: "not_run"},
	}}
	if err := Validate(doc); err == nil {
		t.Fatal("uncaptured probe accepted captured CORS data")
	}
}

func TestBuildAcceptsAvailableScoreWithUnassessedHeaderFinding(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Content-Type-Options", "invalid")
		w.WriteHeader(http.StatusOK)
	}))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	server.StartTLS()
	defer server.Close()
	target, err := network.ParseTarget(strings.Replace(server.URL, "127.0.0.1", "localhost", 1) + "/")
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := network.NewBoundary(target, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second, LabCAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), target, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at, Primary: response})
	if err != nil {
		t.Fatalf("Build rejected valid unassessed-domain finding: %v", err)
	}
	if doc.Score.Status != scoring.ScoreAvailable || doc.Score.Components[1].Status != scoring.ComponentUnavailable {
		t.Fatalf("expected available score with unavailable headers: %+v", doc.Score)
	}
	for _, finding := range doc.Findings {
		if finding.RuleID == "headers.hsts_not_active" {
			if len(doc.Score.Components[1].Penalties) != 0 {
				t.Fatal("unassessed header domain was penalized")
			}
			return
		}
	}
	t.Fatal("missing HSTS finding")
}

func TestValidateRejectsContradictoryRequestBudget(t *testing.T) {
	base := validReportDocument(t)
	base.ScanConfig.TraceEnabled = true
	base.ScanConfig.MaxRedirects = 20
	base.ScanConfig.MaxRequests = 1
	if err := Validate(base); err == nil {
		t.Fatal("declared budget below worst-case redirect cost was accepted")
	}

	base = validReportDocument(t)
	base.ScanConfig.MaxRequests = 2
	for i, id := range []string{strings.Repeat("b", 32), strings.Repeat("c", 32)} {
		copy := base.Requests[0]
		copy.ID = id
		copy.DurationMillis = int64(i)
		base.Requests = append(base.Requests, copy)
	}
	if err := Validate(base); err == nil {
		t.Fatal("observed request count above declared budget was accepted")
	}
}
