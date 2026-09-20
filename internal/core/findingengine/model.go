// Package findingengine converts selected captured evidence into conservative,
// bounded findings without network or filesystem I/O.
package findingengine

import (
	"fmt"

	"sentinelhttp/internal/core/httpclient"
)

const EngineVersion = "1"

type Input struct {
	Exchanges []*httpclient.Response
	Trace     *httpclient.RedirectTrace
	CORSProbe *httpclient.CORSProbeResult
}

type Category string

const (
	CategoryTLS       Category = "tls"
	CategoryHeaders   Category = "headers"
	CategoryCookies   Category = "cookies"
	CategoryCSP       Category = "csp"
	CategoryCORS      Category = "cors"
	CategoryRedirects Category = "redirects"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

type EvidenceSource string

const (
	TLSEvidence       EvidenceSource = "tls_analysis"
	HeaderEvidence    EvidenceSource = "header_analysis"
	CookieEvidence    EvidenceSource = "cookie_analysis"
	CSPEvidence       EvidenceSource = "csp_analysis"
	CORSProbeEvidence EvidenceSource = "cors_probe"
	RedirectEvidence  EvidenceSource = "redirect_trace"
)

type EvidenceRef struct {
	ExchangeID string         `json:"exchange_id"`
	Source     EvidenceSource `json:"source"`
	Code       string         `json:"code"`
	HopIndex   int            `json:"hop_index"`
	ItemIndex  int            `json:"item_index"`
}

type Finding struct {
	FindingID   string        `json:"finding_id"`
	RuleID      string        `json:"rule_id"`
	RuleVersion string        `json:"rule_version"`
	Category    Category      `json:"category"`
	Severity    Severity      `json:"severity"`
	Confidence  Confidence    `json:"confidence"`
	Target      string        `json:"target"`
	Evidence    []EvidenceRef `json:"evidence"`
	Observation string        `json:"observation"`
	Inference   string        `json:"inference"`
	Hypothesis  string        `json:"hypothesis"`
	Impact      string        `json:"impact"`
	Remediation string        `json:"remediation"`
	References  []string      `json:"references"`
	Limitations []string      `json:"limitations"`
}

func (f Finding) String() string {
	return fmt.Sprintf("finding %s at %s: severity=%s confidence=%s", f.RuleID, f.Target, f.Severity, f.Confidence)
}

func (f Finding) GoString() string { return f.String() }

type Report struct {
	EngineVersion   string    `json:"engine_version"`
	Findings        []Finding `json:"findings"`
	OmittedInputs   int       `json:"omitted_inputs"`
	OmittedFindings int       `json:"omitted_findings"`
	OmittedEvidence int       `json:"omitted_evidence"`
	SkippedInputs   int       `json:"skipped_inputs"`
	Truncated       bool      `json:"truncated"`
}

func (r Report) String() string {
	return fmt.Sprintf("finding report: findings=%d omitted_inputs=%d omitted_findings=%d omitted_evidence=%d skipped_inputs=%d truncated=%t", len(r.Findings), r.OmittedInputs, r.OmittedFindings, r.OmittedEvidence, r.SkippedInputs, r.Truncated)
}

func (r Report) GoString() string { return r.String() }
