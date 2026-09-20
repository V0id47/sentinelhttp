package reporting

import (
	"errors"
	"net/url"

	"sentinelhttp/internal/core/findingengine"
	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/scoring"
)

var ErrInvalidInput = errors.New("report_input_invalid")
var ErrReportLimit = errors.New("report_limit_exceeded")

var standardLimitations = [...]string{
	"SentinelHTTP reports observations from performed checks. Absence of findings does not prove an application is secure.",
	"The report does not demonstrate exploitability, authenticated exposure or complete site coverage.",
	"Network, HTTP, TLS and browser behavior outside the captured operations was not assessed.",
}

// Build assembles an owned report from already captured evidence. It neither
// performs I/O nor reads the clock.
func Build(input Input) (Document, error) {
	if input.InitialTarget.RequestURL() == "" || input.StartedAt.IsZero() || input.CompletedAt.IsZero() || input.CompletedAt.Before(input.StartedAt) || input.Trace != nil && len(input.Trace.Hops) > 21 {
		return Document{}, ErrInvalidInput
	}
	if input.Config.MaxRedirects < 0 || input.Config.MaxRedirects > 20 || input.Config.MaxRequests < 0 || input.Config.MaxRequests > 24 || input.Config.TimeoutMillis < 0 || input.Config.ConnectTimeoutMillis < 0 || input.Config.ConnectTimeoutMillis > 10000 || input.Config.MaxResponseBytes < 0 || input.Config.CORSProbeEnabled != (input.CORSProbe != nil) || !validBudgetConfig(input.Config) {
		return Document{}, ErrInvalidInput
	}
	doc := Document{
		SchemaVersion: SchemaVersion, Tool: Tool, ToolVersion: ToolVersion,
		StartedAt: input.StartedAt.UTC(), CompletedAt: input.CompletedAt.UTC(),
		Target: input.InitialTarget.SafeURL(), ScanConfig: input.Config,
		Requests: []RequestSummary{}, Redirects: []RedirectSummary{},
		Findings: []findingengine.Finding{}, Score: scoring.Evaluate(input.Primary),
		Limitations: append([]string(nil), standardLimitations[:]...),
	}
	requestURL, err := url.Parse(input.InitialTarget.RequestURL())
	if err != nil {
		return Document{}, ErrInvalidInput
	}
	doc.TargetScope = "redacted"
	if requestURL.EscapedPath() == "/" && requestURL.RawQuery == "" && !requestURL.ForceQuery {
		doc.TargetScope = "root"
	}
	seen := make(map[string]*httpclient.Response)
	responses := make([]*httpclient.Response, 0, 32)
	add := func(response *httpclient.Response) error {
		if response == nil {
			return ErrInvalidInput
		}
		meta := response.Metadata()
		if !validReportID(meta.ID) || !safeReportOrigin(meta.Target) {
			return ErrInvalidInput
		}
		if previous, exists := seen[meta.ID]; exists {
			if previous != response {
				return ErrInvalidInput
			}
			return nil
		}
		if len(responses) >= 32 {
			return ErrReportLimit
		}
		seen[meta.ID] = response
		responses = append(responses, response)
		return nil
	}
	if input.Primary != nil {
		if err := add(input.Primary); err != nil {
			return Document{}, err
		}
		doc.FinalTarget = input.Primary.Metadata().Target
		doc.PrimaryRequestID = input.Primary.Metadata().ID
	}
	for _, response := range input.Exchanges {
		if err := add(response); err != nil {
			return Document{}, err
		}
	}
	if input.Trace != nil {
		doc.RedirectStop = string(input.Trace.Stop)
		for i, hop := range input.Trace.Hops {
			if hop.Target.RequestURL() == "" {
				return Document{}, ErrInvalidInput
			}
			if i == 0 && hop.Target.RequestURL() != input.InitialTarget.RequestURL() || i > 0 && input.Trace.Hops[i-1].NextTarget.RequestURL() != hop.Target.RequestURL() {
				return Document{}, ErrInvalidInput
			}
			summary := RedirectSummary{HopIndex: i, Target: hop.Target.SafeURL(), LocationStatus: string(hop.LocationStatus)}
			if hop.NextTarget.RequestURL() != "" {
				summary.NextTarget = hop.NextTarget.SafeURL()
			}
			if hop.Response != nil {
				if err := add(hop.Response); err != nil {
					return Document{}, err
				}
				meta := hop.Response.Metadata()
				if meta.Target != summary.Target {
					return Document{}, ErrInvalidInput
				}
				summary.ResponseID, summary.StatusCode = meta.ID, meta.StatusCode
			}
			doc.Redirects = append(doc.Redirects, summary)
		}
	}
	allowedTargets := map[string]bool{doc.Target: true}
	for _, hop := range doc.Redirects {
		allowedTargets[hop.Target] = true
	}
	for _, response := range responses {
		if !allowedTargets[response.Metadata().Target] {
			return Document{}, ErrInvalidInput
		}
		doc.Requests = append(doc.Requests, projectResponse(response))
	}
	sortRequests(doc.Requests)
	if input.CORSProbe != nil {
		probe, err := projectProbe(input.CORSProbe)
		if err != nil {
			return Document{}, err
		}
		probeTarget := doc.FinalTarget
		if probeTarget == "" {
			probeTarget = doc.Target
		}
		for _, attempt := range probe.Attempts {
			if attempt.State == string(httpclient.ProbeCaptured) && attempt.Target != probeTarget {
				return Document{}, ErrInvalidInput
			}
		}
		doc.CORSProbe = &probe
	}
	findings := findingengine.Evaluate(findingengine.Input{Exchanges: responses, Trace: input.Trace, CORSProbe: input.CORSProbe})
	if findings.SkippedInputs != 0 {
		return Document{}, ErrInvalidInput
	}
	doc.Findings = append(doc.Findings, findings.Findings...)
	doc.Truncated = findings.Truncated || anyEvidenceTruncated(doc.Requests)
	doc.OmittedInputs, doc.OmittedFindings, doc.OmittedEvidence, doc.SkippedInputs = findings.OmittedInputs, findings.OmittedFindings, findings.OmittedEvidence, findings.SkippedInputs
	if err := Validate(doc); err != nil {
		if errors.Is(err, ErrReportLimit) {
			return Document{}, ErrReportLimit
		}
		return Document{}, ErrInvalidInput
	}
	return doc, nil
}

func anyEvidenceTruncated(requests []RequestSummary) bool {
	for _, request := range requests {
		if request.TLS.Truncated || request.CookieTruncated || request.CSP.Truncated || request.CORS.Truncated {
			return true
		}
		for _, cert := range request.TLS.Certificates {
			if cert.Truncated {
				return true
			}
		}
		for _, header := range request.Headers {
			if header.Truncated {
				return true
			}
		}
	}
	return false
}

func validReportID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func safeReportOrigin(value string) bool {
	target, err := network.ParseTarget(value)
	return err == nil && target.SafeURL() == value
}
