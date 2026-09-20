package httpclient

import (
	"context"

	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/network"
)

type ProbeState string

const (
	ProbeNotRun   ProbeState = "not_run"
	ProbeCaptured ProbeState = "captured"
	ProbeFailed   ProbeState = "failed"
)

type CORSProbeAttempt struct {
	Kind     corsanalysis.ProbeKind
	Origin   string
	State    ProbeState
	Code     Code
	Metadata Metadata
	Report   corsanalysis.Report
}

type CORSProbeResult struct {
	Attempts   [3]CORSProbeAttempt
	Assessment corsanalysis.ProbeAssessment
}

// ProbeCORS is an explicit opt-in operation. It uses one deadline and at most
// three separate approved connections to the supplied target. No response body
// is retained, and redirects are never followed.
func (c *Client) ProbeCORS(ctx context.Context, target network.Target) (*CORSProbeResult, error) {
	result := &CORSProbeResult{Attempts: [3]CORSProbeAttempt{
		{Kind: corsanalysis.FirstGET, Origin: corsanalysis.ProbeOriginA, State: ProbeNotRun},
		{Kind: corsanalysis.SecondGET, Origin: corsanalysis.ProbeOriginB, State: ProbeNotRun},
		{Kind: corsanalysis.Preflight, Origin: corsanalysis.ProbeOriginA, State: ProbeNotRun},
	}}
	if c == nil || c.boundary == nil || ctx == nil {
		return result, fault(ConfigInvalid)
	}
	batch, cancel := context.WithTimeout(ctx, c.config.TotalTimeout)
	defer cancel()
	samples := make([]corsanalysis.ProbeSample, 0, 3)
	for i := range result.Attempts {
		attempt := &result.Attempts[i]
		method := GET
		if attempt.Kind == corsanalysis.Preflight {
			method = OPTIONS
		}
		response, err := c.do(batch, target, method, exchangeProfile{probe: attempt.Kind, headersOnly: true})
		attempt.Code = ErrorCode(err)
		attempt.Metadata = response.Metadata()
		attempt.Report = response.CORSAnalysis()
		if attempt.Report.Capture == corsanalysis.CaptureComplete {
			attempt.State = ProbeCaptured
			samples = append(samples, corsanalysis.ProbeSample{
				Kind: attempt.Kind, Origin: attempt.Origin, Captured: true,
				StatusCode: attempt.Metadata.StatusCode, Report: attempt.Report.Clone(),
			})
		} else {
			attempt.State = ProbeFailed
		}
		if err != nil {
			result.Assessment = corsanalysis.AssessProbes(samples)
			return result, err
		}
	}
	result.Assessment = corsanalysis.AssessProbes(samples)
	return result, nil
}
