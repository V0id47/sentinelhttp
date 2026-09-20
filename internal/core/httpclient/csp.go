package httpclient

import (
	"sentinelhttp/internal/core/cspanalysis"
	"sentinelhttp/internal/core/headeranalysis"
)

func cspApplicability(context headeranalysis.ResponseContext) cspanalysis.Applicability {
	switch context.Representation {
	case headeranalysis.RepresentationHTML:
		return cspanalysis.Applicable
	case headeranalysis.RepresentationRedirect, headeranalysis.RepresentationNoContent:
		return cspanalysis.NotApplicable
	default:
		return cspanalysis.ApplicabilityUnknown
	}
}

func cspXFOEvidence(report headeranalysis.Report) cspanalysis.XFOEvidence {
	result, ok := report.Result(headeranalysis.XFrameOptions)
	if !ok {
		return cspanalysis.XFOEvidence{}
	}
	return cspanalysis.XFOEvidence{
		Present:   result.Occurrences > 0,
		Valid:     result.Status == headeranalysis.StatusValid,
		Effective: result.Effective,
	}
}
