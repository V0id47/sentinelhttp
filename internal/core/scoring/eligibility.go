package scoring

import (
	"strings"

	"sentinelhttp/internal/core/cookieanalysis"
	"sentinelhttp/internal/core/cspanalysis"
	"sentinelhttp/internal/core/headeranalysis"
	"sentinelhttp/internal/core/httpclient"
)

func eligibility(response *httpclient.Response) [4]Component {
	components := newComponents()
	if response == nil {
		return components
	}
	meta := response.Metadata()
	verifiedHTTPS := strings.HasPrefix(meta.Target, "https://") && meta.TLS != nil && meta.TLS.Verified
	if !strings.HasPrefix(meta.Target, "https://") {
		components[0].Status = ComponentNotApplicable
	} else {
		tls := response.TLSAnalysis()
		if verifiedHTTPS && tls.Status == "verified" && len(tls.Presented) > 0 && !tls.Presented[0].Truncated {
			components[0].Status = ComponentAssessed
		}
	}

	headers := response.HeaderAnalysis()
	if headers.Capture == headeranalysis.CaptureComplete {
		knownContentContext := headers.Context.ContentTypeStatus == headeranalysis.ContextValid || headers.Context.Representation == headeranalysis.RepresentationRedirect || headers.Context.Representation == headeranalysis.RepresentationNoContent
		assessed, incomplete := false, !knownContentContext
		if hsts, ok := headers.Result(headeranalysis.StrictTransportSecurity); ok && hsts.Applicability == headeranalysis.Applicable && verifiedHTTPS {
			if hsts.Status == headeranalysis.StatusAbsent || hsts.Status == headeranalysis.StatusValid && !hsts.Truncated {
				assessed = true
			} else {
				incomplete = true
			}
		}
		if headers.Context.ContentTypeStatus == headeranalysis.ContextValid && (headers.Context.Representation == headeranalysis.RepresentationHTML || headers.Context.Representation == headeranalysis.RepresentationJSON) {
			if xcto, ok := headers.Result(headeranalysis.XContentTypeOptions); ok {
				if xcto.Status == headeranalysis.StatusAbsent || xcto.Status == headeranalysis.StatusValid && !xcto.Truncated {
					assessed = true
				} else {
					incomplete = true
				}
			} else {
				incomplete = true
			}
		}
		if !incomplete {
			if assessed {
				components[1].Status = ComponentAssessed
			} else if headers.Context.ContentTypeStatus == headeranalysis.ContextValid || headers.Context.Representation == headeranalysis.RepresentationRedirect || headers.Context.Representation == headeranalysis.RepresentationNoContent {
				components[1].Status = ComponentNotApplicable
			}
		}
	}

	cookies := response.CookieAnalysis()
	if cookies.Capture == cookieanalysis.CaptureComplete && !cookies.Truncated {
		components[2].Status = ComponentNotApplicable
		if verifiedHTTPS {
			for _, cookie := range cookies.Cookies {
				if cookie.Parse == cookieanalysis.ParseValid && cookie.Acceptance == cookieanalysis.Accepted && !cookie.Truncated && !cookie.IdentityRepeated && cookie.SessionLike.Possible {
					components[2].Status = ComponentAssessed
					break
				}
			}
		}
	}

	csp := response.CSPAnalysis()
	if csp.DocumentApplicability == cspanalysis.NotApplicable {
		components[3].Status = ComponentNotApplicable
	} else if csp.Capture == cspanalysis.CaptureComplete && csp.DocumentApplicability == cspanalysis.Applicable && !csp.Truncated && !csp.Enforced.Truncated {
		components[3].Status = ComponentAssessed
	}
	return components
}
