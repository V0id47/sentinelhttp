package findingengine

import (
	"strings"

	"sentinelhttp/internal/core/cookieanalysis"
	"sentinelhttp/internal/core/cspanalysis"
	"sentinelhttp/internal/core/headeranalysis"
	"sentinelhttp/internal/core/httpclient"
)

func evaluateExchange(b *builder, response *httpclient.Response, meta httpclient.Metadata, hopIndex int) {
	if response == nil || meta.StatusCode == 0 {
		return
	}
	origin, id := meta.Target, meta.ID
	verifiedHTTPS := strings.HasPrefix(origin, "https://") && meta.TLS != nil && meta.TLS.Verified
	add := func(ruleID string, confidence Confidence, source EvidenceSource, code string, item int) {
		b.add(ruleID, origin, confidence, EvidenceRef{ExchangeID: id, Source: source, Code: code, HopIndex: hopIndex, ItemIndex: item})
	}

	headers := response.HeaderAnalysis()
	if headers.Capture == headeranalysis.CaptureComplete {
		if hsts, ok := headers.Result(headeranalysis.StrictTransportSecurity); ok && verifiedHTTPS && hsts.Applicability == headeranalysis.Applicable {
			switch {
			case hsts.Status == headeranalysis.StatusAbsent:
				add("headers.hsts_not_active", ConfidenceHigh, HeaderEvidence, "hsts_absent", -1)
			case hsts.Status == headeranalysis.StatusValid && hsts.Effective == "inactive":
				add("headers.hsts_not_active", ConfidenceHigh, HeaderEvidence, "hsts_inactive", -1)
			}
		}
		if headers.Context.ContentTypeStatus == headeranalysis.ContextValid && (headers.Context.Representation == headeranalysis.RepresentationHTML || headers.Context.Representation == headeranalysis.RepresentationJSON) {
			if xcto, ok := headers.Result(headeranalysis.XContentTypeOptions); ok && xcto.Status == headeranalysis.StatusAbsent {
				add("headers.nosniff_absent", ConfidenceHigh, HeaderEvidence, "nosniff_absent", -1)
			}
		}
	}

	cookies := response.CookieAnalysis()
	if verifiedHTTPS && cookies.Capture == cookieanalysis.CaptureComplete {
		for i, cookie := range cookies.Cookies {
			if cookie.Parse != cookieanalysis.ParseValid || cookie.Acceptance != cookieanalysis.Accepted || cookie.Truncated || cookie.IdentityRepeated || !cookie.SessionLike.Possible {
				continue
			}
			confidence := ConfidenceLow
			if cookie.SessionLike.Confidence == cookieanalysis.ConfidenceMedium {
				confidence = ConfidenceMedium
			}
			if cookie.Secure.Status == cookieanalysis.AttributeAbsent && !cookie.Secure.Enabled {
				add("cookies.session_like_no_secure", confidence, CookieEvidence, "secure_absent", i)
			}
			if cookie.HTTPOnly.Status == cookieanalysis.AttributeAbsent && !cookie.HTTPOnly.Enabled {
				add("cookies.session_like_no_httponly", confidence, CookieEvidence, "httponly_absent", i)
			}
		}
	}

	csp := response.CSPAnalysis()
	if csp.Capture == cspanalysis.CaptureComplete && csp.DocumentApplicability == cspanalysis.Applicable {
		for i, observation := range csp.Observations {
			switch observation.Code {
			case cspanalysis.EnforcementAbsent:
				if !csp.Enforced.Truncated {
					add("csp.no_complete_enforcement", ConfidenceHigh, CSPEvidence, "enforcement_absent", i)
				}
			case cspanalysis.UnsafeInlineEffective, cspanalysis.UnsafeEvalPresent:
				if observation.Disposition != cspanalysis.Enforce || !completeObservedPolicy(csp, observation) {
					continue
				}
				if observation.Code == cspanalysis.UnsafeInlineEffective {
					add("csp.unsafe_inline_observed", ConfidenceMedium, CSPEvidence, "unsafe_inline_effective", i)
				} else {
					add("csp.unsafe_eval_observed", ConfidenceMedium, CSPEvidence, "unsafe_eval_present", i)
				}
			}
		}
	}

	tls := response.TLSAnalysis()
	if verifiedHTTPS && tls.Status == "verified" && len(tls.Presented) > 0 && !tls.Presented[0].Truncated && tls.Presented[0].Validity == "expiring_soon" {
		add("tls.leaf_expiring_soon", ConfidenceHigh, TLSEvidence, "leaf_expiring_soon", 0)
	}
}

func completeObservedPolicy(report cspanalysis.Report, observation cspanalysis.Observation) bool {
	for _, policy := range report.Enforced.Policies {
		if policy.FieldIndex == observation.FieldIndex && policy.MemberIndex == observation.MemberIndex && !policy.Truncated {
			return true
		}
	}
	return false
}
