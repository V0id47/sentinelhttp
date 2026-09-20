package reporting

import (
	"sort"
	"strings"

	"sentinelhttp/internal/core/cookieanalysis"
	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/cspanalysis"
	"sentinelhttp/internal/core/headeranalysis"
	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
)

func projectDecision(value network.Decision) DecisionSummary {
	return DecisionSummary{Allowed: value.Allowed, Reason: string(value.Reason), Class: string(value.Class)}
}

func projectResponse(response *httpclient.Response) RequestSummary {
	meta := response.Metadata()
	result := RequestSummary{
		ID: meta.ID, Target: meta.Target, Method: string(meta.Method),
		StatusCode: meta.StatusCode, Result: string(meta.Result), Protocol: meta.Protocol,
		DurationMillis: meta.Duration.Milliseconds(),
		Resolution: ResolutionSummary{
			Host: meta.Resolution.Host, Source: meta.Resolution.Source,
			PolicyVersion: meta.Resolution.PolicyVersion, Decision: projectDecision(meta.Resolution.Decision),
			Addresses: []AddressSummary{},
		},
		Peer:    PeerSummary{Verified: meta.Peer.Verified, Decision: string(meta.Peer.Decision)},
		Headers: []HeaderSummary{}, Cookies: []CookieSummary{},
	}
	if meta.Resolution.Chosen.IsValid() {
		result.Resolution.Chosen = meta.Resolution.Chosen.String()
	}
	for _, item := range meta.Resolution.Addresses {
		address := AddressSummary{Decision: projectDecision(item.Decision)}
		if item.Returned.IsValid() {
			address.Returned = item.Returned.String()
		}
		if item.Normalized.IsValid() {
			address.Normalized = item.Normalized.String()
		}
		result.Resolution.Addresses = append(result.Resolution.Addresses, address)
	}
	if meta.Peer.Expected.IsValid() {
		result.Peer.Expected = meta.Peer.Expected.String()
	}
	if meta.Peer.Observed.IsValid() {
		result.Peer.Observed = meta.Peer.Observed.String()
	}
	result.TLS = projectTLS(response)
	result.Headers = projectHeaders(response.HeaderAnalysis())
	cookies := response.CookieAnalysis()
	result.Cookies = projectCookies(cookies)
	result.CookieCapture = string(cookies.Capture)
	result.CookieFieldCount = cookies.FieldCount
	result.CookieAnalyzedFields = cookies.AnalyzedFields
	result.CookieOmittedFields = cookies.OmittedFields
	result.CookieTruncated = cookies.Truncated
	result.CSP = projectCSP(response.CSPAnalysis())
	result.CORS = projectCORS(response.CORSAnalysis())
	return result
}

func projectTLS(response *httpclient.Response) TLSSummary {
	source := response.TLSAnalysis()
	result := TLSSummary{Status: source.Status, Version: source.VersionName,
		CipherSuite: source.CipherSuiteName, NegotiatedProtocol: source.NegotiatedProtocol,
		Certificates: []CertificateSummary{}, Truncated: source.Truncated}
	for _, cert := range source.Presented {
		item := CertificateSummary{
			Subject: cert.Subject, Issuer: cert.Issuer, SHA256: cert.SHA256,
			NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
			DaysRemaining: cert.DaysRemaining, Validity: cert.Validity,
			SANs: []SANSummary{}, Truncated: cert.Truncated,
		}
		for _, san := range cert.SANs {
			value := san.Value
			if san.Kind != "dns" && san.Kind != "ip" {
				value = "[REDACTED]"
			}
			item.SANs = append(item.SANs, SANSummary{Kind: san.Kind, Value: value})
		}
		result.Certificates = append(result.Certificates, item)
	}
	return result
}

func projectHeaders(source headeranalysis.Report) []HeaderSummary {
	out := make([]HeaderSummary, 0, len(source.Results))
	for _, field := range source.Results {
		effective := ""
		switch field.ID {
		case headeranalysis.StrictTransportSecurity:
			if field.Effective == "active" || field.Effective == "inactive" {
				effective = field.Effective
			}
		case headeranalysis.XContentTypeOptions:
			if field.Effective == "nosniff" {
				effective = field.Effective
			}
		case headeranalysis.XFrameOptions:
			if field.Effective == "DENY" || field.Effective == "SAMEORIGIN" {
				effective = field.Effective
			}
		}
		out = append(out, HeaderSummary{ID: string(field.ID), Name: field.Name,
			Occurrences: field.Occurrences, Applicability: string(field.Applicability),
			Status: string(field.Status), Effective: effective, Truncated: field.Truncated})
	}
	return out
}

func projectCookies(source cookieanalysis.Report) []CookieSummary {
	out := make([]CookieSummary, 0, len(source.Cookies))
	for _, cookie := range source.Cookies {
		name := cookie.Name
		if len(name) > 256 {
			name = "[REDACTED]"
		}
		pathScope := "unknown"
		if cookie.Path.Effective == "/" {
			pathScope = "root"
		} else if cookie.Path.Effective != "" {
			pathScope = "scoped"
		}
		out = append(out, CookieSummary{
			Position: cookie.Position, Name: name, Parse: string(cookie.Parse),
			Acceptance: string(cookie.Acceptance), Secure: cookie.Secure.Enabled,
			SecureStatus: string(cookie.Secure.Status), HTTPOnly: cookie.HTTPOnly.Enabled,
			HTTPOnlyStatus: string(cookie.HTTPOnly.Status), SameSite: cookie.SameSite.Effective,
			Domain: cookie.Identity.EffectiveDomain, DomainHostOnly: cookie.Domain.HostOnly, PathScope: pathScope,
			SessionLike: cookie.SessionLike.Possible, IdentityRepeated: cookie.IdentityRepeated, Truncated: cookie.Truncated,
		})
	}
	return out
}

func projectCSP(source cspanalysis.Report) CSPSummary {
	result := CSPSummary{Capture: string(source.Capture), Applicability: string(source.DocumentApplicability),
		Policies: []CSPPolicySummary{}, Observations: []string{}, Truncated: source.Truncated}
	for _, set := range []cspanalysis.PolicySet{source.Enforced, source.ReportOnly} {
		for _, policy := range set.Policies {
			item := CSPPolicySummary{Disposition: string(policy.Disposition), FieldIndex: policy.FieldIndex,
				MemberIndex: policy.MemberIndex, Parse: string(policy.Parse),
				Directives: []CSPDirectiveSummary{}, Truncated: policy.Truncated}
			for _, directive := range policy.Directives {
				entry := CSPDirectiveSummary{Name: safeDirectiveName(directive.Name), Kind: string(directive.Kind), Status: string(directive.Status), Sources: []CSPSourceSummary{}}
				for _, parsed := range directive.Sources {
					entry.Sources = append(entry.Sources, CSPSourceSummary{
						Kind: string(parsed.Kind), Keyword: parsed.Keyword, Scheme: parsed.Scheme,
						Host: parsed.Host, Port: parsed.Port, SubdomainWildcard: parsed.SubdomainWildcard,
						Redacted: parsed.Redacted,
					})
				}
				item.Directives = append(item.Directives, entry)
			}
			result.Policies = append(result.Policies, item)
		}
	}
	for _, observation := range source.Observations {
		result.Observations = append(result.Observations, string(observation.Code))
	}
	return result
}

func projectCORS(source corsanalysis.Report) CORSSummary {
	result := CORSSummary{
		Capture: string(source.Capture), OriginStatus: string(source.Origin.Status),
		OriginKind: string(source.Origin.Kind), CredentialsStatus: string(source.Credentials.Status),
		CredentialsEnabled: source.Credentials.Enabled, VaryStatus: string(source.Vary.Status),
		VaryOrigin: source.Vary.Origin, CacheStatus: string(source.Cache.Status),
		CacheFreshShared: source.Cache.FreshShared, Observations: []string{}, Truncated: source.Truncated,
	}
	if source.Origin.Status == corsanalysis.FieldValid && source.Origin.Kind == corsanalysis.OriginExplicit {
		result.OriginValue = source.Origin.Value
	}
	for _, observation := range source.Observations {
		result.Observations = append(result.Observations, string(observation.Code))
	}
	return result
}

func projectProbe(probe *httpclient.CORSProbeResult) (ProbeSummary, error) {
	result := ProbeSummary{Attempts: make([]ProbeAttemptSummary, 0, 3)}
	for i, attempt := range probe.Attempts {
		kind := corsanalysis.FirstGET
		origin := corsanalysis.ProbeOriginA
		if i == 1 {
			kind, origin = corsanalysis.SecondGET, corsanalysis.ProbeOriginB
		} else if i == 2 {
			kind = corsanalysis.Preflight
		}
		if attempt.Kind != kind || attempt.Origin != origin || len(attempt.Report.Observations) > 64 || len(attempt.Report.Origin.Value) > 4096 {
			return ProbeSummary{}, ErrInvalidInput
		}
		item := ProbeAttemptSummary{Kind: string(kind), Origin: origin, State: string(attempt.State), Code: string(attempt.Code)}
		if attempt.State == httpclient.ProbeNotRun && attempt.Code != "" || attempt.State == httpclient.ProbeFailed && !validProbeFailureCode(string(attempt.Code)) {
			return ProbeSummary{}, ErrInvalidInput
		}
		if attempt.State == httpclient.ProbeCaptured {
			method := httpclient.GET
			if kind == corsanalysis.Preflight {
				method = httpclient.OPTIONS
			}
			if !validReportID(attempt.Metadata.ID) || !safeReportOrigin(attempt.Metadata.Target) ||
				attempt.Metadata.Method != method || attempt.Metadata.Result != httpclient.OK || attempt.Code != httpclient.OK ||
				attempt.Metadata.StatusCode != attempt.Report.StatusCode || attempt.Report.Capture != corsanalysis.CaptureComplete {
				return ProbeSummary{}, ErrInvalidInput
			}
			item.ID, item.StatusCode, item.Target, item.CORS = attempt.Metadata.ID, attempt.Metadata.StatusCode, attempt.Metadata.Target, projectCORS(attempt.Report)
		} else if attempt.State != httpclient.ProbeFailed && attempt.State != httpclient.ProbeNotRun {
			return ProbeSummary{}, ErrInvalidInput
		}
		result.Attempts = append(result.Attempts, item)
	}
	return result, nil
}

func sortRequests(requests []RequestSummary) {
	sort.Slice(requests, func(i, j int) bool { return strings.Compare(requests[i].ID, requests[j].ID) < 0 })
}
