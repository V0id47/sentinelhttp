package findingengine

import (
	"sentinelhttp/internal/core/corsanalysis"
	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/redirectanalysis"
)

func evaluateCORS(b *builder, probe *httpclient.CORSProbeResult, report *Report) {
	if b == nil || probe == nil || report == nil {
		return
	}
	var samples []corsanalysis.ProbeSample
	var target string
	for i := 0; i < 2; i++ {
		attempt := probe.Attempts[i]
		kind := corsanalysis.FirstGET
		origin := corsanalysis.ProbeOriginA
		if i == 1 {
			kind = corsanalysis.SecondGET
			origin = corsanalysis.ProbeOriginB
		}
		if attempt.Kind != kind || attempt.Origin != origin {
			report.SkippedInputs++
			return
		}
		if attempt.State == httpclient.ProbeFailed || attempt.State == httpclient.ProbeNotRun {
			return
		}
		if attempt.State != httpclient.ProbeCaptured || attempt.Code != httpclient.OK || attempt.Metadata.Result != attempt.Code || attempt.Metadata.Method != httpclient.GET || attempt.Metadata.StatusCode < 200 || attempt.Metadata.StatusCode > 599 || attempt.Metadata.StatusCode >= 300 && attempt.Metadata.StatusCode <= 399 || attempt.Report.Capture != corsanalysis.CaptureComplete || attempt.Metadata.StatusCode != attempt.Report.StatusCode || !validExchangeID(attempt.Metadata.ID) || !safeOrigin(attempt.Metadata.Target) {
			report.SkippedInputs++
			return
		}
		clean, ok := relevantProbeReport(attempt.Report)
		if !ok {
			report.SkippedInputs++
			return
		}
		if target != "" && target != attempt.Metadata.Target {
			report.SkippedInputs++
			return
		}
		target = attempt.Metadata.Target
		samples = append(samples, corsanalysis.ProbeSample{Kind: kind, Origin: origin, Captured: true, StatusCode: attempt.Metadata.StatusCode, Report: clean})
	}
	// No Phase 11 rule consumes the optional preflight attempt. Excluding it also
	// avoids copying caller-owned token and observation slices into AssessProbes.
	assessment := corsanalysis.AssessProbes(samples)
	for _, observation := range assessment.Observations {
		if observation.Classification != corsanalysis.PotentialRisk {
			continue
		}
		switch observation.Code {
		case corsanalysis.ReflectionForSamples:
			for i := 0; i < 2; i++ {
				b.add("cors.sampled_reflection_with_credentials", target, ConfidenceLow, EvidenceRef{
					ExchangeID: probe.Attempts[i].Metadata.ID, Source: CORSProbeEvidence,
					Code: string(corsanalysis.ReflectionForSamples), HopIndex: -1, ItemIndex: i,
				})
			}
		case corsanalysis.VaryOriginMissing:
			index := -1
			if observation.Sample == corsanalysis.FirstGET {
				index = 0
			} else if observation.Sample == corsanalysis.SecondGET {
				index = 1
			}
			if index >= 0 {
				b.add("cors.vary_origin_shared_cache", target, ConfidenceLow, EvidenceRef{
					ExchangeID: probe.Attempts[index].Metadata.ID, Source: CORSProbeEvidence,
					Code: string(corsanalysis.VaryOriginMissing), HopIndex: -1, ItemIndex: index,
				})
			}
		}
	}
}

// Keep only bounded scalar fields used by the two GET risk predicates. A
// caller-owned report may contain arbitrarily large slices or stale values in
// fields marked absent/invalid; neither enters the comparison layer.
func relevantProbeReport(source corsanalysis.Report) (corsanalysis.Report, bool) {
	origin := source.Origin
	switch origin.Status {
	case corsanalysis.FieldAbsent:
		if origin.Kind != corsanalysis.OriginUnknown || origin.Value != "" {
			return corsanalysis.Report{}, false
		}
	case corsanalysis.FieldValid:
		switch origin.Kind {
		case corsanalysis.OriginExplicit:
			if len(origin.Value) > 512 || !corsanalysis.ValidSerializedOrigin(origin.Value) {
				return corsanalysis.Report{}, false
			}
		case corsanalysis.OriginWildcard, corsanalysis.OriginNull:
			if origin.Value != "" {
				return corsanalysis.Report{}, false
			}
		default:
			return corsanalysis.Report{}, false
		}
	default:
		return corsanalysis.Report{}, false
	}
	credentials := source.Credentials
	if credentials.Enabled && credentials.Status != corsanalysis.FieldValid {
		return corsanalysis.Report{}, false
	}
	cache := source.Cache
	if cache.FreshShared && cache.Status != corsanalysis.FieldValid {
		return corsanalysis.Report{}, false
	}
	vary := source.Vary
	if vary.Status == corsanalysis.FieldAbsent && (vary.Origin || vary.Star) {
		return corsanalysis.Report{}, false
	}
	return corsanalysis.Report{
		Capture: source.Capture, StatusCode: source.StatusCode,
		Origin: origin, Credentials: credentials, Vary: vary, Cache: cache,
	}, true
}

func evaluateTrace(b *builder, trace *httpclient.RedirectTrace, report *Report) {
	if b == nil || trace == nil || report == nil || len(trace.Hops) == 0 || len(trace.Hops) > maxTraceHops {
		return
	}
	switch trace.Stop {
	case httpclient.RedirectDowngradeBlocked, httpclient.RedirectLoop, httpclient.RedirectLimit:
	default:
		return
	}
	lastIndex := len(trace.Hops) - 1
	hop := trace.Hops[lastIndex]
	if hop.Response == nil || hop.LocationStatus != redirectanalysis.LocationValid || hop.NextTarget.RequestURL() == "" {
		report.SkippedInputs++
		return
	}
	meta := hop.Response.Metadata()
	if !validExchangeID(meta.ID) || !safeOrigin(meta.Target) || meta.Target != hop.Target.SafeURL() || !redirectanalysis.IsFollowStatus(meta.StatusCode) {
		report.SkippedInputs++
		return
	}
	location, state := redirectanalysis.ResolveLocation(hop.Target.RequestURL(), hop.Response.HeaderValues("Location"))
	if state != redirectanalysis.LocationValid {
		report.SkippedInputs++
		return
	}
	resolved, err := network.ParseTarget(location)
	if err != nil || resolved.RequestURL() != hop.NextTarget.RequestURL() {
		report.SkippedInputs++
		return
	}
	ref := EvidenceRef{ExchangeID: meta.ID, Source: RedirectEvidence, HopIndex: lastIndex, ItemIndex: -1}
	switch trace.Stop {
	case httpclient.RedirectDowngradeBlocked:
		if hop.Target.Scheme() != "https" || hop.NextTarget.Scheme() != "http" {
			report.SkippedInputs++
			return
		}
		ref.Code = string(httpclient.RedirectDowngradeBlocked)
		b.add("redirects.https_to_http_proposed", meta.Target, ConfidenceHigh, ref)
	case httpclient.RedirectLoop, httpclient.RedirectLimit:
		if trace.Stop == httpclient.RedirectLoop {
			seen := false
			for _, earlier := range trace.Hops {
				if earlier.Target.RequestURL() == resolved.RequestURL() {
					seen = true
					break
				}
			}
			if !seen {
				report.SkippedInputs++
				return
			}
		}
		ref.Code = string(trace.Stop)
		b.add("redirects.loop_or_limit", meta.Target, ConfidenceHigh, ref)
	}
}
