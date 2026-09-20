package corsanalysis

const (
	ProbeOriginA = "https://sentinelhttp-probe-a.invalid"
	ProbeOriginB = "https://sentinelhttp-probe-b.invalid"
)

type ProbeKind string

const (
	FirstGET  ProbeKind = "first_get"
	SecondGET ProbeKind = "second_get"
	Preflight ProbeKind = "preflight"
)

type ProbeSample struct {
	Kind       ProbeKind
	Origin     string
	Captured   bool
	StatusCode int
	Report     Report
}

type ReflectionStatus string

const (
	ReflectionIndeterminate ReflectionStatus = "indeterminate"
	ReflectionObserved      ReflectionStatus = "reflection_observed_for_samples"
	ReflectionNotObserved   ReflectionStatus = "not_observed_for_samples"
)

type PreflightStatus string

const (
	PreflightIndeterminate      PreflightStatus = "indeterminate"
	PreflightConsistent         PreflightStatus = "consistent_with_allowance"
	PreflightNotObservedAllowed PreflightStatus = "not_observed_allowed"
)

type ProbeAssessment struct {
	Reflection   ReflectionStatus
	Preflight    PreflightStatus
	Observations []Observation
}

func (a ProbeAssessment) Clone() ProbeAssessment {
	a.Observations = append([]Observation(nil), a.Observations...)
	return a
}

func AssessProbes(samples []ProbeSample) ProbeAssessment {
	result := ProbeAssessment{Reflection: ReflectionIndeterminate, Preflight: PreflightIndeterminate}
	var first, second, preflight *ProbeSample
	duplicate := false
	for i := range samples {
		s := &samples[i]
		switch s.Kind {
		case FirstGET:
			if first != nil {
				duplicate = true
			}
			first = s
		case SecondGET:
			if second != nil {
				duplicate = true
			}
			second = s
		case Preflight:
			if preflight != nil {
				duplicate = true
			}
			preflight = s
		default:
			duplicate = true
		}
	}
	if duplicate {
		return result
	}
	for _, s := range []*ProbeSample{first, second, preflight} {
		if validCapturedSample(s) && s.Report.Origin.Status == FieldValid && s.Report.Origin.Kind == OriginWildcard && s.Report.Credentials.Enabled {
			result.Observations = append(result.Observations, Observation{Code: WildcardCredentialsMismatch, Classification: Misconfiguration, Sample: s.Kind})
		}
	}
	if validGET(first, FirstGET, ProbeOriginA) && validGET(second, SecondGET, ProbeOriginB) {
		a, b := first.Report.Origin, second.Report.Origin
		if completeOrigin(a) && completeOrigin(b) {
			result.Reflection = ReflectionNotObserved
			if a.Kind == OriginExplicit && a.Value == ProbeOriginA && b.Kind == OriginExplicit && b.Value == ProbeOriginB {
				result.Reflection = ReflectionObserved
				level := ObservationOnly
				if first.Report.Credentials.Enabled && second.Report.Credentials.Enabled {
					level = PotentialRisk
				}
				result.Observations = append(result.Observations, Observation{Code: ReflectionForSamples, Classification: level})
			}
			if originSignature(a) != originSignature(b) {
				for _, s := range []*ProbeSample{first, second} {
					v := s.Report.Vary
					if v.Status != FieldAbsent && v.Status != FieldValid || v.Origin || v.Star {
						continue
					}
					level := ObservationOnly
					if s.Report.Cache.FreshShared {
						level = PotentialRisk
					}
					result.Observations = append(result.Observations, Observation{Code: VaryOriginMissing, Classification: level, Sample: s.Kind})
				}
			}
		}
	}
	result.Preflight = assessPreflight(preflight)
	return result
}

func validCapturedSample(s *ProbeSample) bool {
	return s != nil && s.Captured && s.Report.Capture == CaptureComplete && s.StatusCode == s.Report.StatusCode
}

func validGET(s *ProbeSample, kind ProbeKind, origin string) bool {
	return validCapturedSample(s) && s.Kind == kind && s.Origin == origin && (s.StatusCode < 300 || s.StatusCode > 399)
}

func completeOrigin(origin OriginField) bool {
	return origin.Status == FieldValid || origin.Status == FieldAbsent
}

func originSignature(origin OriginField) string {
	if origin.Status == FieldAbsent {
		return "absent"
	}
	return string(origin.Kind) + ":" + origin.Value
}

func assessPreflight(s *ProbeSample) PreflightStatus {
	if !validCapturedSample(s) || s.Kind != Preflight || s.Origin != ProbeOriginA || isRedirectStatus(s.StatusCode) {
		return PreflightIndeterminate
	}
	if s.StatusCode < 200 || s.StatusCode > 299 {
		return PreflightNotObservedAllowed
	}
	// Fetch extracts both method and header-name lists before deciding whether a
	// safelisted GET needs explicit method allowance. A malformed method list
	// fails that extraction even when GET itself is safelisted.
	m := s.Report.AllowMethods
	if m.Status != FieldAbsent && m.Status != FieldValid {
		return PreflightIndeterminate
	}
	a := s.Report.Origin
	if a.Status != FieldAbsent && a.Status != FieldValid {
		return PreflightIndeterminate
	}
	if a.Status == FieldAbsent || a.Kind != OriginWildcard && (a.Kind != OriginExplicit || a.Value != ProbeOriginA) {
		return PreflightNotObservedAllowed
	}
	h := s.Report.AllowHeaders
	if h.Status != FieldAbsent && h.Status != FieldValid {
		return PreflightIndeterminate
	}
	if h.Status == FieldAbsent {
		return PreflightNotObservedAllowed
	}
	if h.Wildcard {
		return PreflightConsistent
	}
	for _, token := range h.Tokens {
		if token == "x-sentinelhttp-probe" {
			return PreflightConsistent
		}
	}
	return PreflightNotObservedAllowed
}

func isRedirectStatus(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}
