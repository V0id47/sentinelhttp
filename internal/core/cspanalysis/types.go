// Package cspanalysis parses bounded HTTP Content Security Policy evidence.
// It is deterministic and performs no I/O.
package cspanalysis

import "fmt"

// CSPLevel3EditorDraft identifies the normative CSP snapshot used by this package.
const CSPLevel3EditorDraft = "W3C Content Security Policy Level 3 Editor's Draft 2026-09-16"

type CaptureStatus string

const (
	CaptureUnavailable CaptureStatus = "capture_unavailable"
	CaptureComplete    CaptureStatus = "capture_complete"
)

type Applicability string

const (
	Applicable           Applicability = "applicable"
	NotApplicable        Applicability = "not_applicable"
	ApplicabilityUnknown Applicability = "unknown"
)

type Disposition string

const (
	Enforce    Disposition = "enforce"
	ReportOnly Disposition = "report_only"
)

type ParseStatus string

const (
	ParseValid     ParseStatus = "valid"
	ParsePartial   ParseStatus = "partial"
	ParseInvalid   ParseStatus = "invalid"
	ParseTruncated ParseStatus = "truncated"
)

type DirectiveStatus string

const (
	DirectiveValid        DirectiveStatus = "valid"
	DirectivePartial      DirectiveStatus = "partial"
	DirectiveInvalid      DirectiveStatus = "invalid"
	DirectiveTruncated    DirectiveStatus = "truncated"
	DirectiveUnrecognized DirectiveStatus = "unrecognized"
)

type DirectiveKind string

const (
	DirectiveSourceList DirectiveKind = "source_list"
	DirectiveOpaque     DirectiveKind = "opaque"
)

type SourceKind string

const (
	SourceKeyword  SourceKind = "keyword"
	SourceScheme   SourceKind = "scheme"
	SourceHost     SourceKind = "host"
	SourceWildcard SourceKind = "wildcard"
	SourceNonce    SourceKind = "nonce"
	SourceHash     SourceKind = "hash"
	SourceInvalid  SourceKind = "invalid"
)

type EffectiveStatus string

const (
	EffectiveExplicit      EffectiveStatus = "explicit"
	EffectiveFallback      EffectiveStatus = "fallback"
	EffectiveUnrestricted  EffectiveStatus = "unrestricted"
	EffectiveIndeterminate EffectiveStatus = "indeterminate"
)

type ObservationCode string

const (
	EnforcementAbsent            ObservationCode = "enforcement_absent"
	ReportOnlyWithoutEnforcement ObservationCode = "report_only_without_enforcement"
	DuplicateDirectiveIgnored    ObservationCode = "duplicate_directive_ignored"
	SourceListNonconforming      ObservationCode = "source_list_nonconforming"
	UnsafeInlineEffective        ObservationCode = "unsafe_inline_effective"
	UnsafeEvalPresent            ObservationCode = "unsafe_eval_present"
	GeneralWildcardPresent       ObservationCode = "general_wildcard_present"
	ObjectSourcesPermitted       ObservationCode = "object_sources_permitted"
	ObjectControlAbsent          ObservationCode = "object_control_absent"
	BaseURIControlAbsent         ObservationCode = "base_uri_control_absent"
	FrameAncestorsControlAbsent  ObservationCode = "frame_ancestors_control_absent"
	FormActionControlAbsent      ObservationCode = "form_action_control_absent"
)

type FramingRelation string

const (
	CSPOverridesXFO          FramingRelation = "csp_overrides_xfo"
	XFOFallbackObserved      FramingRelation = "xfo_fallback_observed"
	NoObservedFramingControl FramingRelation = "no_observed_framing_control"
	FramingIndeterminate     FramingRelation = "indeterminate"
)

type Input struct {
	Captured              bool
	DocumentApplicability Applicability
	EnforcedFields        []string
	ReportOnlyFields      []string
	XFrameOptions         XFOEvidence
}

type XFOEvidence struct {
	Present   bool
	Valid     bool
	Effective string
}

type Report struct {
	Capture               CaptureStatus
	DocumentApplicability Applicability
	Enforced              PolicySet
	ReportOnly            PolicySet
	Observations          []Observation
	Framing               FramingAssessment
	Truncated             bool
}

type PolicySet struct {
	Disposition      Disposition
	FieldCount       int
	AnalyzedPolicies int
	OmittedPolicies  int
	Policies         []Policy
	Truncated        bool
}

type Policy struct {
	Disposition         Disposition
	FieldIndex          int
	MemberIndex         int
	Parse               ParseStatus
	Directives          []Directive
	EffectiveControls   []EffectiveControl
	SyntaxIssues        int
	Truncated           bool
	discardedDirectives []string
}

type Directive struct {
	Name              string
	Kind              DirectiveKind
	Status            DirectiveStatus
	Sources           []Source
	OpaqueTokens      int
	IgnoredDuplicates int
	Nonconforming     bool
}

// Source contains only the normalized components required for CSP evaluation.
// Nonce and hash payloads are never stored.
type Source struct {
	Kind              SourceKind
	Keyword           string
	Scheme            string
	Host              string
	Port              string
	Path              string
	Algorithm         string
	SubdomainWildcard bool
	Redacted          bool
	Valid             bool
}

type EffectiveControl struct {
	Control   string
	Directive string
	Status    EffectiveStatus
	Sources   []Source
}

type Observation struct {
	// Observation carries bounded parsed context only. It intentionally has no
	// impact, severity, remediation, or target-controlled policy text.
	Code        ObservationCode
	Disposition Disposition
	FieldIndex  int
	MemberIndex int
	Directive   string
	Control     string
}

type FramingAssessment struct {
	// Relation describes the observed CSP/XFO precedence only; it does not make
	// a clickjacking or browser-behavior claim.
	Relation          FramingRelation
	CSPFrameAncestors bool
	XFOPresent        bool
	XFOValid          bool
	XFOEffective      string
}

func (r Report) String() string {
	return fmt.Sprintf("CSP analysis: capture=%s enforced=%d report_only=%d truncated=%t", r.Capture, len(r.Enforced.Policies), len(r.ReportOnly.Policies), r.Truncated)
}

func (r Report) GoString() string { return r.String() }

func (r Report) Clone() Report {
	r.Enforced = r.Enforced.clone()
	r.ReportOnly = r.ReportOnly.clone()
	r.Observations = append([]Observation(nil), r.Observations...)
	return r
}

func (s PolicySet) clone() PolicySet {
	s.Policies = append([]Policy(nil), s.Policies...)
	for i := range s.Policies {
		s.Policies[i].discardedDirectives = append([]string(nil), s.Policies[i].discardedDirectives...)
		s.Policies[i].Directives = append([]Directive(nil), s.Policies[i].Directives...)
		for j := range s.Policies[i].Directives {
			s.Policies[i].Directives[j].Sources = append([]Source(nil), s.Policies[i].Directives[j].Sources...)
		}
		s.Policies[i].EffectiveControls = append([]EffectiveControl(nil), s.Policies[i].EffectiveControls...)
		for j := range s.Policies[i].EffectiveControls {
			s.Policies[i].EffectiveControls[j].Sources = append([]Source(nil), s.Policies[i].EffectiveControls[j].Sources...)
		}
	}
	return s
}
