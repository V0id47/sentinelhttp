// Package corsanalysis records bounded CORS response evidence without network I/O.
package corsanalysis

import (
	"fmt"
	"strings"
)

type CaptureStatus string

const (
	CaptureUnavailable CaptureStatus = "capture_unavailable"
	CaptureComplete    CaptureStatus = "capture_complete"
)

type FieldStatus string

const (
	FieldAbsent    FieldStatus = "absent"
	FieldValid     FieldStatus = "valid"
	FieldInvalid   FieldStatus = "invalid"
	FieldAmbiguous FieldStatus = "ambiguous"
	FieldTruncated FieldStatus = "truncated"
)

type OriginKind string

const (
	OriginUnknown  OriginKind = "unknown"
	OriginWildcard OriginKind = "wildcard"
	OriginNull     OriginKind = "null"
	OriginExplicit OriginKind = "explicit"
)

type Input struct {
	Captured   bool
	StatusCode int
	Headers    map[string][]string
}

type OriginField struct {
	Status      FieldStatus
	Occurrences int
	Kind        OriginKind
	Value       string // Untrusted, bounded, owned serialized origin when valid.
}

type CredentialsField struct {
	Status      FieldStatus
	Occurrences int
	Enabled     bool
}

type VaryField struct {
	Status      FieldStatus
	Occurrences int
	Origin      bool
	Star        bool
}

type TokenListField struct {
	Status      FieldStatus
	Occurrences int
	Tokens      []string
	Wildcard    bool
}

type MaxAgeField struct {
	Status      FieldStatus
	Occurrences int
	Seconds     uint64
}

type CacheField struct {
	Status      FieldStatus
	Occurrences int
	FreshShared bool
}

type Classification string

const (
	ObservationOnly  Classification = "observation"
	Misconfiguration Classification = "misconfiguration"
	PotentialRisk    Classification = "potential_risk"
)

type ObservationCode string

const (
	ReflectionForSamples        ObservationCode = "reflection_observed_for_samples"
	WildcardCredentialsMismatch ObservationCode = "wildcard_credentials_mismatch"
	VaryOriginMissing           ObservationCode = "vary_origin_missing"
)

type Observation struct {
	Code           ObservationCode
	Classification Classification
	Sample         ProbeKind
}

type Report struct {
	Capture       CaptureStatus
	StatusCode    int
	Origin        OriginField
	Credentials   CredentialsField
	Vary          VaryField
	AllowMethods  TokenListField
	AllowHeaders  TokenListField
	ExposeHeaders TokenListField
	MaxAge        MaxAgeField
	Cache         CacheField
	Observations  []Observation
	Truncated     bool
}

func (r Report) String() string {
	return fmt.Sprintf("CORS analysis: capture=%s origin=%s credentials=%s truncated=%t", r.Capture, r.Origin.Status, r.Credentials.Status, r.Truncated)
}

func (r Report) GoString() string { return r.String() }

func (r Report) Clone() Report {
	r.Origin.Value = strings.Clone(r.Origin.Value)
	r.AllowMethods.Tokens = append([]string(nil), r.AllowMethods.Tokens...)
	r.AllowHeaders.Tokens = append([]string(nil), r.AllowHeaders.Tokens...)
	r.ExposeHeaders.Tokens = append([]string(nil), r.ExposeHeaders.Tokens...)
	r.Observations = append([]Observation(nil), r.Observations...)
	return r
}
