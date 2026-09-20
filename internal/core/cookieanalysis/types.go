// Package cookieanalysis evaluates bounded Set-Cookie evidence without retaining
// cookie values. It is deterministic and performs no I/O.
package cookieanalysis

import (
	"fmt"
	"time"
)

type CaptureStatus string

const (
	CaptureUnavailable CaptureStatus = "capture_unavailable"
	CaptureComplete    CaptureStatus = "capture_complete"
)

type ParseStatus string

const (
	ParseValid     ParseStatus = "valid"
	ParseInvalid   ParseStatus = "invalid"
	ParseTruncated ParseStatus = "truncated"
)

type AttributeStatus string

const (
	AttributeAbsent    AttributeStatus = "absent"
	AttributeValid     AttributeStatus = "valid"
	AttributeInvalid   AttributeStatus = "invalid"
	AttributeDuplicate AttributeStatus = "duplicate"
	AttributeTruncated AttributeStatus = "truncated"
)

type AcceptanceStatus string

const (
	Accepted                AcceptanceStatus = "accepted"
	Rejected                AcceptanceStatus = "rejected"
	AcceptanceIndeterminate AcceptanceStatus = "indeterminate"
)

type PersistenceKind string

const (
	Session                  PersistenceKind = "session"
	Persistent               PersistenceKind = "persistent"
	Deletion                 PersistenceKind = "deletion"
	PersistenceIndeterminate PersistenceKind = "indeterminate"
)

type PrefixStatus string

const (
	PrefixNotApplicable PrefixStatus = "not_applicable"
	PrefixSatisfied     PrefixStatus = "satisfied"
	PrefixViolated      PrefixStatus = "violated"
	PrefixIndeterminate PrefixStatus = "indeterminate"
)

type Confidence string

const (
	ConfidenceNone   Confidence = "none"
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
)

const (
	ReasonSyntaxInvalid        = "cookie_syntax_invalid"
	ReasonDomainInvalid        = "domain_invalid"
	ReasonDomainMismatch       = "domain_mismatch"
	ReasonPublicSuffix         = "domain_is_public_suffix"
	ReasonSecureOriginRequired = "secure_origin_required"
	ReasonSameSiteNeedsSecure  = "samesite_none_requires_secure"
	ReasonPrefixRequirements   = "prefix_requirements_not_met"
	ReasonNameHeuristic        = "name_pattern"
	ReasonNonPersistent        = "non_persistent"
)

type Input struct {
	Captured        bool
	Scheme          string
	Host            string
	EmitterResource string
	RequestPath     string
	ObservedAt      time.Time
	Fields          []string
}

type Attribute struct {
	Status      AttributeStatus
	Occurrences int
	Effective   string
	Explicit    bool
	Sanitized   bool
}

type FlagAttribute struct {
	Status      AttributeStatus
	Occurrences int
	Enabled     bool
}

type TimeAttribute struct {
	Status           AttributeStatus
	Occurrences      int
	ValidOccurrences int
	Observed         time.Time
	Effective        time.Time
	Clamped          bool
}

type IntegerAttribute struct {
	Status           AttributeStatus
	Occurrences      int
	ValidOccurrences int
	ObservedSeconds  int64
	Seconds          int64
	Clamped          bool
}

type DomainAttribute struct {
	Attribute
	HostOnly          bool
	DomainMatch       bool
	PublicSuffix      string
	PublicSuffixICANN bool
}

type UnknownAttribute struct {
	Name        string
	Occurrences int
}

type Identity struct {
	EmitterResource string
	CookieName      string
	EffectiveDomain string
	EffectivePath   string
}

type PrefixEvaluation struct {
	Kind    string
	Status  PrefixStatus
	Reasons []string
}

type Inference struct {
	Possible   bool
	Confidence Confidence
	Reasons    []string
}

type Cookie struct {
	Position              int
	Name                  string
	NameSanitized         bool
	Parse                 ParseStatus
	Acceptance            AcceptanceStatus
	RejectionReasons      []string
	Identity              Identity
	IdentityRepeated      bool
	Secure                FlagAttribute
	HTTPOnly              FlagAttribute
	SameSite              Attribute
	Domain                DomainAttribute
	Path                  Attribute
	Expires               TimeAttribute
	MaxAge                IntegerAttribute
	UnknownAttributes     []UnknownAttribute
	InvalidAttributeNames int
	Prefix                PrefixEvaluation
	Persistence           PersistenceKind
	SessionLike           Inference
	Truncated             bool
}

type Report struct {
	Capture        CaptureStatus
	ObservedAt     time.Time
	FieldCount     int
	AnalyzedFields int
	OmittedFields  int
	Truncated      bool
	Cookies        []Cookie
}

func (r Report) String() string {
	return fmt.Sprintf("cookie analysis: capture=%s cookies=%d truncated=%t", r.Capture, len(r.Cookies), r.Truncated)
}

func (r Report) GoString() string { return r.String() }

func (r Report) Clone() Report {
	r.Cookies = append([]Cookie(nil), r.Cookies...)
	for i := range r.Cookies {
		r.Cookies[i].RejectionReasons = append([]string(nil), r.Cookies[i].RejectionReasons...)
		r.Cookies[i].UnknownAttributes = append([]UnknownAttribute(nil), r.Cookies[i].UnknownAttributes...)
		r.Cookies[i].Prefix.Reasons = append([]string(nil), r.Cookies[i].Prefix.Reasons...)
		r.Cookies[i].SessionLike.Reasons = append([]string(nil), r.Cookies[i].SessionLike.Reasons...)
	}
	return r
}
