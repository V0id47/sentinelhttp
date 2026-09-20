// Package diffing compares two validated SentinelHTTP reports without I/O.
package diffing

import "time"

const Version = "1"

type Status string

const (
	StatusComparable   Status = "comparable"
	StatusPartial      Status = "partial"
	StatusIncomparable Status = "incomparable"
)

type ChangeKind string

const (
	NewFinding          ChangeKind = "new_finding"
	ResolvedFinding     ChangeKind = "resolved_finding"
	SeverityChanged     ChangeKind = "severity_changed"
	HeaderAdded         ChangeKind = "header_added"
	HeaderRemoved       ChangeKind = "header_removed"
	HeaderChanged       ChangeKind = "header_changed"
	CookieAdded         ChangeKind = "cookie_added"
	CookieRemoved       ChangeKind = "cookie_removed"
	CookiePolicyChanged ChangeKind = "cookie_policy_changed"
	TLSChanged          ChangeKind = "tls_changed"
	CertificateChanged  ChangeKind = "certificate_changed"
	CSPChanged          ChangeKind = "csp_changed"
	RedirectChanged     ChangeKind = "redirect_changed"
)

type Change struct {
	Kind   ChangeKind `json:"kind"`
	Key    string     `json:"key"`
	Before string     `json:"before"`
	After  string     `json:"after"`
}

type Unknown struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Reason  string `json:"reason"`
}

type Result struct {
	DiffVersion   string    `json:"diff_version"`
	Status        Status    `json:"status"`
	Target        string    `json:"target"`
	BeforeStarted time.Time `json:"before_started"`
	AfterStarted  time.Time `json:"after_started"`
	Changes       []Change  `json:"changes"`
	Unknown       []Unknown `json:"unknown"`
}
