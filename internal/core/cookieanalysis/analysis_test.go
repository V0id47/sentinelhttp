package cookieanalysis

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var observedAt = time.Date(2026, time.September, 18, 12, 0, 0, 0, time.UTC)

func completeInput(fields ...string) Input {
	return Input{
		Captured:        true,
		Scheme:          "https",
		Host:            "app.example.com",
		EmitterResource: "https://app.example.com/[REDACTED]",
		RequestPath:     "/account/login",
		ObservedAt:      observedAt,
		Fields:          fields,
	}
}

func TestAnalyzeExpiresCommaAndNeverRetainsCookieValue(t *testing.T) {
	report := Analyze(completeInput("sessionid=TOP-SECRET-CANARY; Expires=Wed, 21 Oct 2027 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax; Path=/account"))
	if report.Capture != CaptureComplete || report.FieldCount != 1 || report.AnalyzedFields != 1 || len(report.Cookies) != 1 {
		t.Fatalf("capture mismatch: %+v", report)
	}
	cookie := report.Cookies[0]
	if cookie.Name != "sessionid" || cookie.Parse != ParseValid || cookie.Acceptance != Accepted {
		t.Fatalf("cookie mismatch: %+v", cookie)
	}
	if cookie.Expires.Status != AttributeValid || !cookie.Expires.Effective.Equal(time.Date(2027, time.October, 21, 7, 28, 0, 0, time.UTC)) {
		t.Fatalf("expires comma was split or misparsed: %+v", cookie.Expires)
	}
	if !cookie.Secure.Enabled || !cookie.HTTPOnly.Enabled || cookie.SameSite.Effective != "Lax" || cookie.Path.Effective != "/account" || cookie.Persistence != Persistent {
		t.Fatalf("attributes mismatch: %+v", cookie)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(encoded), fmt.Sprint(report), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", report)} {
		if strings.Contains(rendered, "TOP-SECRET-CANARY") {
			t.Fatal("cookie value retained by report")
		}
	}
}

func TestAnalyzeKeepsSetCookieFieldsSeparateAndMarksRepeatedIdentity(t *testing.T) {
	report := Analyze(completeInput(
		"sid=first; Secure; Path=/",
		"sid=second; Secure; Path=/",
		"theme=dark; Path=/account",
	))
	if len(report.Cookies) != 3 || !report.Cookies[0].IdentityRepeated || !report.Cookies[1].IdentityRepeated || report.Cookies[2].IdentityRepeated {
		t.Fatalf("field identity mismatch: %+v", report.Cookies)
	}
	if report.Cookies[0].Identity != (Identity{EmitterResource: "https://app.example.com/[REDACTED]", CookieName: "sid", EffectiveDomain: "app.example.com", EffectivePath: "/"}) {
		t.Fatalf("wrong identity: %+v", report.Cookies[0].Identity)
	}
}

func TestAnalyzeUsesLastValidRepeatedAttributesAndMaxAgePrecedence(t *testing.T) {
	report := Analyze(completeInput("sid=value; Domain=.example.com; Domain=example.com; Path=/old; Path=/new; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Max-Age=60; Max-Age=0; SameSite=Strict; SameSite=None; Secure"))
	cookie := report.Cookies[0]
	if cookie.Domain.Status != AttributeDuplicate || cookie.Domain.Effective != "example.com" || !cookie.Domain.DomainMatch || cookie.Domain.HostOnly {
		t.Fatalf("domain duplicate mismatch: %+v", cookie.Domain)
	}
	if cookie.Path.Status != AttributeDuplicate || cookie.Path.Effective != "/new" || cookie.SameSite.Status != AttributeDuplicate || cookie.SameSite.Effective != "None" {
		t.Fatalf("last attribute did not win: path=%+v same_site=%+v", cookie.Path, cookie.SameSite)
	}
	if cookie.MaxAge.Status != AttributeDuplicate || cookie.MaxAge.Seconds != 0 || cookie.Persistence != Deletion {
		t.Fatalf("Max-Age did not override Expires: %+v", cookie)
	}
}

func TestAnalyzeDomainAndPublicSuffixPolicy(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		acceptance AcceptanceStatus
		domain     string
		hostOnly   bool
		reason     string
	}{
		{"host only", "id=x", Accepted, "app.example.com", true, ""},
		{"parent domain", "id=x; Domain=example.com", Accepted, "example.com", false, ""},
		{"leading dot", "id=x; Domain=.example.com", Accepted, "example.com", false, ""},
		{"public suffix", "id=x; Domain=com", Rejected, "", false, ReasonPublicSuffix},
		{"unrelated", "id=x; Domain=attacker.test", Rejected, "", false, ReasonDomainMismatch},
		{"trailing dot", "id=x; Domain=example.com.", Rejected, "", false, ReasonDomainInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cookie := Analyze(completeInput(tc.field)).Cookies[0]
			if cookie.Acceptance != tc.acceptance || cookie.Domain.Effective != tc.domain || cookie.Domain.HostOnly != tc.hostOnly {
				t.Fatalf("domain result mismatch: %+v", cookie)
			}
			if tc.reason != "" && !contains(cookie.RejectionReasons, tc.reason) {
				t.Fatalf("missing rejection reason %q: %+v", tc.reason, cookie.RejectionReasons)
			}
		})
	}
}

func TestAnalyzeRejectsNonASCIIDomainAttribute(t *testing.T) {
	input := completeInput("id=x; Domain=bücher.example")
	input.Host = "xn--bcher-kva.example"
	cookie := Analyze(input).Cookies[0]
	if cookie.Acceptance != Rejected || !contains(cookie.RejectionReasons, ReasonDomainInvalid) {
		t.Fatalf("non-CHAR Domain was not rejected: %+v", cookie)
	}
}

func TestAnalyzeUsesLastProcessedDomainAttribute(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		acceptance AcceptanceStatus
		domain     string
		hostOnly   bool
	}{
		{"empty Domain wins", "id=x; Domain=example.com; Domain=", Accepted, "app.example.com", true},
		{"invalid trailing dot wins", "id=x; Domain=example.com; Domain=example.com.", Rejected, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cookie := Analyze(completeInput(tc.field)).Cookies[0]
			if cookie.Acceptance != tc.acceptance || cookie.Domain.Effective != tc.domain || cookie.Domain.HostOnly != tc.hostOnly {
				t.Fatalf("last processed Domain did not win: %+v", cookie)
			}
		})
	}
}

func TestAnalyzeHostPrefixAcceptsPublicSuffixEqualToEmitterAsHostOnly(t *testing.T) {
	input := completeInput("__Host-id=x; Secure; Path=/; Domain=com")
	input.Host = "com"
	cookie := Analyze(input).Cookies[0]
	if cookie.Domain.Effective != "com" || !cookie.Domain.HostOnly || cookie.Prefix.Status != PrefixSatisfied || cookie.Acceptance != Accepted {
		t.Fatalf("public-suffix-equal emitter was not converted to host-only: %+v", cookie)
	}
}

func TestAnalyzeCookiePrefixesAndSameSiteNone(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		status     PrefixStatus
		acceptance AcceptanceStatus
	}{
		{"secure prefix", "__Secure-id=x; Secure", PrefixSatisfied, Accepted},
		{"secure prefix missing flag", "__Secure-id=x", PrefixViolated, Rejected},
		{"host prefix", "__Host-id=x; Secure; Path=/", PrefixSatisfied, Accepted},
		{"host prefix empty domain remains host only", "__Host-id=x; Secure; Path=/; Domain=", PrefixSatisfied, Accepted},
		{"host prefix default path is insufficient", "__Host-id=x; Secure", PrefixViolated, Rejected},
		{"host prefix domain", "__Host-id=x; Secure; Path=/; Domain=app.example.com", PrefixViolated, Rejected},
		{"host prefix last empty path wins", "__Host-id=x; Secure; Path=/; Path", PrefixViolated, Rejected},
		{"user agent prefix matching is case insensitive", "__secure-id=x", PrefixViolated, Rejected},
		{"same site none needs secure", "id=x; SameSite=None", PrefixNotApplicable, Rejected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cookie := Analyze(completeInput(tc.field)).Cookies[0]
			if cookie.Prefix.Status != tc.status || cookie.Acceptance != tc.acceptance {
				t.Fatalf("prefix/policy mismatch: %+v", cookie)
			}
		})
	}
}

func TestAnalyzeUsesTolerantUserAgentCookiePairParsing(t *testing.T) {
	tests := []struct {
		field      string
		name       string
		parse      ParseStatus
		acceptance AcceptanceStatus
	}{
		{"odd name=value with spaces", "odd name", ParseValid, Accepted},
		{"quoted=\"unterminated", "quoted", ParseValid, Accepted},
		{"nameless-value", "", ParseValid, Accepted},
		{"=value", "", ParseValid, Accepted},
		{"__secure-id-value", "", ParseValid, Rejected},
		{"id=value\x00", "", ParseInvalid, Rejected},
		{"=", "", ParseInvalid, Rejected},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			cookie := Analyze(completeInput(tc.field)).Cookies[0]
			if cookie.Name != tc.name || cookie.Parse != tc.parse || cookie.Acceptance != tc.acceptance {
				t.Fatalf("user-agent parsing mismatch: %+v", cookie)
			}
		})
	}
}

func TestAnalyzeAppliesFourHundredDayLifetimeCap(t *testing.T) {
	limit := observedAt.Add(400 * 24 * time.Hour)
	expires := Analyze(completeInput("id=x; Expires=Wed, 21 Oct 2037 07:28:00 GMT")).Cookies[0].Expires
	if !expires.Observed.Equal(time.Date(2037, time.October, 21, 7, 28, 0, 0, time.UTC)) || !expires.Effective.Equal(limit) || !expires.Clamped {
		t.Fatalf("Expires lifetime not bounded: %+v", expires)
	}
	maxAge := Analyze(completeInput("id=x; Max-Age=999999999")).Cookies[0].MaxAge
	if maxAge.ObservedSeconds != 999999999 || maxAge.Seconds != 34560000 || !maxAge.Clamped {
		t.Fatalf("Max-Age lifetime not bounded: %+v", maxAge)
	}
}

func TestAnalyzeCookieDateAcceptsDraftTrailingOctets(t *testing.T) {
	expires := Analyze(completeInput("id=x; Expires=Wed, 21st Oct 27 07:28:00GMT")).Cookies[0].Expires
	want := time.Date(2027, time.October, 21, 7, 28, 0, 0, time.UTC)
	if expires.Status != AttributeValid || !expires.Effective.Equal(want) {
		t.Fatalf("tolerant cookie-date production not implemented: %+v", expires)
	}
}

func TestAnalyzeIgnoresAttributeValuesAboveDraftLimit(t *testing.T) {
	cookie := Analyze(completeInput("id=x; Secure=" + strings.Repeat("a", 1025))).Cookies[0]
	if cookie.Secure.Status != AttributeInvalid || cookie.Secure.Enabled || cookie.Acceptance != Accepted {
		t.Fatalf("oversized Secure attribute was applied: %+v", cookie)
	}
}

func TestAnalyzeSaturatesSyntacticallyValidMaxAgeOverflow(t *testing.T) {
	positive := Analyze(completeInput("id=x; Max-Age=999999999999999999999999999999")).Cookies[0]
	if positive.MaxAge.Status != AttributeValid || positive.MaxAge.Seconds != 34560000 || !positive.MaxAge.Clamped || positive.Persistence != Persistent {
		t.Fatalf("positive overflow was not lifetime-capped: %+v", positive)
	}
	negative := Analyze(completeInput("id=x; Max-Age=-999999999999999999999999999999")).Cookies[0]
	if negative.MaxAge.Status != AttributeValid || negative.Persistence != Deletion {
		t.Fatalf("negative overflow was not treated as deletion: %+v", negative)
	}
}

func TestAnalyzeDoesNotConflateSanitizedNamesForIdentity(t *testing.T) {
	report := Analyze(completeInput("\xff=one", "\xfe=two"))
	if len(report.Cookies) != 2 || !report.Cookies[0].NameSanitized || !report.Cookies[1].NameSanitized {
		t.Fatalf("hostile names were not explicitly sanitized: %+v", report.Cookies)
	}
	if report.Cookies[0].IdentityRepeated || report.Cookies[1].IdentityRepeated {
		t.Fatalf("lossy display names were conflated as one identity: %+v", report.Cookies)
	}
}

func TestAnalyzeMarksRepeatedEmptyCookieNames(t *testing.T) {
	report := Analyze(completeInput("=one; Path=/", "=two; Path=/"))
	if !report.Cookies[0].IdentityRepeated || !report.Cookies[1].IdentityRepeated {
		t.Fatalf("valid empty cookie names were excluded from identity: %+v", report.Cookies)
	}
}

func TestAnalyzeNeverMarksLossyIdentityAsRepeated(t *testing.T) {
	report := Analyze(completeInput("�=one; Path=/", "�=two; Path=/", "\xff=three; Path=/"))
	if !report.Cookies[0].IdentityRepeated || !report.Cookies[1].IdentityRepeated {
		t.Fatalf("exact identities were not marked repeated: %+v", report.Cookies)
	}
	if report.Cookies[2].IdentityRepeated {
		t.Fatalf("lossy identity inherited another identity's collision: %+v", report.Cookies)
	}
}

func TestAnalyzeDefaultsPathAndFallsBackFromInvalidPersistenceAttributes(t *testing.T) {
	tests := []struct {
		path        string
		field       string
		wantPath    string
		persistence PersistenceKind
	}{
		{"/account/login", "id=x", "/account", Session},
		{"/one", "id=x; Path=relative", "/", Session},
		{"/account/login", "id=x; Max-Age=oops; Expires=Wed, 21 Oct 2037 07:28:00 GMT", "/account", Persistent},
		{"/account/login", "id=x; Max-Age=-1; Expires=Wed, 21 Oct 2037 07:28:00 GMT", "/account", Deletion},
		{"/account/login", "id=x; Expires=Wed, 21 Oct 2015 07:28:00 GMT", "/account", Deletion},
	}
	for _, tc := range tests {
		t.Run(tc.field+tc.path, func(t *testing.T) {
			input := completeInput(tc.field)
			input.RequestPath = tc.path
			cookie := Analyze(input).Cookies[0]
			if cookie.Path.Effective != tc.wantPath || cookie.Persistence != tc.persistence {
				t.Fatalf("default/effective mismatch: %+v", cookie)
			}
		})
	}
}

func TestAnalyzeSanitizesEffectivePathWithoutChangingPolicy(t *testing.T) {
	cookie := Analyze(completeInput("id=x; Path=/a\tb")).Cookies[0]
	if cookie.Acceptance != Accepted || cookie.Path.Effective != "/a�b" || !cookie.Path.Sanitized || !cookie.Path.Explicit {
		t.Fatalf("effective path was not retained safely: %+v", cookie)
	}
}

func TestAnalyzeDoesNotConflateSanitizedPathsForIdentity(t *testing.T) {
	report := Analyze(completeInput("id=one; Path=/a\xffb", "id=two; Path=/a\xfeb"))
	if report.Cookies[0].IdentityRepeated || report.Cookies[1].IdentityRepeated {
		t.Fatalf("lossy paths were conflated as one identity: %+v", report.Cookies)
	}
}

func TestAnalyzeDuplicateInvalidPersistenceAttributesAreNotEffective(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  PersistenceKind
	}{
		{
			name:  "invalid Max-Age duplicates fall back to Expires",
			field: "id=x; Max-Age=nope; Max-Age=still-nope; Expires=Wed, 21 Oct 2027 07:28:00 GMT",
			want:  Persistent,
		},
		{
			name:  "invalid Expires duplicates remain a session cookie",
			field: "id=x; Expires=nope; Expires=still-nope",
			want:  Session,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cookie := Analyze(completeInput(tc.field)).Cookies[0]
			if cookie.Persistence != tc.want {
				t.Fatalf("persistence mismatch: %+v", cookie)
			}
		})
	}
}

func TestAnalyzeSanitizesUnknownAttributesWithoutTheirValues(t *testing.T) {
	report := Analyze(completeInput("sid=COOKIE-SECRET; Priority=ATTRIBUTE-SECRET; Foo=one; foo=two; Bad Name=value"))
	cookie := report.Cookies[0]
	want := []UnknownAttribute{{Name: "priority", Occurrences: 1}, {Name: "foo", Occurrences: 2}}
	if !reflect.DeepEqual(cookie.UnknownAttributes, want) || cookie.InvalidAttributeNames != 1 {
		t.Fatalf("unknown attribute mismatch: %+v", cookie)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "COOKIE-SECRET") || strings.Contains(string(encoded), "ATTRIBUTE-SECRET") || strings.Contains(string(encoded), "one") || strings.Contains(string(encoded), "two") {
		t.Fatalf("attribute or cookie value retained: %s", encoded)
	}
}

func TestAnalyzeBoundsAndUnavailableCapture(t *testing.T) {
	unavailable := Analyze(Input{Scheme: "https", Host: "app.example.com", Fields: []string{"id=secret"}})
	if unavailable.Capture != CaptureUnavailable || unavailable.FieldCount != 0 || len(unavailable.Cookies) != 0 {
		t.Fatalf("pre-header failure became cookie absence: %+v", unavailable)
	}

	secret := strings.Repeat("PRIVATE", 800)
	report := Analyze(completeInput("id=" + secret))
	if !report.Truncated || len(report.Cookies) != 1 || report.Cookies[0].Parse != ParseTruncated || report.Cookies[0].Acceptance != AcceptanceIndeterminate {
		t.Fatalf("oversized field not bounded: %+v", report)
	}
	assertTruncatedCookie(t, report.Cookies[0])
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("oversized value retained")
	}

	manyAttributes := Analyze(completeInput("id=x" + strings.Repeat("; A", maxAttributeSegments+1)))
	if !manyAttributes.Truncated || len(manyAttributes.Cookies) != 1 || manyAttributes.Cookies[0].Parse != ParseTruncated || manyAttributes.Cookies[0].Acceptance != AcceptanceIndeterminate {
		t.Fatalf("attribute segment limit did not suppress conclusions: %+v", manyAttributes)
	}
	assertTruncatedCookie(t, manyAttributes.Cookies[0])
}

func assertTruncatedCookie(t *testing.T, cookie Cookie) {
	t.Helper()
	statuses := []AttributeStatus{
		cookie.Secure.Status,
		cookie.HTTPOnly.Status,
		cookie.SameSite.Status,
		cookie.Domain.Status,
		cookie.Path.Status,
		cookie.Expires.Status,
		cookie.MaxAge.Status,
	}
	for _, got := range statuses {
		if got != AttributeTruncated {
			t.Fatalf("truncated evidence retained attribute conclusion %q: %+v", got, cookie)
		}
	}
	if cookie.Prefix.Status != PrefixStatus("indeterminate") || cookie.Persistence != PersistenceIndeterminate {
		t.Fatalf("truncated evidence retained policy conclusion: %+v", cookie)
	}
	if cookie.SessionLike.Possible || cookie.SessionLike.Confidence != ConfidenceNone || len(cookie.SessionLike.Reasons) != 0 {
		t.Fatalf("truncated evidence retained session inference: %+v", cookie.SessionLike)
	}
	if cookie.Identity != (Identity{}) || cookie.IdentityRepeated {
		t.Fatalf("truncated evidence retained identity: %+v", cookie)
	}
}

func TestAnalyzeSessionLikeIsExplicitInference(t *testing.T) {
	tests := []struct {
		field      string
		possible   bool
		confidence Confidence
	}{
		{"sessionid=x; Secure", true, ConfidenceMedium},
		{"preferences=x; Secure", true, ConfidenceLow},
		{"preferences=x; Secure; Max-Age=3600", false, ConfidenceNone},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			got := Analyze(completeInput(tc.field)).Cookies[0].SessionLike
			if got.Possible != tc.possible || got.Confidence != tc.confidence {
				t.Fatalf("session inference mismatch: %+v", got)
			}
		})
	}
}

func TestReportCloneOwnsNestedData(t *testing.T) {
	report := Analyze(completeInput("__Host-sessionid=x; Foo=bar"))
	clone := report.Clone()
	clone.Cookies[0].Name = "changed"
	clone.Cookies[0].RejectionReasons[0] = "changed"
	clone.Cookies[0].UnknownAttributes[0].Name = "changed"
	clone.Cookies[0].Prefix.Reasons[0] = "changed"
	clone.Cookies[0].SessionLike.Reasons[0] = "changed"
	if report.Cookies[0].Name != "__Host-sessionid" ||
		report.Cookies[0].RejectionReasons[0] == "changed" ||
		report.Cookies[0].UnknownAttributes[0].Name != "foo" ||
		report.Cookies[0].Prefix.Reasons[0] == "changed" ||
		report.Cookies[0].SessionLike.Reasons[0] == "changed" {
		t.Fatal("clone aliases retained analysis")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
