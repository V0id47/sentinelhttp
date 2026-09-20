package cookieanalysis

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

const (
	maxCookieFields      = 128
	maxFieldBytes        = 4096
	maxEvidenceBytes     = 64 << 10
	maxAttributeSegments = 64
	maxUnknownAttributes = 32
)

type domainCandidate struct {
	value string
	empty bool
	valid bool
}

type parsedAttributes struct {
	domainValues                                                     []domainCandidate
	pathValues                                                       []string
	expiresValues                                                    []time.Time
	maxAgeValues                                                     []int64
	sameSiteValues                                                   []string
	domainCount, pathCount, expiresCount, maxAgeCount, sameSiteCount int
	secureCount, secureValid, httpOnlyCount, httpOnlyValid           int
	unknown                                                          []UnknownAttribute
	unknownIndex                                                     map[string]int
	invalidNames                                                     int
	truncated                                                        bool
}

func Analyze(input Input) Report {
	if !input.Captured {
		return Report{Capture: CaptureUnavailable}
	}
	report := Report{
		Capture: CaptureComplete, ObservedAt: input.ObservedAt.UTC(),
		FieldCount: len(input.Fields),
	}
	limit := len(input.Fields)
	if limit > maxCookieFields {
		limit = maxCookieFields
		report.OmittedFields = len(input.Fields) - limit
		report.Truncated = true
	}
	remaining := maxEvidenceBytes
	for index, field := range input.Fields[:limit] {
		cookie := newCookie(index)
		report.AnalyzedFields++
		if len(field) > maxFieldBytes || len(field) > remaining {
			markTruncated(&cookie)
			report.Truncated = true
			report.Cookies = append(report.Cookies, cookie)
			remaining = max(0, remaining-len(field))
			continue
		}
		remaining -= len(field)
		cookie = analyzeField(input, index, field)
		if cookie.Truncated {
			report.Truncated = true
		}
		report.Cookies = append(report.Cookies, cookie)
	}
	markRepeatedIdentities(report.Cookies)
	return report
}

func analyzeField(input Input, position int, field string) Cookie {
	cookie := newCookie(position)
	if containsRejectedCTL(field) {
		cookie.RejectionReasons = []string{ReasonSyntaxInvalid}
		return cookie
	}
	segments := strings.Split(field, ";")
	if len(segments) > maxAttributeSegments+1 {
		segments = segments[:maxAttributeSegments+1]
		cookie.Truncated = true
	}
	first := trimOWS(segments[0])
	name, value, found := strings.Cut(first, "=")
	if !found {
		name, value = "", first
	}
	name = trimOWS(name)
	value = trimOWS(value)
	if name == "" && value == "" {
		cookie.RejectionReasons = []string{ReasonSyntaxInvalid}
		return cookie
	}
	var nameTruncated bool
	cookie.Name, cookie.NameSanitized, nameTruncated = sanitizeText(name, 256)
	cookie.Truncated = cookie.Truncated || nameTruncated
	cookie.Parse = ParseValid
	cookie.Acceptance = Accepted

	attrs := parseAttributes(segments[1:])
	attrs.truncated = attrs.truncated || cookie.Truncated
	cookie.Truncated = attrs.truncated
	cookie.InvalidAttributeNames = attrs.invalidNames
	cookie.UnknownAttributes = attrs.unknown
	cookie.Secure = flag(attrs.secureCount, attrs.secureValid)
	cookie.HTTPOnly = flag(attrs.httpOnlyCount, attrs.httpOnlyValid)
	cookie.SameSite = effectiveSameSite(attrs)
	cookie.Expires = effectiveExpires(attrs, input.ObservedAt)
	cookie.MaxAge = effectiveMaxAge(attrs)
	var pathTruncated bool
	cookie.Path, pathTruncated = effectivePath(attrs, input.RequestPath)
	cookie.Truncated = cookie.Truncated || pathTruncated
	cookie.Domain = effectiveDomain(attrs, strings.ToLower(input.Host), &cookie)
	cookie.Persistence = persistence(cookie.MaxAge, cookie.Expires, input.ObservedAt)
	cookie.Prefix = evaluatePrefix(cookie, strings.ToLower(input.Scheme))
	if name == "" {
		if kind := namelessPrefix(value); kind != "" {
			cookie.Prefix = PrefixEvaluation{Kind: kind, Status: PrefixViolated, Reasons: []string{ReasonPrefixRequirements}}
		}
	}
	applyAcceptance(&cookie, strings.ToLower(input.Scheme))
	cookie.SessionLike = inferSession(cookie.Name, cookie.Persistence)
	cookie.Identity = Identity{
		EmitterResource: input.EmitterResource,
		CookieName:      cookie.Name,
		EffectiveDomain: cookie.Domain.Effective,
		EffectivePath:   cookie.Path.Effective,
	}
	if cookie.Truncated {
		markTruncated(&cookie)
	}
	return cookie
}

func newCookie(position int) Cookie {
	return Cookie{
		Position: position, Parse: ParseInvalid, Acceptance: Rejected,
		Persistence: PersistenceIndeterminate,
		Secure:      FlagAttribute{Status: AttributeAbsent},
		HTTPOnly:    FlagAttribute{Status: AttributeAbsent},
		SameSite:    Attribute{Status: AttributeAbsent, Effective: "Default"},
		Domain:      DomainAttribute{Attribute: Attribute{Status: AttributeAbsent}},
		Path:        Attribute{Status: AttributeAbsent},
		Expires:     TimeAttribute{Status: AttributeAbsent},
		MaxAge:      IntegerAttribute{Status: AttributeAbsent},
		Prefix:      PrefixEvaluation{Status: PrefixNotApplicable},
		SessionLike: Inference{Confidence: ConfidenceNone},
	}
}

func markTruncated(cookie *Cookie) {
	cookie.Parse = ParseTruncated
	cookie.Acceptance = AcceptanceIndeterminate
	cookie.RejectionReasons = nil
	cookie.Truncated = true
	cookie.Secure.Status, cookie.Secure.Enabled = AttributeTruncated, false
	cookie.HTTPOnly.Status, cookie.HTTPOnly.Enabled = AttributeTruncated, false
	cookie.SameSite = Attribute{Status: AttributeTruncated, Occurrences: cookie.SameSite.Occurrences}
	cookie.Domain = DomainAttribute{Attribute: Attribute{Status: AttributeTruncated, Occurrences: cookie.Domain.Occurrences}}
	cookie.Path = Attribute{Status: AttributeTruncated, Occurrences: cookie.Path.Occurrences}
	cookie.Expires = TimeAttribute{Status: AttributeTruncated, Occurrences: cookie.Expires.Occurrences}
	cookie.MaxAge = IntegerAttribute{Status: AttributeTruncated, Occurrences: cookie.MaxAge.Occurrences}
	cookie.Prefix = PrefixEvaluation{Kind: cookie.Prefix.Kind, Status: PrefixIndeterminate}
	cookie.Persistence = PersistenceIndeterminate
	cookie.SessionLike = Inference{Confidence: ConfidenceNone}
	cookie.Identity = Identity{}
	cookie.IdentityRepeated = false
}

func parseAttributes(segments []string) parsedAttributes {
	attrs := parsedAttributes{unknownIndex: make(map[string]int)}
	for _, segment := range segments {
		segment = trimOWS(segment)
		if segment == "" {
			continue
		}
		name, value, hasValue := strings.Cut(segment, "=")
		name = trimOWS(name)
		value = trimOWS(value)
		if !validToken(name) {
			attrs.invalidNames++
			continue
		}
		if len(value) > 1024 {
			countIgnoredKnown(&attrs, strings.ToLower(name))
			continue
		}
		switch strings.ToLower(name) {
		case "secure":
			attrs.secureCount++
			attrs.secureValid++
		case "httponly":
			attrs.httpOnlyCount++
			attrs.httpOnlyValid++
		case "domain":
			attrs.domainCount++
			attrs.domainValues = append(attrs.domainValues, parseDomainValue(value))
		case "path":
			attrs.pathCount++
			attrs.pathValues = append(attrs.pathValues, value)
		case "expires":
			attrs.expiresCount++
			if hasValue {
				if expires, ok := parseCookieDate(value); ok {
					attrs.expiresValues = append(attrs.expiresValues, expires)
				}
			}
		case "max-age":
			attrs.maxAgeCount++
			if hasValue {
				if seconds, ok := parseMaxAge(value); ok {
					attrs.maxAgeValues = append(attrs.maxAgeValues, seconds)
				}
			}
		case "samesite":
			attrs.sameSiteCount++
			effective := "Default"
			if hasValue {
				switch strings.ToLower(value) {
				case "strict":
					effective = "Strict"
				case "lax":
					effective = "Lax"
				case "none":
					effective = "None"
				}
			}
			attrs.sameSiteValues = append(attrs.sameSiteValues, effective)
		default:
			lower := strings.ToLower(name)
			if at, ok := attrs.unknownIndex[lower]; ok {
				attrs.unknown[at].Occurrences++
			} else if len(attrs.unknown) < maxUnknownAttributes {
				attrs.unknownIndex[lower] = len(attrs.unknown)
				attrs.unknown = append(attrs.unknown, UnknownAttribute{Name: lower, Occurrences: 1})
			} else {
				attrs.truncated = true
			}
		}
	}
	return attrs
}

func flag(count, valid int) FlagAttribute {
	return FlagAttribute{Status: status(count, valid), Occurrences: count, Enabled: valid > 0}
}

func effectiveSameSite(attrs parsedAttributes) Attribute {
	result := Attribute{Status: status(attrs.sameSiteCount, len(attrs.sameSiteValues)), Occurrences: attrs.sameSiteCount, Effective: "Default"}
	if len(attrs.sameSiteValues) > 0 {
		result.Effective = attrs.sameSiteValues[len(attrs.sameSiteValues)-1]
		if result.Effective == "Default" && attrs.sameSiteCount == 1 {
			result.Status = AttributeInvalid
		}
	}
	return result
}

func effectiveExpires(attrs parsedAttributes, observed time.Time) TimeAttribute {
	result := TimeAttribute{Status: status(attrs.expiresCount, len(attrs.expiresValues)), Occurrences: attrs.expiresCount, ValidOccurrences: len(attrs.expiresValues)}
	if len(attrs.expiresValues) > 0 {
		result.Observed = attrs.expiresValues[len(attrs.expiresValues)-1]
		result.Effective = result.Observed
		if !observed.IsZero() {
			limit := observed.Add(400 * 24 * time.Hour)
			if result.Effective.After(limit) {
				result.Effective, result.Clamped = limit, true
			}
		}
	}
	return result
}

func effectiveMaxAge(attrs parsedAttributes) IntegerAttribute {
	result := IntegerAttribute{Status: status(attrs.maxAgeCount, len(attrs.maxAgeValues)), Occurrences: attrs.maxAgeCount, ValidOccurrences: len(attrs.maxAgeValues)}
	if len(attrs.maxAgeValues) > 0 {
		result.ObservedSeconds = attrs.maxAgeValues[len(attrs.maxAgeValues)-1]
		result.Seconds = result.ObservedSeconds
		if result.Seconds > 400*24*60*60 {
			result.Seconds, result.Clamped = 400*24*60*60, true
		}
	}
	return result
}

func effectivePath(attrs parsedAttributes, requestPath string) (Attribute, bool) {
	result := Attribute{Status: status(attrs.pathCount, len(attrs.pathValues)), Occurrences: attrs.pathCount}
	effective := defaultPath(requestPath)
	if len(attrs.pathValues) > 0 {
		candidate := attrs.pathValues[len(attrs.pathValues)-1]
		if strings.HasPrefix(candidate, "/") {
			effective = candidate
			result.Explicit = true
		} else if attrs.pathCount == 1 {
			result.Status = AttributeInvalid
		}
	}
	var truncated bool
	result.Effective, result.Sanitized, truncated = sanitizeText(effective, maxFieldBytes)
	return result, truncated
}

func effectiveDomain(attrs parsedAttributes, host string, cookie *Cookie) DomainAttribute {
	attributeStatus := status(attrs.domainCount, len(attrs.domainValues))
	if attrs.domainCount == 1 && (len(attrs.domainValues) == 0 || attrs.domainValues[0].empty || !attrs.domainValues[0].valid) {
		attributeStatus = AttributeInvalid
	}
	result := DomainAttribute{
		Attribute: Attribute{Status: attributeStatus, Occurrences: attrs.domainCount},
		HostOnly:  attrs.domainCount == 0, DomainMatch: true,
	}
	if attrs.domainCount == 0 {
		result.Effective = host
		return result
	}
	// Attribute values above the processing limit are ignored. If no Domain
	// value was processed, the cookie remains host-only.
	if len(attrs.domainValues) == 0 {
		result.Effective, result.HostOnly = host, true
		return result
	}
	candidate := attrs.domainValues[len(attrs.domainValues)-1]
	if candidate.empty {
		result.Effective, result.HostOnly = host, true
		return result
	}
	if !candidate.valid {
		result.DomainMatch = false
		cookie.reject(ReasonDomainInvalid)
		return result
	}
	domain := candidate.value
	if ip, err := netip.ParseAddr(host); err == nil {
		if domain != ip.Unmap().String() {
			result.DomainMatch = false
			cookie.reject(ReasonDomainMismatch)
			return result
		}
		result.Effective, result.HostOnly = host, false
		return result
	}
	result.PublicSuffix, result.PublicSuffixICANN = publicsuffix.PublicSuffix(domain)
	if result.PublicSuffix == domain {
		if host == domain {
			result.Effective, result.HostOnly = host, true
			return result
		}
		result.DomainMatch = false
		cookie.reject(ReasonPublicSuffix)
		return result
	}
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		result.DomainMatch = false
		cookie.reject(ReasonDomainMismatch)
		return result
	}
	result.Effective, result.HostOnly = domain, false
	return result
}

func evaluatePrefix(cookie Cookie, scheme string) PrefixEvaluation {
	result := PrefixEvaluation{Status: PrefixNotApplicable}
	lowerName := strings.ToLower(cookie.Name)
	switch {
	case strings.HasPrefix(lowerName, "__secure-"):
		result.Kind = "__Secure-"
		if cookie.Secure.Enabled && scheme == "https" {
			result.Status = PrefixSatisfied
		} else {
			result.Status = PrefixViolated
			result.Reasons = []string{ReasonPrefixRequirements}
		}
	case strings.HasPrefix(lowerName, "__host-"):
		result.Kind = "__Host-"
		explicitRootPath := cookie.Path.Explicit && cookie.Path.Effective == "/" && cookie.Path.Status != AttributeInvalid
		if cookie.Secure.Enabled && scheme == "https" && cookie.Domain.HostOnly && explicitRootPath {
			result.Status = PrefixSatisfied
		} else {
			result.Status = PrefixViolated
			result.Reasons = []string{ReasonPrefixRequirements}
		}
	}
	return result
}

func applyAcceptance(cookie *Cookie, scheme string) {
	if cookie.Parse != ParseValid {
		cookie.reject(ReasonSyntaxInvalid)
		return
	}
	if cookie.Secure.Enabled && scheme != "https" {
		cookie.reject(ReasonSecureOriginRequired)
	}
	if cookie.SameSite.Effective == "None" && !cookie.Secure.Enabled {
		cookie.reject(ReasonSameSiteNeedsSecure)
	}
	if cookie.Prefix.Status == PrefixViolated {
		cookie.reject(ReasonPrefixRequirements)
	}
}

func (c *Cookie) reject(reason string) {
	c.Acceptance = Rejected
	for _, existing := range c.RejectionReasons {
		if existing == reason {
			return
		}
	}
	c.RejectionReasons = append(c.RejectionReasons, reason)
}

func persistence(maxAge IntegerAttribute, expires TimeAttribute, observed time.Time) PersistenceKind {
	if maxAge.ValidOccurrences > 0 {
		if maxAge.Seconds <= 0 {
			return Deletion
		}
		return Persistent
	}
	if expires.ValidOccurrences > 0 {
		if observed.IsZero() {
			return PersistenceIndeterminate
		}
		if !expires.Effective.After(observed) {
			return Deletion
		}
		return Persistent
	}
	return Session
}

func inferSession(name string, kind PersistenceKind) Inference {
	lower := strings.ToLower(name)
	nameLike := strings.Contains(lower, "session") || lower == "sid" || strings.HasSuffix(lower, "_sid") || strings.HasSuffix(lower, "-sid") || strings.Contains(lower, "sessid")
	if nameLike && kind != Deletion {
		return Inference{Possible: true, Confidence: ConfidenceMedium, Reasons: []string{ReasonNameHeuristic}}
	}
	if kind == Session {
		return Inference{Possible: true, Confidence: ConfidenceLow, Reasons: []string{ReasonNonPersistent}}
	}
	return Inference{Confidence: ConfidenceNone}
}

func status(occurrences, valid int) AttributeStatus {
	if occurrences == 0 {
		return AttributeAbsent
	}
	if occurrences > 1 {
		return AttributeDuplicate
	}
	if valid == 0 {
		return AttributeInvalid
	}
	return AttributeValid
}

func parseDomainValue(value string) domainCandidate {
	value = strings.TrimPrefix(value, ".")
	if value == "" {
		return domainCandidate{empty: true, valid: true}
	}
	for i := 0; i < len(value); i++ {
		if value[i] == 0 || value[i] > 0x7f {
			return domainCandidate{}
		}
	}
	value = strings.ToLower(value)
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || len(value) > 253 {
		return domainCandidate{}
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return domainCandidate{value: ip.Unmap().String(), valid: true}
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return domainCandidate{}
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return domainCandidate{}
			}
		}
	}
	return domainCandidate{value: value, valid: true}
}

func parseMaxAge(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	start := 0
	if value[0] == '-' {
		start = 1
	}
	if start == len(value) {
		return 0, false
	}
	for i := start; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		if value[0] == '-' {
			return -1 << 63, true
		}
		return 1<<63 - 1, true
	}
	return seconds, true
}

func defaultPath(path string) string {
	if path == "" || path[0] != '/' {
		return "/"
	}
	last := strings.LastIndexByte(path, '/')
	if last == 0 {
		return "/"
	}
	return path[:last]
}

func containsRejectedCTL(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] <= 0x08 || value[i] >= 0x0a && value[i] <= 0x1f || value[i] == 0x7f {
			return true
		}
	}
	return false
}

func sanitizeText(value string, limit int) (string, bool, bool) {
	var out strings.Builder
	sanitized, truncated := false, false
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			sanitized = true
		}
		value = value[size:]
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r, sanitized = utf8.RuneError, true
		}
		width := utf8.RuneLen(r)
		if out.Len()+width > limit {
			truncated = true
			break
		}
		out.WriteRune(r)
	}
	if value != "" {
		truncated = true
	}
	return out.String(), sanitized, truncated
}

func namelessPrefix(value string) string {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "__secure-") {
		return "__Secure-"
	}
	if strings.HasPrefix(lower, "__host-") {
		return "__Host-"
	}
	return ""
}

func countIgnoredKnown(attrs *parsedAttributes, name string) {
	switch name {
	case "domain":
		attrs.domainCount++
	case "path":
		attrs.pathCount++
	case "expires":
		attrs.expiresCount++
	case "max-age":
		attrs.maxAgeCount++
	case "samesite":
		attrs.sameSiteCount++
	case "secure":
		attrs.secureCount++
	case "httponly":
		attrs.httpOnlyCount++
	}
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))) {
			return false
		}
	}
	return true
}

func trimOWS(value string) string { return strings.Trim(value, " \t") }

func markRepeatedIdentities(cookies []Cookie) {
	counts := make(map[Identity]int)
	for _, cookie := range cookies {
		if identityComparable(cookie) {
			counts[cookie.Identity]++
		}
	}
	for index := range cookies {
		cookies[index].IdentityRepeated = identityComparable(cookies[index]) && counts[cookies[index].Identity] > 1
	}
}

func identityComparable(cookie Cookie) bool {
	return cookie.Parse == ParseValid &&
		!cookie.Truncated &&
		!cookie.NameSanitized &&
		!cookie.Path.Sanitized &&
		cookie.Identity.EmitterResource != "" &&
		cookie.Identity.EffectiveDomain != "" &&
		cookie.Identity.EffectivePath != ""
}
