package headeranalysis

import (
	"mime"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxValuesPerHeader   = 16
	maxValueBytes        = 4096
	maxEvidenceBytes     = 32768
	maxContextValueBytes = 1024
)

func Analyze(in Input) Report {
	if !in.Captured {
		in.Headers = nil
		return Report{Capture: CaptureUnavailable, Context: classifyContext(in)}
	}
	context := classifyContext(in)
	report := Report{Capture: CaptureUnavailable, Context: context}
	report.Capture = CaptureComplete
	report.values = make(map[HeaderID][]string)
	remaining := maxEvidenceBytes
	for _, id := range allHeaderIDs {
		values := headerValues(in.Headers, names[id])
		result := Result{
			ID: id, Name: names[id], Occurrences: len(values),
			Applicability: applicability(id, context), Status: StatusAbsent,
		}
		if len(values) > 0 {
			retained, complete, _ := retain(values, &remaining)
			report.values[id] = retained
			if !complete {
				result.Status, result.Truncated = StatusTruncated, true
			} else if id != Server && !semanticValuesSafe(values) {
				result.Status = StatusInvalid
			} else {
				evaluate(&result, values, context)
			}
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func classifyContext(in Input) ResponseContext {
	c := ResponseContext{Scheme: strings.ToLower(in.Scheme), TLSVerified: in.TLSVerified, HostIsIP: in.HostIsIP, StatusCode: in.StatusCode, ContentTypeStatus: ContextMissing, Representation: RepresentationUnknown}
	if in.StatusCode == 204 || in.StatusCode == 304 {
		c.Representation = RepresentationNoContent
		return c
	}
	if in.StatusCode >= 300 && in.StatusCode <= 399 {
		c.Representation = RepresentationRedirect
		return c
	}
	values := headerValues(in.Headers, "Content-Type")
	if len(values) > 1 {
		c.ContentTypeStatus = ContextAmbiguous
		return c
	}
	if len(values) == 0 {
		return c
	}
	if len(values[0]) > maxContextValueBytes {
		c.ContentTypeStatus = ContextTruncated
		return c
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		c.ContentTypeStatus = ContextInvalid
		return c
	}
	c.ContentTypeStatus = ContextValid
	c.MediaType = strings.ToLower(mediaType)
	switch {
	case c.MediaType == "text/html" || c.MediaType == "application/xhtml+xml":
		c.Representation = RepresentationHTML
	case c.MediaType == "application/json" || c.MediaType == "text/json" || strings.HasSuffix(c.MediaType, "+json"):
		c.Representation = RepresentationJSON
	default:
		c.Representation = RepresentationOther
	}
	return c
}

func applicability(id HeaderID, c ResponseContext) Applicability {
	switch id {
	case StrictTransportSecurity:
		if c.Scheme == "http" || c.HostIsIP {
			return NotApplicable
		}
		if c.Scheme == "https" && c.TLSVerified {
			return Applicable
		}
		return ApplicabilityUnknown
	case CrossOriginOpenerPolicy, CrossOriginEmbedderPolicy:
		if c.Representation == RepresentationHTML {
			if c.Scheme == "https" && c.TLSVerified {
				return Applicable
			}
			return ApplicabilityUnknown
		}
		if c.Representation == RepresentationUnknown {
			return ApplicabilityUnknown
		}
		return NotApplicable
	case ContentSecurityPolicy, PermissionsPolicy, XFrameOptions:
		switch c.Representation {
		case RepresentationHTML:
			return Applicable
		case RepresentationJSON, RepresentationOther, RepresentationRedirect, RepresentationNoContent:
			return NotApplicable
		default:
			return ApplicabilityUnknown
		}
	case XContentTypeOptions, CrossOriginResourcePolicy:
		return ApplicabilityUnknown
	default:
		return Applicable
	}
}

func evaluate(result *Result, values []string, context ResponseContext) {
	switch result.ID {
	case ContentSecurityPolicy:
		result.Status = StatusObserved
	case StrictTransportSecurity:
		evaluateHSTS(result, values)
	case XContentTypeOptions:
		evaluateXCTO(result, values)
	case ReferrerPolicy:
		evaluateReferrerPolicy(result, values)
	case PermissionsPolicy:
		evaluatePermissionsPolicy(result, values)
	case XFrameOptions:
		evaluateXFO(result, values)
	case CrossOriginOpenerPolicy:
		evaluateStructuredPolicy(result, values, []string{"unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups"}, "unsafe-none")
	case CrossOriginResourcePolicy:
		evaluateCORP(result, values)
	case CrossOriginEmbedderPolicy:
		evaluateStructuredPolicy(result, values, []string{"unsafe-none", "require-corp", "credentialless"}, "unsafe-none")
	case Server:
		result.Status = StatusObserved
	}
	if result.ID == StrictTransportSecurity && result.Applicability == NotApplicable {
		result.Status, result.Effective, result.Tokens = StatusIgnored, "", nil
	}
}

func evaluateHSTS(result *Result, values []string) {
	parts, splitOK := splitHTTPDirectives(values[0]) // RFC 6797: only the first field is processed.
	if !splitOK {
		result.Status = StatusInvalid
		return
	}
	seenNames := make(map[string]bool)
	seenMaxAge, seenSubdomains, seenPreload := false, false, false
	maxAge := ""
	for _, raw := range parts {
		part := strings.Trim(raw, " \t")
		if part == "" {
			result.Status = StatusInvalid
			return
		}
		name, value, hasValue := strings.Cut(part, "=")
		name = strings.Trim(name, " \t")
		value = strings.Trim(value, " \t")
		if !validHTTPToken(name) {
			result.Status = StatusInvalid
			return
		}
		lowerName := strings.ToLower(name)
		if seenNames[lowerName] {
			result.Status = StatusInvalid
			return
		}
		seenNames[lowerName] = true
		switch lowerName {
		case "max-age":
			decoded, valid := parseDirectiveValue(value)
			if !hasValue || !valid || !allDigits(decoded) {
				result.Status = StatusInvalid
				return
			}
			seenMaxAge = true
			maxAge = strings.TrimLeft(decoded, "0")
			if maxAge == "" {
				maxAge = "0"
			}
		case "includesubdomains":
			if seenSubdomains || hasValue {
				result.Status = StatusInvalid
				return
			}
			seenSubdomains = true
		case "preload":
			if seenPreload || hasValue {
				result.Status = StatusInvalid
				return
			}
			seenPreload = true
		default:
			if _, valid := parseDirectiveValue(value); hasValue && !valid {
				result.Status = StatusInvalid
				return
			}
		}
	}
	if !seenMaxAge {
		result.Status = StatusInvalid
		return
	}
	result.Status = StatusValid
	result.Effective = "active"
	if maxAge == "0" {
		result.Effective = "inactive"
	}
	result.Tokens = []string{"max-age=" + maxAge}
	if seenSubdomains {
		result.Tokens = append(result.Tokens, "includeSubDomains")
	}
	if seenPreload {
		result.Tokens = append(result.Tokens, "preload")
	}
}

func evaluateXCTO(result *Result, values []string) {
	var split []string
	for _, value := range values {
		split = append(split, strings.Split(value, ",")...)
	}
	if len(split) > 0 && strings.EqualFold(strings.Trim(split[0], " \t"), "nosniff") {
		result.Effective = "nosniff"
	}
	if len(values) == 1 && len(split) == 1 && result.Effective == "nosniff" {
		result.Status = StatusValid
	} else {
		result.Status = StatusInvalid
	}
}

func evaluateReferrerPolicy(result *Result, values []string) {
	recognized := map[string]bool{
		"no-referrer": true, "no-referrer-when-downgrade": true, "same-origin": true,
		"origin": true, "strict-origin": true, "origin-when-cross-origin": true,
		"strict-origin-when-cross-origin": true, "unsafe-url": true,
	}
	seenNonempty := false
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			token = strings.ToLower(strings.Trim(token, " \t"))
			if token == "" {
				continue
			}
			seenNonempty = true
			if recognized[token] {
				result.Effective = token
			}
		}
	}
	switch {
	case result.Effective != "":
		result.Status = StatusValid
	case seenNonempty:
		result.Status = StatusUnrecognized
	default:
		result.Status = StatusInvalid
	}
}

func evaluatePermissionsPolicy(result *Result, values []string) {
	entries, ok := parseSFDictionary(strings.Join(values, ","))
	if !ok || len(entries) == 0 {
		result.Status = StatusInvalid
		return
	}
	for _, entry := range entries {
		directive := Directive{Name: entry.key, Status: StatusValid, Repeated: entry.member.repeated}
		items, params := entry.member.items, entry.member.params
		if !entry.member.inner {
			items, params = []sfItemValue{entry.member.item}, entry.member.item.params
		}
		if reportTo, present := parameter(params, "report-to"); present {
			directive.ReportToStatus = StatusValid
			if reportTo.kind != sfString {
				directive.ReportToStatus = StatusIgnored
			}
		}
		for _, item := range items {
			switch {
			case item.bare.kind == sfString && validPermissionsSourceExpression(item.bare.value):
				directive.Items = append(directive.Items, DirectiveItem{Kind: DirectiveString, Value: item.bare.value})
			case item.bare.kind == sfToken && (item.bare.value == "self" || item.bare.value == "*"):
				directive.Items = append(directive.Items, DirectiveItem{Kind: DirectiveToken, Value: item.bare.value})
			default:
				directive.IgnoredItems++
			}
		}
		if !entry.member.inner && directive.IgnoredItems > 0 {
			directive.Status = StatusIgnored
			directive.Items = nil
		}
		result.Tokens = append(result.Tokens, entry.key)
		result.Directives = append(result.Directives, directive)
	}
	result.Status = StatusValid
}

func evaluateXFO(result *Result, values []string) {
	set := make(map[string]bool)
	for _, field := range values {
		for _, value := range strings.Split(field, ",") {
			set[strings.ToLower(strings.Trim(value, " \t"))] = true
		}
	}
	if len(set) > 1 {
		if set["deny"] || set["sameorigin"] || set["allowall"] {
			result.Status, result.Effective = StatusAmbiguous, "DENY"
		} else {
			result.Status = StatusInvalid
		}
		return
	}
	if set["deny"] {
		result.Status, result.Effective = StatusValid, "DENY"
	} else if set["sameorigin"] {
		result.Status, result.Effective = StatusValid, "SAMEORIGIN"
	} else {
		result.Status = StatusInvalid
	}
}

func evaluateStructuredPolicy(result *Result, values, accepted []string, fallback string) {
	item, ok := parseSFItemField(strings.Join(values, ","))
	if !ok || item.bare.kind != sfToken {
		result.Status, result.Effective = StatusInvalid, fallback
		return
	}
	for _, value := range accepted {
		if item.bare.value == value {
			result.Status, result.Effective = StatusValid, value
			return
		}
	}
	result.Status, result.Effective = StatusUnrecognized, fallback
}

func evaluateCORP(result *Result, values []string) {
	if len(values) != 1 {
		result.Status = StatusInvalid
		return
	}
	value := strings.Trim(values[0], " \t")
	if value == "same-origin" || value == "same-site" || value == "cross-origin" {
		result.Status, result.Effective = StatusValid, value
		return
	}
	result.Status = StatusInvalid
}

func retain(values []string, remaining *int) ([]string, bool, bool) {
	complete, safe := len(values) <= maxValuesPerHeader, true
	limit := len(values)
	if limit > maxValuesPerHeader {
		limit = maxValuesPerHeader
	}
	out := make([]string, 0, limit)
	for _, value := range values[:limit] {
		capBytes := maxValueBytes
		if *remaining < capBytes {
			capBytes = *remaining
		}
		normalized, full, clean := normalize(value, capBytes)
		out = append(out, normalized)
		*remaining -= len(normalized)
		complete = complete && full
		safe = safe && clean
	}
	return out, complete, safe
}

func normalize(value string, limit int) (string, bool, bool) {
	var out strings.Builder
	full, clean := true, true
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			clean = false
		}
		value = value[size:]
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r, clean = utf8.RuneError, false
		}
		width := utf8.RuneLen(r)
		if width < 0 {
			width = 3
		}
		if out.Len()+width > limit {
			full = false
			break
		}
		out.WriteRune(r)
	}
	if value != "" {
		full = false
	}
	return out.String(), full, clean
}

func semanticValuesSafe(values []string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
		for _, r := range value {
			if unicode.IsControl(r) && r != '\t' || unicode.Is(unicode.Cf, r) {
				return false
			}
		}
	}
	return true
}

func splitHTTPDirectives(value string) ([]string, bool) {
	var parts []string
	start, quoted, escaped := 0, false, false
	for i := 0; i < len(value); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case !quoted && value[i] == ';':
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	return append(parts, value[start:]), true
}

func parseDirectiveValue(value string) (string, bool) {
	if validHTTPToken(value) {
		return value, true
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	var out strings.Builder
	for i := 1; i < len(value)-1; i++ {
		b := value[i]
		if b == '\\' {
			i++
			if i >= len(value)-1 {
				return "", false
			}
			b = value[i]
			if b < 0x20 && b != '\t' || b == 0x7f {
				return "", false
			}
			out.WriteByte(b)
			continue
		}
		if b == '"' || b < 0x20 && b != '\t' || b == 0x7f {
			return "", false
		}
		out.WriteByte(b)
	}
	return out.String(), true
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r > unicode.MaxASCII || !(isAlpha(byte(r)) || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}

func isAlpha(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }
func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func headerValues(headers map[string][]string, name string) []string {
	keys := make([]string, 0, 1)
	for key := range headers {
		if strings.EqualFold(key, name) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var values []string
	for _, key := range keys {
		values = append(values, headers[key]...)
	}
	return values
}
