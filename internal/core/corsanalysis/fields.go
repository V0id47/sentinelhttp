package corsanalysis

import (
	"strconv"
	"strings"
)

func parseVaryField(headers map[string][]string, remaining *int, truncated *bool) VaryField {
	values, count, state := boundedValues(headers, "Vary", remaining)
	result := VaryField{Status: state, Occurrences: count}
	if state == FieldAbsent || state == FieldInvalid {
		return result
	}
	if state == FieldTruncated {
		*truncated = true
		return result
	}
	result.Status = FieldValid
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.Trim(part, " \t")
			if !validHTTPToken(part) {
				return VaryField{Status: FieldInvalid, Occurrences: count}
			}
			if part == "*" {
				result.Star = true
			} else if strings.EqualFold(part, "Origin") {
				result.Origin = true
			}
		}
	}
	if result.Star && (result.Origin || len(values) != 1 || strings.Trim(values[0], " \t") != "*") {
		return VaryField{Status: FieldInvalid, Occurrences: count}
	}
	return result
}

func parseTokenListField(headers map[string][]string, name string, remaining *int, truncated *bool, lowercase bool) TokenListField {
	values, count, state := boundedValues(headers, name, remaining)
	result := TokenListField{Status: state, Occurrences: count}
	if state == FieldAbsent || state == FieldInvalid {
		return result
	}
	if state == FieldTruncated {
		*truncated = true
		return result
	}
	result.Status = FieldValid
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.Trim(part, " \t")
			if !validHTTPToken(part) {
				return TokenListField{Status: FieldInvalid, Occurrences: count}
			}
			if lowercase {
				part = strings.ToLower(part)
			}
			result.Tokens = append(result.Tokens, strings.Clone(part))
			if part == "*" {
				result.Wildcard = true
			}
		}
	}
	return result
}

func parseMaxAgeField(headers map[string][]string, remaining *int, truncated *bool) MaxAgeField {
	values, count, state := boundedValues(headers, "Access-Control-Max-Age", remaining)
	result := MaxAgeField{Status: state, Occurrences: count}
	if state == FieldAbsent || state == FieldInvalid {
		return result
	}
	if state == FieldTruncated {
		*truncated = true
		return result
	}
	if count != 1 {
		result.Status = FieldAmbiguous
		return result
	}
	value := strings.Trim(values[0], " \t")
	if !allDigits(value) {
		result.Status = FieldInvalid
		return result
	}
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		result.Status = FieldInvalid
		return result
	}
	result.Status, result.Seconds = FieldValid, seconds
	return result
}

func parseCacheField(headers map[string][]string, remaining *int, truncated *bool) CacheField {
	values, count, state := boundedValues(headers, "Cache-Control", remaining)
	result := CacheField{Status: state, Occurrences: count}
	if state == FieldAbsent || state == FieldInvalid {
		return result
	}
	if state == FieldTruncated {
		*truncated = true
		return result
	}
	result.Status = FieldValid
	seen := map[string]bool{}
	public, blocked := false, false
	maxAge, sharedAge := uint64(0), uint64(0)
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			part := strings.Trim(raw, " \t")
			name, argument, hasArgument := strings.Cut(part, "=")
			name = strings.ToLower(strings.Trim(name, " \t"))
			if !validHTTPToken(name) {
				return CacheField{Status: FieldInvalid, Occurrences: count}
			}
			switch name {
			case "private", "no-store", "no-cache":
				blocked = true
			case "public":
				if hasArgument {
					return CacheField{Status: FieldInvalid, Occurrences: count}
				}
				public = true
			case "max-age", "s-maxage":
				if seen[name] {
					return CacheField{Status: FieldAmbiguous, Occurrences: count}
				}
				seen[name] = true
				argument = strings.Trim(argument, " \t")
				if !hasArgument || !allDigits(argument) {
					return CacheField{Status: FieldInvalid, Occurrences: count}
				}
				age, err := strconv.ParseUint(argument, 10, 64)
				if err != nil {
					return CacheField{Status: FieldInvalid, Occurrences: count}
				}
				if name == "max-age" {
					maxAge = age
				} else {
					sharedAge = age
				}
			}
		}
	}
	// s-maxage takes precedence over max-age for shared caches, including an
	// explicit zero value.
	result.FreshShared = !blocked && (seen["s-maxage"] && sharedAge > 0 || !seen["s-maxage"] && public && maxAge > 0)
	return result
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			continue
		}
		return false
	}
	return true
}
