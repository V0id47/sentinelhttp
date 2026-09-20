// Package redirectanalysis classifies redirect response data without network I/O.
package redirectanalysis

import (
	"net/url"
	"unicode"
	"unicode/utf8"
)

const maxURLBytes = 8192

type LocationStatus string

const (
	LocationNotApplicable LocationStatus = "not_applicable"
	LocationMissing       LocationStatus = "missing"
	LocationValid         LocationStatus = "valid"
	LocationAmbiguous     LocationStatus = "ambiguous"
	LocationInvalid       LocationStatus = "invalid"
)

func IsFollowStatus(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// ResolveLocation returns a transient sensitive URL. Its caller must validate
// the target and must not place the candidate in default reports or errors.
func ResolveLocation(currentURL string, values []string) (string, LocationStatus) {
	if len(values) == 0 {
		return "", LocationMissing
	}
	if len(values) != 1 {
		return "", LocationAmbiguous
	}
	value := values[0]
	if len(value) == 0 || len(value) > maxURLBytes || !utf8.ValidString(value) {
		return "", LocationInvalid
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) || r == '\\' {
			return "", LocationInvalid
		}
	}
	base, err := url.Parse(currentURL)
	if err != nil || base.Host == "" || base.Scheme != "http" && base.Scheme != "https" {
		return "", LocationInvalid
	}
	ref, err := url.Parse(value)
	if err != nil {
		return "", LocationInvalid
	}
	resolved := base.ResolveReference(ref).String()
	if len(resolved) > maxURLBytes {
		return "", LocationInvalid
	}
	return resolved, LocationValid
}
