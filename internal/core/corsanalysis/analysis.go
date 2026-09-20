package corsanalysis

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxValuesPerField = 16
	maxValueBytes     = 4096
	maxInputBytes     = 32768
)

func Analyze(in Input) Report {
	r := Report{Capture: CaptureUnavailable, Origin: OriginField{Status: FieldAbsent, Kind: OriginUnknown}, Credentials: CredentialsField{Status: FieldAbsent}}
	if !in.Captured {
		return r
	}
	r.Capture = CaptureComplete
	r.StatusCode = in.StatusCode
	remaining := maxInputBytes
	origin, count, state := boundedValues(in.Headers, "Access-Control-Allow-Origin", &remaining)
	r.Origin.Occurrences = count
	r.Origin.Status = state
	if state == FieldValid {
		r.Origin = parseOrigin(origin, count)
	} else if state == FieldTruncated {
		r.Truncated = true
	}
	credentials, count, state := boundedValues(in.Headers, "Access-Control-Allow-Credentials", &remaining)
	r.Credentials.Occurrences = count
	r.Credentials.Status = state
	if state == FieldValid {
		r.Credentials = parseCredentials(credentials, count)
	} else if state == FieldTruncated {
		r.Truncated = true
	}
	r.Vary = parseVaryField(in.Headers, &remaining, &r.Truncated)
	r.AllowMethods = parseTokenListField(in.Headers, "Access-Control-Allow-Methods", &remaining, &r.Truncated, false)
	r.AllowHeaders = parseTokenListField(in.Headers, "Access-Control-Allow-Headers", &remaining, &r.Truncated, true)
	r.ExposeHeaders = parseTokenListField(in.Headers, "Access-Control-Expose-Headers", &remaining, &r.Truncated, true)
	r.MaxAge = parseMaxAgeField(in.Headers, &remaining, &r.Truncated)
	r.Cache = parseCacheField(in.Headers, &remaining, &r.Truncated)
	return r
}

// boundedValues sorts noncanonical map keys for deterministic behavior even when
// callers construct http.Header directly rather than using Header.Add.
func boundedValues(headers map[string][]string, name string, remaining *int) ([]string, int, FieldStatus) {
	var keys []string
	count := 0
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			keys = append(keys, key)
			count += len(values)
		}
	}
	if count == 0 {
		return nil, 0, FieldAbsent
	}
	if count > maxValuesPerField {
		*remaining = 0
		return nil, count, FieldTruncated
	}
	sort.Strings(keys)
	out := make([]string, 0, count)
	invalid := false
	for _, key := range keys {
		for _, value := range headers[key] {
			if len(value) > maxValueBytes || len(value) > *remaining {
				*remaining = 0
				return nil, count, FieldTruncated
			}
			*remaining -= len(value)
			if !safeFieldValue(value) {
				invalid = true
			} else {
				out = append(out, value)
			}
		}
	}
	if invalid {
		return nil, count, FieldInvalid
	}
	return out, count, FieldValid
}

func safeFieldValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 && r != '\t' || r == 0x7f || r >= 0x80 {
			return false
		}
	}
	return true
}

func parseOrigin(values []string, count int) OriginField {
	result := OriginField{Status: FieldInvalid, Occurrences: count, Kind: OriginUnknown}
	if count != 1 {
		result.Status = FieldAmbiguous
		return result
	}
	value := strings.Trim(values[0], " \t")
	if strings.Contains(value, ",") {
		result.Status = FieldAmbiguous
		return result
	}
	switch value {
	case "*":
		result.Status, result.Kind = FieldValid, OriginWildcard
	case "null":
		result.Status, result.Kind = FieldValid, OriginNull
	default:
		if ValidSerializedOrigin(value) {
			result.Status, result.Kind, result.Value = FieldValid, OriginExplicit, strings.Clone(value)
		}
	}
	return result
}

func parseCredentials(values []string, count int) CredentialsField {
	result := CredentialsField{Status: FieldInvalid, Occurrences: count}
	if count != 1 {
		result.Status = FieldAmbiguous
		return result
	}
	if strings.Trim(values[0], " \t") == "true" {
		result.Status, result.Enabled = FieldValid, true
	}
	return result
}

// ValidSerializedOrigin checks the canonical ACAO origin grammar used by the
// analyzer. Finding consumers can reuse it when validating caller-owned reports.
func ValidSerializedOrigin(value string) bool {
	if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != value {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, "%\\") {
		return false
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return false
		}
		serialized := ip.String()
		if ip.Is4In6() {
			b := ip.As16()
			serialized = fmt.Sprintf("::ffff:%x:%x", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
		}
		if "["+serialized+"]" != strings.Split(u.Host, "]")[0]+"]" {
			return false
		}
	} else {
		if strings.ContainsAny(host, ":[]") {
			return false
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if !ip.Is4() || ip.String() != host {
				return false
			}
		} else if !validASCIIHost(host) || hostEndsInNumber(host) {
			return false
		}
	}
	port := u.Port()
	if port != "" {
		if len(port) > 5 || len(port) > 1 && port[0] == '0' {
			return false
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || u.Scheme == "http" && n == 80 || u.Scheme == "https" && n == 443 {
			return false
		}
	}
	return true
}

// The URL host parser attempts IPv4 parsing when the last domain label is a
// number. If netip could not parse a canonical IPv4 address, such a host is
// either invalid or noncanonical as a serialized origin.
func hostEndsInNumber(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if allDigits(last) {
		return true
	}
	if !strings.HasPrefix(last, "0x") {
		return false
	}
	for i := 2; i < len(last); i++ {
		b := last[i]
		if b < '0' || b > '9' && b < 'a' || b > 'f' {
			return false
		}
	}
	return true
}

func validASCIIHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' {
				continue
			}
			return false
		}
	}
	return true
}
