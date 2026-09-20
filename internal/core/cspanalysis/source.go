package cspanalysis

import "strings"

const (
	maxSourcePathBytes      = 512
	maxSourceComponentBytes = 256
)

// parseSource classifies one complete source expression. It never retains raw
// nonce or hash payloads.
func parseSource(raw string) Source {
	if raw == "" || unsafeToken(raw) {
		return Source{Kind: SourceInvalid}
	}
	if keyword, ok := parseKeyword(raw); ok {
		return Source{Kind: SourceKeyword, Keyword: keyword, Valid: true}
	}
	if raw == "*" {
		return Source{Kind: SourceWildcard, Valid: true}
	}
	if isKeywordValue(raw) {
		return Source{Kind: SourceInvalid}
	}
	if source := parseNonceOrHash(raw); source.Valid {
		return source
	}
	if source, ok := parseSchemeSource(raw); ok {
		return source
	}
	if source, ok := parseHostSource(raw); ok {
		return source
	}
	return Source{Kind: SourceInvalid}
}

// parseDirectiveSource applies directive-specific source grammar without
// weakening the general CSP source-list grammar used by other directives.
func parseDirectiveSource(directive, raw string) Source {
	source := parseSource(raw)
	if directive != "frame-ancestors" || !source.Valid {
		return source
	}
	switch source.Kind {
	case SourceScheme, SourceHost, SourceWildcard:
		return source
	case SourceKeyword:
		if source.Keyword == "self" || source.Keyword == "none" {
			return source
		}
	}
	return Source{Kind: SourceInvalid}
}

func parseKeyword(raw string) (string, bool) {
	if len(raw) < 3 || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
		return "", false
	}
	keyword := lowerASCII(raw[1 : len(raw)-1])
	if isKeywordValue(keyword) {
		return keyword, true
	}
	return "", false
}

func isKeywordValue(keyword string) bool {
	switch keyword {
	case "self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic",
		"unsafe-hashes", "report-sample", "unsafe-allow-redirects",
		"wasm-unsafe-eval", "trusted-types-eval", "report-sha256",
		"report-sha384", "report-sha512", "unsafe-webtransport-hashes":
		return true
	default:
		return false
	}
}

func parseNonceOrHash(raw string) Source {
	if len(raw) < len("'nonce-x'") || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
		return Source{Kind: SourceInvalid}
	}
	value := raw[1 : len(raw)-1]
	canonicalValue := lowerASCII(value)
	if strings.HasPrefix(canonicalValue, "nonce-") {
		if validBase64Value(value[len("nonce-"):]) {
			return Source{Kind: SourceNonce, Redacted: true, Valid: true}
		}
		return Source{Kind: SourceInvalid}
	}
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		prefix := algorithm + "-"
		if strings.HasPrefix(canonicalValue, prefix) {
			if validBase64Value(value[len(prefix):]) {
				return Source{Kind: SourceHash, Algorithm: algorithm, Redacted: true, Valid: true}
			}
			return Source{Kind: SourceInvalid}
		}
	}
	return Source{Kind: SourceInvalid}
}

func parseSchemeSource(raw string) (Source, bool) {
	if !strings.HasSuffix(raw, ":") || strings.Contains(raw, "/") {
		return Source{}, false
	}
	scheme := raw[:len(raw)-1]
	if !validScheme(scheme) || len(scheme) > maxSourceComponentBytes {
		return Source{}, false
	}
	return Source{Kind: SourceScheme, Scheme: lowerASCII(scheme), Valid: true}, true
}

func parseHostSource(raw string) (Source, bool) {
	if raw == "" || len(raw) > maxTokenBytes {
		return Source{}, false
	}

	remaining := raw
	scheme := ""
	if separator := strings.Index(remaining, "://"); separator >= 0 && separator+1 == strings.IndexByte(remaining, '/') {
		candidate := remaining[:separator]
		if !validScheme(candidate) || len(candidate) > maxSourceComponentBytes {
			return Source{}, false
		}
		scheme = lowerASCII(candidate)
		remaining = remaining[separator+3:]
	}
	hostPort, path, hasPath := strings.Cut(remaining, "/")
	if hasPath {
		path = "/" + path
		if !validSourcePath(path) {
			return Source{}, false
		}
	}
	if hostPort == "" {
		return Source{}, false
	}

	host, port, ok := splitHostPort(hostPort)
	if !ok || len(host) > maxSourceComponentBytes || len(port) > maxSourceComponentBytes {
		return Source{}, false
	}
	subdomainWildcard := false
	if strings.HasPrefix(host, "*.") {
		subdomainWildcard = true
		host = host[2:]
	}
	if host == "*" {
		if subdomainWildcard {
			return Source{}, false
		}
	} else if !validASCIIHost(host) {
		return Source{}, false
	}

	return Source{
		Kind:              SourceHost,
		Scheme:            scheme,
		Host:              lowerASCII(host),
		Port:              strings.Clone(port),
		Path:              path,
		SubdomainWildcard: subdomainWildcard,
		Valid:             true,
	}, true
}

func validBase64Value(raw string) bool {
	if raw == "" {
		return false
	}
	padding := 0
	firstPadding := len(raw)
	for i := 0; i < len(raw); i++ {
		char := raw[i]
		if char == '=' {
			if padding == 0 {
				firstPadding = i
			}
			padding++
			if padding > 2 {
				return false
			}
			continue
		}
		if padding != 0 || !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '+' || char == '/' || char == '-' || char == '_') {
			return false
		}
	}
	return firstPadding > 0
}

func isSourceListDirective(name string) bool {
	switch name {
	case "default-src", "script-src", "script-src-elem", "script-src-attr",
		"style-src", "style-src-elem", "style-src-attr", "object-src", "base-uri",
		"frame-ancestors", "form-action", "connect-src", "img-src", "font-src",
		"child-src", "frame-src", "media-src", "manifest-src", "worker-src":
		return true
	default:
		return false
	}
}

func validScheme(raw string) bool {
	if raw == "" || !((raw[0] >= 'A' && raw[0] <= 'Z') || (raw[0] >= 'a' && raw[0] <= 'z')) {
		return false
	}
	for i := 1; i < len(raw); i++ {
		char := raw[i]
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '+' || char == '-' || char == '.') {
			return false
		}
	}
	return true
}

func splitHostPort(raw string) (host, port string, ok bool) {
	if strings.Count(raw, ":") > 1 {
		return "", "", false
	}
	if separator := strings.IndexByte(raw, ':'); separator >= 0 {
		host, port = raw[:separator], raw[separator+1:]
		if port == "" {
			return "", "", false
		}
		if port == "*" {
			return host, port, true
		}
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return "", "", false
			}
		}
		return host, port, true
	}
	return raw, "", true
}

func validASCIIHost(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.HasSuffix(raw, ".") {
		raw = raw[:len(raw)-1]
	}
	if raw == "" || len(raw) > 253 {
		return false
	}
	labels := strings.Split(raw, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !asciiAlphaNumeric(label[0]) || !asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !asciiAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(char byte) bool {
	return (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
}

func validSourcePath(raw string) bool {
	return len(raw) <= maxSourcePathBytes && validSourcePathSyntax(raw)
}

func validSourcePathSyntax(raw string) bool {
	if len(raw) == 0 || raw[0] != '/' {
		return false
	}
	if len(raw) > 1 && raw[1] == '/' {
		return false
	}
	for i := 0; i < len(raw); i++ {
		char := raw[i]
		if char == '%' {
			if i+2 >= len(raw) || !hexDigit(raw[i+1]) || !hexDigit(raw[i+2]) {
				return false
			}
			i += 2
			continue
		}
		if !sourcePathCharacter(char) {
			return false
		}
	}
	return true
}

// sourceRetentionLimitExceeded identifies otherwise-valid source components
// that cannot be retained safely. Policy truncation remains in analysis.go so
// no parser path silently discards bounded evidence.
func sourceRetentionLimitExceeded(raw string) bool {
	if raw == "" || unsafeToken(raw) {
		return false
	}
	if strings.HasSuffix(raw, ":") && !strings.Contains(raw, "/") {
		return validScheme(raw[:len(raw)-1]) && len(raw)-1 > maxSourceComponentBytes
	}

	remaining := raw
	if separator := strings.Index(remaining, "://"); separator >= 0 && separator+1 == strings.IndexByte(remaining, '/') {
		candidate := remaining[:separator]
		if !validScheme(candidate) {
			return false
		}
		if len(candidate) > maxSourceComponentBytes {
			return true
		}
		remaining = remaining[separator+3:]
	}

	hostPort, path, hasPath := strings.Cut(remaining, "/")
	host, port, ok := splitHostPort(hostPort)
	if !ok {
		return false
	}
	if len(port) > maxSourceComponentBytes {
		return true
	}
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
	}
	if host != "*" && !validASCIIHost(host) {
		return false
	}
	if !hasPath {
		return false
	}
	path = "/" + path
	return len(path) > maxSourcePathBytes && validSourcePathSyntax(path)
}

func sourcePathCharacter(char byte) bool {
	return asciiAlphaNumeric(char) || char == '-' || char == '.' || char == '_' || char == '~' ||
		char == '!' || char == '$' || char == '&' || char == '\'' || char == '(' || char == ')' ||
		char == '*' || char == '+' || char == '=' || char == ':' || char == '@' || char == '/'
}

func hexDigit(char byte) bool {
	return (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')
}
