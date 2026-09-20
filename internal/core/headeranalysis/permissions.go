package headeranalysis

import "strings"

// validPermissionsSourceExpression implements the Permissions Policy reference
// to CSP's scheme-source / host-source grammar without interpreting CSP policy.
func validPermissionsSourceExpression(value string) bool {
	if strings.HasSuffix(value, ":") && validScheme(value[:len(value)-1]) {
		return true
	}

	rest := value
	marker := strings.Index(rest, "://")
	firstSlash := strings.IndexByte(rest, '/')
	if marker >= 0 && firstSlash == marker+1 {
		if !validScheme(rest[:marker]) {
			return false
		}
		rest = rest[marker+3:]
	}
	path := ""
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		path, rest = rest[slash:], rest[:slash]
	}
	if rest == "" || !validPermissionsPath(path) {
		return false
	}

	host := rest
	if colon := strings.LastIndexByte(rest, ':'); colon >= 0 {
		if strings.IndexByte(rest, ':') != colon {
			return false
		}
		host, rest = rest[:colon], rest[colon+1:]
		if rest == "" || rest != "*" && !allDigits(rest) {
			return false
		}
	}
	return validPermissionsHost(host)
}

func validScheme(value string) bool {
	if value == "" || !isAlpha(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		b := value[i]
		if !(isAlpha(b) || isDigit(b) || b == '+' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}

func validPermissionsHost(value string) bool {
	if value == "*" {
		return true
	}
	if strings.HasPrefix(value, "*.") {
		value = value[2:]
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !(isAlpha(label[i]) || isDigit(label[i]) || label[i] == '-') {
				return false
			}
		}
	}
	return true
}

func validPermissionsPath(value string) bool {
	if value == "" {
		return true
	}
	if value[0] != '/' {
		return false
	}
	if len(value) > 1 && value[1] == '/' {
		return false
	}
	for i := 1; i < len(value); i++ {
		b := value[i]
		if b == '%' {
			if i+2 >= len(value) || !isHex(value[i+1]) || !isHex(value[i+2]) {
				return false
			}
			i += 2
			continue
		}
		if !(isAlpha(b) || isDigit(b) || strings.ContainsRune("-._~!$&'()*+=:@/", rune(b))) {
			return false
		}
	}
	return true
}

func isHex(b byte) bool {
	return isDigit(b) || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}
