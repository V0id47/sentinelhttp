package reporting

// safeDirectiveName retains only reviewed CSP directive identifiers. Unknown
// extension tokens can contain secrets and are represented by a fixed label.
func safeDirectiveName(name string) string {
	switch name {
	case "default-src", "script-src", "script-src-elem", "script-src-attr",
		"style-src", "style-src-elem", "style-src-attr", "object-src", "base-uri",
		"frame-ancestors", "form-action", "connect-src", "img-src", "font-src",
		"child-src", "frame-src", "media-src", "manifest-src", "worker-src",
		"report-uri", "report-to", "upgrade-insecure-requests", "block-all-mixed-content",
		"require-trusted-types-for", "trusted-types", "sandbox", "navigate-to",
		"plugin-types", "reflected-xss":
		return name
	default:
		return "unknown"
	}
}
