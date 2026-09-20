package reporting

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const preflightMaxDepth = 32
const preflightMaxObjectMembers = 64
const preflightUnknownArrayLimit = 256

// preflightJSON bounds the shape of untrusted JSON before Decode allocates
// slices in Document. It does not replace the typed decode or Validate.
func preflightJSON(data []byte) error {
	if len(data) > MaxDocumentBytes {
		return ErrReportLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrReportMalformed
	}
	if err := preflightObject(decoder, nil, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrReportMalformed
	}
	return nil
}

func preflightObject(decoder *json.Decoder, path []string, depth int) error {
	count := 0
	seen := make([]string, 0, 8)
	for decoder.More() {
		count++
		if count > preflightMaxObjectMembers {
			return ErrReportLimit
		}
		key, err := decoder.Token()
		if err != nil {
			return ErrReportMalformed
		}
		name, ok := key.(string)
		if !ok {
			return ErrReportMalformed
		}
		// encoding/json accepts duplicate and case-folded member names, taking
		// the later value. Reject that ambiguity before typed decoding so all
		// report consumers see one meaning for each object member.
		for _, previous := range seen {
			if strings.EqualFold(previous, name) {
				return ErrReportMalformed
			}
		}
		seen = append(seen, name)
		if err := preflightValue(decoder, append(path, name), depth); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return ErrReportMalformed
	}
	return nil
}

func preflightArray(decoder *json.Decoder, path []string, depth int) error {
	limit := preflightArrayLimit(path)
	count := 0
	for decoder.More() {
		count++
		if count > limit {
			return ErrReportLimit
		}
		if err := preflightValue(decoder, path, depth); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(']') {
		return ErrReportMalformed
	}
	return nil
}

func preflightValue(decoder *json.Decoder, path []string, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrReportMalformed
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= preflightMaxDepth {
		return ErrReportLimit
	}
	switch delim {
	case '{':
		return preflightObject(decoder, path, depth+1)
	case '[':
		return preflightArray(decoder, path, depth+1)
	default:
		return ErrReportMalformed
	}
}

// EqualFold mirrors encoding/json's case-insensitive field matching. Paths
// reuse decoder-owned key strings instead of concatenating attacker input.
func preflightPath(path []string, names ...string) bool {
	if len(path) != len(names) {
		return false
	}
	for i, name := range names {
		if !strings.EqualFold(path[i], name) {
			return false
		}
	}
	return true
}

func preflightArrayLimit(path []string) int {
	switch {
	case preflightPath(path, "requests"):
		return 32
	case preflightPath(path, "redirects"):
		return 21
	case preflightPath(path, "findings"):
		return 256
	case preflightPath(path, "limitations"):
		return 64
	case preflightPath(path, "requests", "resolution", "addresses"):
		return 64
	case preflightPath(path, "requests", "tls", "certificates"):
		return 16
	case preflightPath(path, "requests", "tls", "certificates", "sans"):
		return 128
	case preflightPath(path, "requests", "headers"):
		return 10
	case preflightPath(path, "requests", "cookies"):
		return 128
	case preflightPath(path, "requests", "csp", "policies"):
		return 64
	case preflightPath(path, "requests", "csp", "policies", "directives"):
		return 64
	case preflightPath(path, "requests", "csp", "policies", "directives", "sources"):
		return 256
	case preflightPath(path, "requests", "csp", "observations"):
		return 64
	case preflightPath(path, "requests", "cors", "observations"):
		return 64
	case preflightPath(path, "cors_probe", "attempts"):
		return 3
	case preflightPath(path, "cors_probe", "attempts", "cors", "observations"):
		return 64
	case preflightPath(path, "findings", "evidence"):
		return 16
	case preflightPath(path, "findings", "references"):
		return 16
	case preflightPath(path, "findings", "limitations"):
		return 16
	case preflightPath(path, "score", "components"):
		return 4
	case preflightPath(path, "score", "components", "penalties"):
		return 16
	case preflightPath(path, "score", "limitations"):
		return 16
	default:
		return preflightUnknownArrayLimit
	}
}
