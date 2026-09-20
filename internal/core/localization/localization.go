// Package localization translates fixed product prose without changing raw
// evidence, protocol identifiers or the canonical JSON schema.
package localization

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

//go:embed catalog.json
var catalogBytes []byte

type Locale string

const (
	English Locale = "en"
	Spanish Locale = "es"
	Russian Locale = "ru"
	Chinese Locale = "zh-CN"
)

var ErrUnsupported = errors.New("language_unsupported")

var catalog = func() map[string][3]string {
	var parsed map[string][3]string
	if err := json.Unmarshal(catalogBytes, &parsed); err != nil {
		panic(err)
	}
	for _, values := range parsed {
		for _, value := range values {
			if value == "" {
				panic("empty localization entry")
			}
		}
	}
	return parsed
}()

// Parse accepts the supported primary language subtags and a Chinese region.
func Parse(value string) (Locale, error) {
	switch strings.ToLower(value) {
	case "en", "en-us", "en-gb":
		return English, nil
	case "es", "es-ar", "es-es":
		return Spanish, nil
	case "ru", "ru-ru":
		return Russian, nil
	case "zh", "zh-cn", "zh-hans":
		return Chinese, nil
	default:
		return "", ErrUnsupported
	}
}

func Text(lang Locale, english string) string {
	if lang == English {
		return english
	}
	values, ok := catalog[english]
	if !ok {
		return english
	}
	switch lang {
	case Spanish:
		return values[0]
	case Russian:
		return values[1]
	case Chinese:
		return values[2]
	default:
		return english
	}
}

// ReportLimitation translates only shipped explanatory copy. An imported
// report's arbitrary limitation text is retained verbatim.
func ReportLimitation(lang Locale, value string) string {
	switch value {
	case "SentinelHTTP reports observations from performed checks. Absence of findings does not prove an application is secure.",
		"The report does not demonstrate exploitability, authenticated exposure or complete site coverage.",
		"Network, HTTP, TLS and browser behavior outside the captured operations was not assessed.",
		"CORS probe was not run because the primary request did not complete.",
		"This score reflects only the checks performed on one captured response.",
		"It is not a security level, vulnerability count, exploitability estimate or site-wide guarantee.",
		"Missing or inapplicable controls do not earn points.":
		return Text(lang, value)
	default:
		return value
	}
}

func CatalogSize() int { return len(catalog) }

func FormatTime(lang Locale, value time.Time) string {
	switch lang {
	case Spanish:
		return value.Format("02/01/2006 15:04:05 Z07:00")
	case Russian:
		return value.Format("02.01.2006 15:04:05 Z07:00")
	case Chinese:
		return value.Format("2006年01月02日 15:04:05 Z07:00")
	default:
		return value.Format("2006-01-02T15:04:05Z07:00")
	}
}
