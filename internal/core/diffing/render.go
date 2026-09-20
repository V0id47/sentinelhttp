package diffing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sentinelhttp/internal/core/localization"
	"strconv"
	"strings"
)

var ErrFormatUnsupported = errors.New("diff_format_unsupported")

type Format string

const (
	FormatJSON     Format = "json"
	FormatTerminal Format = "terminal"
)

// Render quotes every dynamic field in the terminal view, including Unicode
// controls and bidi format characters. JSON remains the interchange view.
func Render(result Result, format Format) ([]byte, error) {
	if result.DiffVersion != Version {
		return nil, ErrFormatUnsupported
	}
	switch format {
	case FormatJSON:
		return json.Marshal(result)
	case FormatTerminal:
		var out bytes.Buffer
		fmt.Fprintf(&out, "SentinelHTTP diff %s: %s\nTarget: %s\n", Version, result.Status, strconv.QuoteToASCII(result.Target))
		for _, change := range result.Changes {
			if change.Before == "" && change.After == "" {
				fmt.Fprintf(&out, "%s %s\n", change.Kind, strconv.QuoteToASCII(change.Key))
			} else {
				fmt.Fprintf(&out, "%s %s: %s -> %s\n", change.Kind, strconv.QuoteToASCII(change.Key), strconv.QuoteToASCII(change.Before), strconv.QuoteToASCII(change.After))
			}
		}
		for _, unknown := range result.Unknown {
			fmt.Fprintf(&out, "unknown %s %s: %s\n", unknown.Section, strconv.QuoteToASCII(unknown.Key), unknown.Reason)
		}
		return out.Bytes(), nil
	default:
		return nil, ErrFormatUnsupported
	}
}

// RenderLocalized preserves JSON and the English wire-compatible terminal
// output while translating fixed status labels for other human locales.
func RenderLocalized(result Result, format Format, lang localization.Locale) ([]byte, error) {
	if format == FormatJSON || lang == localization.English {
		return Render(result, format)
	}
	if result.DiffVersion != Version || format != FormatTerminal {
		return nil, ErrFormatUnsupported
	}
	label := func(value string) string { return localization.Text(lang, strings.ReplaceAll(value, "_", " ")) }
	var out bytes.Buffer
	fmt.Fprintf(&out, "SentinelHTTP %s %s: %s\n%s: %s\n", localization.Text(lang, "diff"), Version, label(string(result.Status)), localization.Text(lang, "Target"), strconv.QuoteToASCII(result.Target))
	for _, change := range result.Changes {
		if change.Before == "" && change.After == "" {
			fmt.Fprintf(&out, "%s %s\n", label(string(change.Kind)), strconv.QuoteToASCII(change.Key))
		} else {
			fmt.Fprintf(&out, "%s %s: %s -> %s\n", label(string(change.Kind)), strconv.QuoteToASCII(change.Key), strconv.QuoteToASCII(change.Before), strconv.QuoteToASCII(change.After))
		}
	}
	for _, unknown := range result.Unknown {
		fmt.Fprintf(&out, "%s %s %s: %s\n", localization.Text(lang, "unknown"), unknown.Section, strconv.QuoteToASCII(unknown.Key), localization.Text(lang, unknown.Reason))
	}
	return out.Bytes(), nil
}
