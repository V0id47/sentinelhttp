package cli

import (
	"flag"
	"io"
	"os"
	"strings"

	"sentinelhttp/internal/core/diffing"
	"sentinelhttp/internal/core/localization"
	"sentinelhttp/internal/core/reporting"
)

const diffHelp = `Usage: sentinelhttp diff OLD.json NEW.json [--format terminal|json] [--output FILE] [--lang en|es|ru|zh-CN]
Reports are parsed as untrusted input. No network requests are made.
`

func readReportFile(path string) (reporting.Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return reporting.Document{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, reporting.MaxDocumentBytes+1))
	if err != nil {
		return reporting.Document{}, err
	}
	return reporting.Parse(data)
}

func runDiff(args []string, stdout, stderr io.Writer, lang localization.Locale) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			_, _ = io.WriteString(stdout, helpText(lang, "diff"))
			return 0
		}
	}
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "terminal", "")
	output := fs.String("output", "", "")
	if len(args) >= 2 && !strings.HasPrefix(args[0], "-") && !strings.HasPrefix(args[1], "-") {
		args = append(append([]string(nil), args[2:]...), args[0], args[1])
	}
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 2 {
		return failL(stderr, lang, 2, "invalid_arguments")
	}
	if *output == "-" {
		return failL(stderr, lang, 2, "output_invalid")
	}
	view := diffing.Format(*format)
	if view != diffing.FormatJSON && view != diffing.FormatTerminal {
		return failL(stderr, lang, 2, "format_unsupported")
	}
	before, err := readReportFile(fs.Args()[0])
	if err != nil {
		return failL(stderr, lang, 2, "old_report_invalid")
	}
	after, err := readReportFile(fs.Args()[1])
	if err != nil {
		return failL(stderr, lang, 2, "new_report_invalid")
	}
	result, err := diffing.Compare(before, after)
	if err != nil {
		return failL(stderr, lang, 2, "reports_incomparable")
	}
	data, err := diffing.RenderLocalized(result, view, lang)
	if err != nil {
		return failL(stderr, lang, 4, "diff_render_failed")
	}
	if *output != "" {
		if err := writeNewFile(*output, data); err != nil {
			return failL(stderr, lang, 4, "output_write_failed")
		}
	} else if count, err := stdout.Write(data); err != nil || count != len(data) {
		return failL(stderr, lang, 4, "output_write_failed")
	}
	return 0
}
