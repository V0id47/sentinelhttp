package cli

import (
	"context"
	"flag"
	"io"
	"strings"

	"sentinelhttp/internal/core/localization"
	"sentinelhttp/internal/dashboard"
)

const serveHelp = `Usage: sentinelhttp serve REPORT.json [--compare OLD.json] [--no-open] [--lang en|es|ru|zh-CN]
Serve one validated report on a random 127.0.0.1 port. Press Ctrl+C to stop.
`

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer, lang localization.Locale) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			_, _ = io.WriteString(stdout, helpText(lang, "serve"))
			return 0
		}
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	noOpen := fs.Bool("no-open", false, "")
	comparePath := fs.String("compare", "", "")
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string(nil), args[1:]...), args[0])
	}
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 1 || fs.Args()[0] == "-" {
		return failL(stderr, lang, 2, "invalid_arguments")
	}
	doc, err := readReportFile(fs.Args()[0])
	if err != nil {
		return failL(stderr, lang, 2, "report_invalid")
	}
	var server *dashboard.Server
	if *comparePath == "" {
		server, err = dashboard.New(doc)
	} else {
		baseline, readErr := readReportFile(*comparePath)
		if readErr != nil {
			return failL(stderr, lang, 2, "comparison_report_invalid")
		}
		server, err = dashboard.NewWithBaseline(doc, baseline)
	}
	if err != nil {
		return failL(stderr, lang, 4, "dashboard_start_failed")
	}
	defer server.Close()
	if _, err := io.WriteString(stdout, server.URL()+"\n"); err != nil {
		return failL(stderr, lang, 4, "output_write_failed")
	}
	if !*noOpen {
		if err := openBrowser(server.URL()); err != nil {
			_ = failL(stderr, lang, 0, "browser_open_failed")
		}
	}
	if err := server.Serve(ctx); err != nil {
		return failL(stderr, lang, 4, "dashboard_serve_failed")
	}
	return 0
}
