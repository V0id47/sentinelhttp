// Package cli owns SentinelHTTP process arguments, scan I/O and the only scan
// orchestration path. Core analyzers and reporting remain free of I/O.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/localization"
	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/reporting"
)

const scanHelp = `Usage: sentinelhttp scan TARGET [options] [--lang en|es|ru|zh-CN]
Assess only systems you own or are authorized to test.
Options: --format terminal|json|markdown|html, --output FILE,
  --allow-private, --same-host, --trace-redirects, --probe-cors,
  --max-redirects 1..20 (default 10), --max-requests 1..24 (default 16),
  --timeout DURATION (default 15s, max 60s),
  --connect-timeout DURATION (default 3s, max 10s),
  --max-response-bytes N (default 2097152, max 8388608), --ca-file PEM.
HTTPS on Windows/macOS/iOS requires --ca-file for offline verification.
`

// Run returns 0 for success, 2 for invalid invocation, 3 for an incomplete
// scan, and 4 for report/output failure. Error text contains only fixed codes.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return 2
	}
	lang, args, langErr := takeLanguage(args)
	if langErr != nil {
		return failL(stderr, localization.English, 2, "language_unsupported")
	}
	if len(args) == 0 {
		if lang == localization.English {
			_, _ = io.WriteString(stderr, "usage: sentinelhttp scan TARGET | diff OLD.json NEW.json | serve REPORT.json | version\n")
		} else {
			_, _ = io.WriteString(stderr, helpText(lang, "scan"))
		}
		return 2
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return failL(stderr, lang, 2, "invalid_arguments")
		}
		_, _ = fmt.Fprintf(stdout, "%s %s\n", reporting.Tool, reporting.ToolVersion)
		return 0
	case "help", "--help", "-h":
		_, _ = io.WriteString(stdout, helpText(lang, "scan"))
		return 0
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr, lang)
	case "diff":
		return runDiff(args[1:], stdout, stderr, lang)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr, lang)
	default:
		return failL(stderr, lang, 2, "unknown_command")
	}
}

func fail(stderr io.Writer, exit int, code string) int {
	_, _ = io.WriteString(stderr, code+"\n")
	return exit
}

func failL(stderr io.Writer, lang localization.Locale, exit int, code string) int {
	if lang == localization.English {
		return fail(stderr, exit, code)
	}
	parts := strings.SplitN(code, ":", 2)
	base := parts[0]
	message := localization.Text(lang, "error."+base)
	if message == "error."+base {
		message = localization.Text(lang, "error.generic")
	}
	if len(parts) == 2 {
		detail := localization.Text(lang, "error."+parts[1])
		if detail != "error."+parts[1] {
			message += " " + detail
		}
	}
	_, _ = io.WriteString(stderr, code+": "+message+"\n")
	return exit
}

func takeLanguage(args []string) (localization.Locale, []string, error) {
	lang := localization.English
	filtered := make([]string, 0, len(args))
	seen := false
	for i := 0; i < len(args); i++ {
		value := ""
		if args[i] == "--lang" {
			if i+1 >= len(args) || seen {
				return "", nil, localization.ErrUnsupported
			}
			i++
			value = args[i]
		} else if strings.HasPrefix(args[i], "--lang=") {
			if seen {
				return "", nil, localization.ErrUnsupported
			}
			value = strings.TrimPrefix(args[i], "--lang=")
		} else {
			filtered = append(filtered, args[i])
			continue
		}
		seen = true
		parsed, err := localization.Parse(value)
		if err != nil {
			return "", nil, err
		}
		lang = parsed
	}
	return lang, filtered, nil
}

type scanOptions struct {
	allowPrivate, sameHost, trace, probe bool
	maxRedirects, maxRequests            int
	timeout, connectTimeout              time.Duration
	maxResponseBytes                     int64
	caFile, output                       string
	format                               reporting.Format
	target                               network.Target
}

func parseScan(args []string) (scanOptions, string) {
	var opts scanOptions
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&opts.allowPrivate, "allow-private", false, "")
	fs.BoolVar(&opts.sameHost, "same-host", false, "")
	fs.BoolVar(&opts.trace, "trace-redirects", false, "")
	fs.BoolVar(&opts.probe, "probe-cors", false, "")
	fs.IntVar(&opts.maxRedirects, "max-redirects", 10, "")
	fs.IntVar(&opts.maxRequests, "max-requests", 16, "")
	fs.DurationVar(&opts.timeout, "timeout", 15*time.Second, "")
	fs.DurationVar(&opts.connectTimeout, "connect-timeout", 3*time.Second, "")
	fs.Int64Var(&opts.maxResponseBytes, "max-response-bytes", 2<<20, "")
	fs.StringVar(&opts.caFile, "ca-file", "", "")
	fs.StringVar(&opts.output, "output", "", "")
	format := fs.String("format", "terminal", "")
	// Standard flag parsing stops at the first operand. The documented
	// TARGET-first form is normalized without parsing URL text as flags.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string(nil), args[1:]...), args[0])
	}
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 1 {
		return scanOptions{}, "invalid_arguments"
	}
	if opts.maxRedirects < 1 || opts.maxRedirects > 20 || opts.maxRequests < 1 || opts.maxRequests > 24 || opts.timeout <= 0 || opts.timeout > 60*time.Second || opts.connectTimeout <= 0 || opts.connectTimeout > 10*time.Second || opts.maxResponseBytes < 1 || opts.maxResponseBytes > 8<<20 {
		return scanOptions{}, "config_invalid"
	}
	needed := 1
	if opts.trace {
		needed = opts.maxRedirects + 1
	}
	if opts.probe {
		needed += 3
	}
	if needed > opts.maxRequests {
		return scanOptions{}, "request_budget_exceeded"
	}
	opts.format = reporting.Format(*format)
	switch opts.format {
	case reporting.FormatTerminal, reporting.FormatJSON, reporting.FormatMarkdown, reporting.FormatHTML:
	default:
		return scanOptions{}, "format_unsupported"
	}
	if opts.output == "-" {
		return scanOptions{}, "output_invalid"
	}
	var err error
	opts.target, err = network.ParseTarget(fs.Args()[0])
	if err != nil {
		return scanOptions{}, string(network.ErrorCode(err))
	}
	if opts.target.Scheme() == "https" && opts.caFile == "" && (runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios") {
		return scanOptions{}, string(httpclient.CABundleRequired)
	}
	return opts, ""
}

func readCAPEM(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return nil, fmt.Errorf("ca_invalid")
	}
	return data, nil
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer, lang localization.Locale) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			_, _ = io.WriteString(stdout, helpText(lang, "scan"))
			return 0
		}
	}
	opts, code := parseScan(args)
	if code != "" {
		return failL(stderr, lang, 2, code)
	}
	ca, err := readCAPEM(opts.caFile)
	if err != nil {
		return failL(stderr, lang, 2, "ca_file_invalid")
	}
	effectiveSameHost := opts.sameHost || opts.allowPrivate
	boundary, err := network.NewBoundary(opts.target, network.Policy{AllowPrivate: opts.allowPrivate, SameHost: effectiveSameHost, ConnectTimeout: opts.connectTimeout})
	if err != nil {
		return failL(stderr, lang, 2, "scope_config_invalid")
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: opts.timeout, MaxResponseBytes: opts.maxResponseBytes, LabCAPEM: ca})
	if err != nil {
		return failL(stderr, lang, 2, string(httpclient.ErrorCode(err)))
	}
	scanCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	started := time.Now().UTC()
	var primary *httpclient.Response
	var exchanges []*httpclient.Response
	var trace *httpclient.RedirectTrace
	var probe *httpclient.CORSProbeResult
	var scanErr error
	probeTarget := opts.target
	if opts.trace {
		trace, scanErr = client.TraceRedirects(scanCtx, opts.target, httpclient.RedirectOptions{MaxRedirects: opts.maxRedirects, SameHost: effectiveSameHost})
		if trace != nil {
			for _, hop := range trace.Hops {
				if hop.Response != nil {
					exchanges = append(exchanges, hop.Response)
					if hop.Response.Metadata().StatusCode != 0 {
						primary, probeTarget = hop.Response, hop.Target
					}
				}
			}
		}
	} else {
		primary, scanErr = client.Do(scanCtx, opts.target, httpclient.GET)
		if primary != nil {
			exchanges = append(exchanges, primary)
		}
	}
	if opts.probe && scanErr == nil && primary != nil && primary.Metadata().StatusCode != 0 {
		probe, scanErr = client.ProbeCORS(scanCtx, probeTarget)
	}
	config := reporting.ScanConfig{
		AllowPrivate: opts.allowPrivate, SameHost: effectiveSameHost, TraceEnabled: opts.trace,
		MaxRedirects: opts.maxRedirects, MaxRequests: opts.maxRequests,
		TimeoutMillis: opts.timeout.Milliseconds(), ConnectTimeoutMillis: opts.connectTimeout.Milliseconds(),
		MaxResponseBytes: opts.maxResponseBytes, CORSProbeEnabled: probe != nil,
		TrustBundleProvided: len(ca) != 0,
	}
	doc, err := reporting.Build(reporting.Input{InitialTarget: opts.target, StartedAt: started, CompletedAt: time.Now().UTC(), Config: config, Primary: primary, Exchanges: exchanges, Trace: trace, CORSProbe: probe})
	if err != nil {
		return failL(stderr, lang, 4, "report_build_failed")
	}
	if opts.probe && probe == nil {
		doc.Limitations = append(doc.Limitations, "CORS probe was not run because the primary request did not complete.")
	}
	data, err := reporting.RenderLocalized(doc, opts.format, lang)
	if err != nil {
		return failL(stderr, lang, 4, "report_render_failed")
	}
	if opts.output != "" {
		if err := writeNewFile(opts.output, data); err != nil {
			return failL(stderr, lang, 4, "output_write_failed")
		}
	} else if count, err := stdout.Write(data); err != nil || count != len(data) {
		return failL(stderr, lang, 4, "output_write_failed")
	}
	if scanErr != nil {
		return failL(stderr, lang, 3, "scan_incomplete:"+string(httpclient.ErrorCode(scanErr)))
	}
	return 0
}
