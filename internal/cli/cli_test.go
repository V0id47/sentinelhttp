package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"sentinelhttp/internal/core/diffing"
	"sentinelhttp/internal/core/reporting"
)

func TestRunScanDefaultsToOneBoundedGET(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", server.URL + "/private?token=secret", "--allow-private", "--format", "json"}, &out, &errOut)
	if code != 0 || hits.Load() != 1 || errOut.Len() != 0 {
		t.Fatalf("exit=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
	doc, err := reporting.Parse(out.Bytes())
	if err != nil || doc.ScanConfig.TraceEnabled || doc.ScanConfig.CORSProbeEnabled || doc.ScanConfig.MaxRequests != 16 || strings.Contains(out.String(), "token=secret") {
		t.Fatalf("unexpected report: %v", err)
	}
}

func TestRunRejectsBudgetBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer server.Close()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--trace-redirects", "--probe-cors", "--max-requests", "2"}, &out, &errOut)
	if code == 0 || hits.Load() != 0 || out.Len() != 0 || strings.Contains(errOut.String(), server.URL) {
		t.Fatalf("budget preflight failed: code=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
}

func TestRunOutputDoesNotClobberExistingFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--format", "json", "--output", path}, &out, &errOut)
	data, err := os.ReadFile(path)
	if code == 0 || err != nil || string(data) != "existing" || out.Len() != 0 {
		t.Fatalf("existing output overwritten: code=%d err=%v data=%q", code, err, data)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp file leaked: entries=%v err=%v", entries, err)
	}
}

func TestRunVersionAndBadTargetAreSafe(t *testing.T) {
	var out, errOut bytes.Buffer
	if Run(context.Background(), []string{"version"}, &out, &errOut) != 0 || !strings.Contains(out.String(), reporting.ToolVersion) {
		t.Fatal("version failed")
	}
	out.Reset()
	errOut.Reset()
	secret := "https://user:secret@example.com/private?token=secret"
	if Run(context.Background(), []string{"scan", secret, "--format", "json"}, &out, &errOut) == 0 || strings.Contains(errOut.String(), "secret") || out.Len() != 0 {
		t.Fatalf("unsafe target error: %q", errOut.String())
	}
}

func TestRunRedirectAndProbeAreExplicitAndBounded(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	var out, errOut bytes.Buffer
	args := []string{"scan", server.URL + "/start", "--allow-private", "--trace-redirects", "--probe-cors", "--max-requests", "5", "--format", "json"}
	if Run(context.Background(), args, &out, &errOut) == 0 || hits.Load() != 0 {
		t.Fatal("worst-case budget was not enforced before requests")
	}
	out.Reset()
	errOut.Reset()
	args = append(args, "--max-redirects", "1")
	if code := Run(context.Background(), args, &out, &errOut); code != 0 {
		t.Fatalf("opt-in scan failed: code=%d stderr=%q", code, errOut.String())
	}
	if hits.Load() != 5 {
		t.Fatalf("expected 2 redirect GETs and 3 CORS probes, got %d", hits.Load())
	}
	doc, err := reporting.Parse(out.Bytes())
	if err != nil || len(doc.Redirects) != 2 || doc.CORSProbe == nil || len(doc.CORSProbe.Attempts) != 3 || !doc.ScanConfig.TraceEnabled || !doc.ScanConfig.CORSProbeEnabled {
		t.Fatalf("missing opt-in evidence: %v", err)
	}
}

func TestRunHTTPSWithoutBundleFailsBeforeNetworkOnNativePlatforms(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skip("native trust guard applies only to native-root platforms")
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "https://localhost:8443/private?token=secret", "--allow-private"}, &out, &errOut); code == 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "tls_ca_bundle_required") || strings.Contains(errOut.String(), "token=secret") {
		t.Fatalf("native HTTPS guard failed: code=%d stderr=%q", code, errOut.String())
	}
}

func TestRunScopeBlockDoesNotSendHTTPRequest(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer server.Close()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", server.URL + "/private?token=secret", "--format", "json"}, &out, &errOut)
	if code != 3 || hits.Load() != 0 || strings.Contains(errOut.String(), "token=secret") {
		t.Fatalf("scope block failed: exit=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
	if _, err := reporting.Parse(out.Bytes()); err != nil {
		t.Fatalf("blocked request did not yield a safe partial report: %v", err)
	}
}

func TestRunPrivateTraceReportsEffectiveSameHostPolicy(t *testing.T) {
	var hits atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", strings.Replace(server.URL, "127.0.0.1", "localhost", 1)+"/final")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", server.URL + "/start", "--allow-private", "--trace-redirects", "--format", "json"}, &out, &errOut)
	if code != 0 || hits.Load() != 1 {
		t.Fatalf("cross-host private redirect was not stopped locally: exit=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
	doc, err := reporting.Parse(out.Bytes())
	if err != nil || !doc.ScanConfig.SameHost || doc.RedirectStop != "same_host_blocked" {
		t.Fatalf("effective private same-host policy not reported: %v stop=%q", err, doc.RedirectStop)
	}
}

func TestRunWritesNewPrivateReportFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "report.json")
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--format", "json", "--output", path}, &out, &errOut); code != 0 || out.Len() != 0 {
		t.Fatalf("report file failed: code=%d stderr=%q", code, errOut.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reporting.Parse(data); err != nil {
		t.Fatalf("written report was invalid: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("report file permissions are not private: %v", info.Mode())
	}
	if runtime.GOOS == "windows" {
		aclPath := filepath.Join(t.TempDir(), "acl.txt")
		if output, err := exec.Command("icacls", path, "/save", aclPath).CombinedOutput(); err != nil {
			t.Fatalf("cannot inspect report ACL: %v %q", err, output)
		}
		raw, err := os.ReadFile(aclPath)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw)%2 != 0 {
			t.Fatal("invalid ACL export")
		}
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
		}
		acl := string(utf16.Decode(units))
		if !strings.Contains(acl, "D:P") || strings.Contains(acl, ";;;BU") || strings.Contains(acl, "S-1-5-32-545") {
			t.Fatalf("report inherited broad ACL: %q", acl)
		}
	}
}

func TestRunInvalidOptionsNeverStartNetwork(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown command": {"remove"},
		"version operand": {"version", "extra"},
		"missing target":  {"scan"},
		"bad timeout":     {"scan", "http://localhost/", "--timeout", "61s"},
		"bad format":      {"scan", "http://localhost/", "--format", "xml"},
		"bad budget":      {"scan", "http://localhost/", "--max-requests", "0"},
		"invalid CA":      {"scan", "http://localhost/", "--allow-private", "--ca-file", "missing.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
				t.Fatalf("invalid invocation accepted: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestReadCAPEMIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(path, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readCAPEM(path); err != nil || string(data) != "pem" {
		t.Fatalf("small CA file read failed: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, 1<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAPEM(path); err == nil {
		t.Fatal("oversized CA file accepted")
	}
}

func TestRunHelpAndTargetAfterFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--help"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "--max-requests") {
		t.Fatalf("scan help failed: code=%d", code)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"scan", "--allow-private", "--format", "json", server.URL}, &out, &errOut); code != 0 {
		t.Fatalf("target-last form failed: code=%d stderr=%q", code, errOut.String())
	}
	if _, err := reporting.Parse(out.Bytes()); err != nil {
		t.Fatalf("target-last report invalid: %v", err)
	}
}

func TestRunRejectsInvalidPEMBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--ca-file", path}, &out, &errOut)
	if code != 2 || hits.Load() != 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "lab_ca_invalid") {
		t.Fatalf("invalid PEM was not rejected before network: code=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
}

func TestRunDiffReadsValidatedReportsWithoutNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	var scanOut, scanErr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--format", "json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("fixture scan failed: %d %q", code, scanErr.String())
	}
	server.Close()
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	for _, path := range []string{oldPath, newPath} {
		if err := os.WriteFile(path, scanOut.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"diff", oldPath, newPath, "--format", "json"}, &out, &errOut); code != 0 {
		t.Fatalf("diff failed: %d %q", code, errOut.String())
	}
	var result diffing.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Status != diffing.StatusComparable || len(result.Changes) != 0 {
		t.Fatalf("identical diff invalid: %v %+v", err, result)
	}
	if err := os.WriteFile(newPath, []byte(`{"schema_version":"2.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"diff", oldPath, newPath, "--format", "json"}, &out, &errOut); code == 0 || out.Len() != 0 || strings.Contains(errOut.String(), dir) {
		t.Fatalf("invalid report was accepted or path leaked: code=%d stderr=%q", code, errOut.String())
	}
}

func TestRunDiffRejectsOversizedInputAndPreservesOutput(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large.json")
	if err := os.WriteFile(large, bytes.Repeat([]byte{'x'}, reporting.MaxDocumentBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"diff", large, large}, &out, &errOut); code != 2 || out.Len() != 0 || strings.Contains(errOut.String(), large) {
		t.Fatalf("oversized input accepted or leaked: %d %q", code, errOut.String())
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	var report bytes.Buffer
	if code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--format", "json"}, &report, &errOut); code != 0 {
		t.Fatalf("fixture scan failed: %d %q", code, errOut.String())
	}
	server.Close()
	input := filepath.Join(dir, "report.json")
	output := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(input, report.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("KEEP"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"diff", input, input, "--output", output}, &out, &errOut); code != 4 || out.Len() != 0 {
		t.Fatalf("existing output was overwritten: %d %q", code, errOut.String())
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "KEEP" {
		t.Fatalf("existing output changed: %q %v", data, err)
	}
}

type urlCaptureWriter struct{ url chan string }

func (w urlCaptureWriter) Write(data []byte) (int, error) {
	w.url <- strings.TrimSpace(string(data))
	return len(data), nil
}

func TestRunServeValidatedReportLifecycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	var report, scanErr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", server.URL, "--allow-private", "--format", "json"}, &report, &scanErr); code != 0 {
		t.Fatalf("fixture scan failed: %d %q", code, scanErr.String())
	}
	server.Close()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, report.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	urlCh := make(chan string, 1)
	codeCh := make(chan int, 1)
	var errOut bytes.Buffer
	go func() {
		codeCh <- Run(ctx, []string{"serve", path, "--compare", path, "--no-open"}, urlCaptureWriter{urlCh}, &errOut)
	}()
	var url string
	select {
	case url = <-urlCh:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not publish URL")
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("serve URL is not loopback: %q", url)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(url + "/api/report")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("API failed: %d %v", resp.StatusCode, err)
	}
	if _, err := reporting.Parse(data); err != nil {
		t.Fatalf("served report invalid: %v", err)
	}
	diffResponse, err := client.Get(url + "/api/diff")
	if err != nil {
		t.Fatal(err)
	}
	var diff diffing.Result
	err = json.NewDecoder(diffResponse.Body).Decode(&diff)
	diffResponse.Body.Close()
	if err != nil || diffResponse.StatusCode != http.StatusOK || diff.Status != diffing.StatusComparable {
		t.Fatalf("served diff invalid: %d %v %+v", diffResponse.StatusCode, err, diff)
	}
	cancel()
	select {
	case code := <-codeCh:
		if code != 0 {
			t.Fatalf("serve exit %d: %q", code, errOut.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestRunServeRejectsInvalidAndOversizedReport(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"invalid.json": []byte(`{"schema_version":"2.0"}`),
		"large.json":   bytes.Repeat([]byte{'x'}, reporting.MaxDocumentBytes+1),
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), []string{"serve", path, "--no-open"}, &out, &errOut); code != 2 || out.Len() != 0 || strings.Contains(errOut.String(), path) {
			t.Fatalf("invalid report accepted or path leaked: %d %q", code, errOut.String())
		}
	}
}
