package reporting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode"

	"sentinelhttp/internal/core/httpclient"
	"sentinelhttp/internal/core/network"
)

func hostileReport(t *testing.T) Document {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "session_id=private; SameSite=Lax")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	target, err := network.ParseTarget(server.URL + "/secret?token=private")
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := network.NewBoundary(target, network.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := httpclient.New(boundary, httpclient.Config{TotalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), target, httpclient.GET)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	doc, err := Build(Input{InitialTarget: target, StartedAt: at, CompletedAt: at.Add(time.Second), Primary: response})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) == 0 || len(doc.Requests[0].Cookies) == 0 {
		t.Fatal("fixture lacks findings/cookies")
	}
	doc.Findings[0].Observation = "\x1b[31m<script>alert(1)</script> # heading | `code` **bold**\u202e"
	doc.Findings[0].Remediation = "[click](https://evil.example)\n## injected"
	doc.Requests[0].Cookies[0].Name = "<img src=x onerror=alert(1)>\x1b[0m"
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatalf("hostile but structurally valid report was rejected: %v", err)
	}
	return parsed
}

func TestRenderHostileTerminalAndMarkdown(t *testing.T) {
	doc := hostileReport(t)
	terminal, err := Render(doc, FormatTerminal)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range string(terminal) {
		if r == '\n' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("terminal contains active control %U", r)
		}
	}
	if !strings.Contains(string(terminal), "performed checks") || !strings.Contains(string(terminal), "coverage") {
		t.Fatalf("terminal lacks scope/coverage: %s", terminal)
	}
	if !strings.Contains(string(terminal), "Evidence: exchange=") || !strings.Contains(string(terminal), "Score limitation:") {
		t.Fatalf("terminal lacks evidence or score scope: %s", terminal)
	}
	markdown, err := Render(doc, FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	text := string(markdown)
	for _, unsafe := range []string{"<script>", "<img", "## injected", "[click](https://evil.example)", "| `code`"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("markdown contains injected syntax %q: %s", unsafe, text)
		}
	}
	if !strings.Contains(text, "performed checks") || !strings.Contains(text, "coverage") {
		t.Fatalf("markdown lacks scope/coverage: %s", text)
	}
	if !strings.Contains(text, "Evidence: exchange ") || !strings.Contains(text, "Score limitation:") {
		t.Fatalf("markdown lacks evidence or score scope: %s", text)
	}
}

func TestRenderHostileHTMLAndJSON(t *testing.T) {
	doc := hostileReport(t)
	html, err := Render(doc, FormatHTML)
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, unsafe := range []string{"<script>", "<img src=x", "onerror=alert", "https://evil.example\"", "<link ", "src=\"http"} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("HTML contains active content %q: %s", unsafe, text)
		}
	}
	if !strings.Contains(text, "&lt;script&gt;") || !strings.Contains(text, "Content-Security-Policy") {
		t.Fatalf("HTML escaping/CSP missing: %s", text)
	}
	if !strings.Contains(text, "performed checks") {
		t.Fatalf("HTML lacks disclaimer: %s", text)
	}
	if !strings.Contains(text, "Evidence: exchange ") || !strings.Contains(text, "Score limitation:") {
		t.Fatalf("HTML lacks evidence or score scope: %s", text)
	}
	encoded, err := Render(doc, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Document
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != SchemaVersion || decoded.Findings[0].Observation != doc.Findings[0].Observation {
		t.Fatal("JSON was not faithful")
	}
	if _, err := Render(doc, Format("xml")); err == nil {
		t.Fatal("unsupported format accepted")
	}
}
