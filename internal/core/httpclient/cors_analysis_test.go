package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinelhttp/internal/core/corsanalysis"
)

func TestCORSAnalysisCapturesHeadersWithoutSendingOrigin(t *testing.T) {
	const canary = "https://private-origin-canary.invalid"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("passive request sent CORS probe or credentials: %+v", r.Header)
		}
		w.Header().Set("Access-Control-Allow-Origin", canary)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "X-SentinelHTTP-Probe")
		fmt.Fprint(w, "body")
	}))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), GET)
	if err != nil {
		t.Fatal(err)
	}
	report := response.CORSAnalysis()
	if report.Capture != corsanalysis.CaptureComplete || report.Origin.Kind != corsanalysis.OriginExplicit || report.Origin.Value != canary || !report.Credentials.Enabled || len(report.AllowHeaders.Tokens) != 1 {
		t.Fatalf("CORS response evidence lost: %+v", report)
	}
	report.Origin.Value = "https://changed.invalid"
	report.AllowHeaders.Tokens[0] = "changed"
	again := response.CORSAnalysis()
	if again.Origin.Value != canary || again.AllowHeaders.Tokens[0] != "x-sentinelhttp-probe" {
		t.Fatalf("CORS accessor aliases retained response: %+v", again)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{string(encoded), fmt.Sprintf("%v %+v %#v", response, response, response)} {
		if strings.Contains(text, canary) {
			t.Fatalf("CORS evidence leaked in default output: %q", text)
		}
	}
}

func TestCORSAnalysisUnavailableBeforeResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("request sent") }))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), Method("TRACE"))
	if ErrorCode(err) != MethodRejected || response.CORSAnalysis().Capture != corsanalysis.CaptureUnavailable {
		t.Fatalf("pre-header error inferred CORS result: %v %+v", err, response.CORSAnalysis())
	}
}

func TestCORSAnalysisSurvivesIncompleteBody(t *testing.T) {
	url, _ := rawServer(t, "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 10\r\n\r\nx")
	client := makeClient(t, url, true, Config{})
	response, err := client.Do(context.Background(), parse(t, url), GET)
	if ErrorCode(err) != BodyReadFailed {
		t.Fatal(err)
	}
	report := response.CORSAnalysis()
	if report.Capture != corsanalysis.CaptureComplete || report.Origin.Kind != corsanalysis.OriginWildcard {
		t.Fatalf("body failure erased CORS headers: %+v", report)
	}
}
