package httpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelhttp/internal/core/headeranalysis"
)

func TestHeaderAnalysisUsesCapturedHTTPSResponse(t *testing.T) {
	now := time.Now()
	cert, ca := labCertificate(t, "localhost", now.Add(-time.Hour), now.Add(time.Hour))
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'private-csp-canary'")
		w.Header().Set("Server", "private-server-canary")
		w.WriteHeader(http.StatusNoContent)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()

	target := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
	c := makeClient(t, target, true, Config{LabCAPEM: ca})
	r, err := c.Do(context.Background(), parse(t, target), GET)
	if err != nil {
		t.Fatal(err)
	}
	report := r.HeaderAnalysis()
	if report.Capture != headeranalysis.CaptureComplete || !report.Context.TLSVerified || report.Context.Representation != headeranalysis.RepresentationNoContent {
		t.Fatalf("headers not analyzed: %+v", report)
	}
	hsts, ok := report.Result(headeranalysis.StrictTransportSecurity)
	if !ok || hsts.Status != headeranalysis.StatusValid || hsts.Effective != "active" {
		t.Fatalf("wrong HSTS result: %+v", hsts)
	}
	xfo, ok := report.Result(headeranalysis.XFrameOptions)
	if !ok || xfo.Status != headeranalysis.StatusValid || xfo.Effective != "DENY" || xfo.Applicability != headeranalysis.NotApplicable {
		t.Fatalf("response context was not applied to XFO: %+v", xfo)
	}
	if got := report.Values(headeranalysis.Server); len(got) != 1 || got[0] != "private-server-canary" {
		t.Fatalf("explicit evidence missing: %q", got)
	}

	report.Results[0].Effective = "changed"
	serverValues := report.Values(headeranalysis.Server)
	serverValues[0] = "changed"
	second := r.HeaderAnalysis()
	if second.Results[0].Effective == "changed" || second.Values(headeranalysis.Server)[0] == "changed" {
		t.Fatal("header report aliases retained response")
	}
	encoded, _ := json.Marshal(r)
	formatted := string(encoded) + fmt.Sprintf("%v %+v %#v", r, r, r)
	if strings.Contains(formatted, "private-server-canary") || strings.Contains(formatted, "private-csp-canary") {
		t.Fatal("header evidence leaked through default response output")
	}
}

func TestHeaderAnalysisUnavailableBeforeResponseHeaders(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("request sent") }))
	defer s.Close()
	c := makeClient(t, s.URL, true, Config{})
	r, err := c.Do(context.Background(), parse(t, s.URL), Method("PRIVATE-CANARY"))
	if ErrorCode(err) != MethodRejected || r.HeaderAnalysis().Capture != headeranalysis.CaptureUnavailable || len(r.HeaderAnalysis().Results) != 0 {
		t.Fatalf("failed exchange inferred missing headers: %v %+v", err, r.HeaderAnalysis())
	}
}

func TestHeaderAnalysisSurvivesIncompleteBody(t *testing.T) {
	url, _ := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Frame-Options: DENY\r\nContent-Length: 10\r\n\r\nx")
	c := makeClient(t, url, true, Config{})
	r, err := c.Do(context.Background(), parse(t, url), GET)
	if ErrorCode(err) != BodyReadFailed {
		t.Fatal(err)
	}
	xfo, ok := r.HeaderAnalysis().Result(headeranalysis.XFrameOptions)
	if r.HeaderAnalysis().Capture != headeranalysis.CaptureComplete || !ok || xfo.Effective != "DENY" {
		t.Fatalf("captured headers lost after body failure: %+v", r.HeaderAnalysis())
	}
}
