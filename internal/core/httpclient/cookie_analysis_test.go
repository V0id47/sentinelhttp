package httpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinelhttp/internal/core/cookieanalysis"
)

func TestCookieAnalysisUsesSeparateCapturedFieldsWithoutValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "sessionid=PRIVATE-COOKIE-CANARY; HttpOnly; SameSite=Lax; Path=/account")
		w.Header().Add("Set-Cookie", "theme=PRIVATE-PREFERENCE-CANARY; Max-Age=3600")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	target := server.URL + "/account/login?token=PRIVATE-QUERY-CANARY"
	client := makeClient(t, target, true, Config{})
	response, err := client.Do(context.Background(), parse(t, target), GET)
	if err != nil {
		t.Fatal(err)
	}
	report := response.CookieAnalysis()
	if report.Capture != cookieanalysis.CaptureComplete || report.FieldCount != 2 || len(report.Cookies) != 2 {
		t.Fatalf("cookies not captured separately: %+v", report)
	}
	first := report.Cookies[0]
	if first.Name != "sessionid" || first.Path.Effective != "/account" || first.Acceptance != cookieanalysis.Accepted || !first.HTTPOnly.Enabled {
		t.Fatalf("wrong effective cookie: %+v", first)
	}
	if report.Cookies[1].Path.Effective != "/account" || report.Cookies[1].Persistence != cookieanalysis.Persistent {
		t.Fatalf("request path or persistence not integrated: %+v", report.Cookies[1])
	}

	report.Cookies[0].Name = "changed"
	if response.CookieAnalysis().Cookies[0].Name != "sessionid" {
		t.Fatal("cookie report aliases retained response")
	}
	encoded, _ := json.Marshal(response)
	rendered := string(encoded) + fmt.Sprintf("%v %+v %#v", response, response, response)
	for _, canary := range []string{"PRIVATE-COOKIE-CANARY", "PRIVATE-PREFERENCE-CANARY", "PRIVATE-QUERY-CANARY", "sessionid"} {
		if strings.Contains(rendered, canary) {
			t.Fatalf("cookie analysis leaked through default response output: %q", canary)
		}
	}
}

func TestCookieAnalysisUnavailableBeforeResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("request sent") }))
	defer server.Close()
	client := makeClient(t, server.URL, true, Config{})
	response, err := client.Do(context.Background(), parse(t, server.URL), Method("PRIVATE-CANARY"))
	if ErrorCode(err) != MethodRejected || response.CookieAnalysis().Capture != cookieanalysis.CaptureUnavailable || len(response.CookieAnalysis().Cookies) != 0 {
		t.Fatalf("failed exchange inferred cookie absence: %v %+v", err, response.CookieAnalysis())
	}
}

func TestCookieAnalysisSurvivesIncompleteBody(t *testing.T) {
	url, _ := rawServer(t, "HTTP/1.1 200 OK\r\nSet-Cookie: sid=PRIVATE-CANARY; HttpOnly\r\nContent-Length: 10\r\n\r\nx")
	client := makeClient(t, url, true, Config{})
	response, err := client.Do(context.Background(), parse(t, url+"/account/login"), GET)
	if ErrorCode(err) != BodyReadFailed {
		t.Fatal(err)
	}
	report := response.CookieAnalysis()
	if report.Capture != cookieanalysis.CaptureComplete || len(report.Cookies) != 1 || report.Cookies[0].Name != "sid" {
		t.Fatalf("captured cookies lost after body failure: %+v", report)
	}
}

func TestCookieAnalysisUsesEscapedRequestPathForDefaultPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "id=PRIVATE-CANARY")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	target := server.URL + "/foo%2Fbar/login"
	client := makeClient(t, target, true, Config{})
	response, err := client.Do(context.Background(), parse(t, target), GET)
	if err != nil {
		t.Fatal(err)
	}
	cookie := response.CookieAnalysis().Cookies[0]
	if cookie.Path.Effective != "/foo%2Fbar" {
		t.Fatalf("escaped request path was decoded before default-path: %+v", cookie)
	}
}
