package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMaximumCombinedBudgetIsCheckedBeforeDial(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	args := []string{"scan", server.URL + "/secret?token=canary", "--allow-private", "--trace-redirects", "--max-redirects", "20", "--probe-cors", "--max-requests", "23", "--format", "json"}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), args, &out, &errOut); code != 2 || hits.Load() != 0 || out.Len() != 0 || strings.Contains(errOut.String(), "canary") {
		t.Fatalf("under-reserved scan reached network or leaked target: exit=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
	args[8] = "24"
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), args, &out, &errOut); code != 0 || hits.Load() != 4 || errOut.Len() != 0 {
		t.Fatalf("exact maximum budget failed: exit=%d hits=%d stderr=%q", code, hits.Load(), errOut.String())
	}
}
