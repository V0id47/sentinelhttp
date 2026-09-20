package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestLanguageFlagAndSafeLocalizedErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "--help", "--lang", "ru"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "Использование") {
		t.Fatalf("help: %d %q", code, out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"scan", "https://user:secret@example.com/?token=private", "--lang=es"}, &out, &errOut); code == 0 || strings.Contains(errOut.String(), "secret") || strings.Contains(errOut.String(), "private") || !strings.Contains(errOut.String(), "La URL no puede incluir credenciales") {
		t.Fatalf("localized error: %d %q", code, errOut.String())
	}
}
