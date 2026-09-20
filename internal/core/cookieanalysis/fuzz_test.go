package cookieanalysis

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func FuzzAnalyze(f *testing.F) {
	f.Add("sid=value; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Secure; SameSite=Lax")
	f.Add("__Host-id=secret; Secure; Path=/; Domain=com")
	f.Add("name=value; Path=/one; Path; Max-Age=-1; X-Unknown=private")
	f.Add("\x00\xff; Domain=..example.com; SameSite=unknown")

	f.Fuzz(func(t *testing.T, field string) {
		input := completeInput(field)
		first := Analyze(input)
		second := Analyze(input)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("analysis is not deterministic")
		}
		if len(first.Cookies) > maxCookieFields || first.AnalyzedFields > maxCookieFields {
			t.Fatal("field bound exceeded")
		}
		for _, cookie := range first.Cookies {
			if len(cookie.Name) > 256 || len(cookie.UnknownAttributes) > maxUnknownAttributes || len(cookie.Path.Effective) > maxFieldBytes {
				t.Fatalf("retained evidence exceeded a bound: %+v", cookie)
			}
		}
	})
}

func FuzzCookieValuesAreNeverRetained(f *testing.F) {
	f.Add([]byte("private-cookie-value"))
	f.Add([]byte{0, 1, 2, 3, 254, 255})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 256 {
			raw = raw[:256]
		}
		secret := hex.EncodeToString(raw)
		if len(secret) < 16 {
			return
		}
		report := Analyze(completeInput("sid=" + secret + "; X-Probe=" + secret))
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatal("cookie or extension value retained")
		}
	})
}
