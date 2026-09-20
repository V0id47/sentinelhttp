package headeranalysis

import "testing"

func TestStructuredItemAcceptsRFC9651BareParameterTypes(t *testing.T) {
	value := `same-origin; integer=-12; decimal=1.25; string="a;b"; token=abc/def; binary=:YQ:; partial-padding=:YQ=:; boolean=?0; date=@1659578233; display=%"%e2%82%ac"; implicit`
	item, ok := parseSFItemField(value)
	if !ok || item.bare.kind != sfToken || item.bare.value != "same-origin" || len(item.params) != 10 {
		t.Fatalf("valid structured item rejected: %+v, ok=%v", item, ok)
	}
}

func TestStructuredDictionaryAllowsOWSAndOverwritesDuplicates(t *testing.T) {
	entries, ok := parseSFDictionary("camera=(self),\tmicrophone=*, camera=\"https://example.test\"")
	if !ok || len(entries) != 2 || entries[0].key != "camera" || !entries[0].member.repeated || entries[0].member.item.bare.kind != sfString {
		t.Fatalf("dictionary combination semantics lost: %+v, ok=%v", entries, ok)
	}
}

func TestStructuredFieldRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{
		`same-origin; Bad=1`,
		`same-origin; value="bad\q"`,
		`same-origin; value=1234567890123456`,
		`same-origin; value=1234567890123.1`,
		`same-origin; value=1.2345`,
		`same-origin; value=?2`,
		`same-origin; value=:a:`,
		`same-origin; value=%"%E2%82%AC"`,
		`same-origin,`,
	} {
		if _, ok := parseSFItemField(value); ok {
			t.Fatalf("accepted malformed structured item %q", value)
		}
	}
	if _, ok := parseSFDictionary("camera=(self\t*)"); ok {
		t.Fatal("accepted HTAB as an inner-list item delimiter")
	}
}
