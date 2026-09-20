package findingengine

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestFrontendNarrativeCatalogMatchesRules(t *testing.T) {
	data, err := os.ReadFile("../../../frontend/src/finding-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var frontend []Narrative
	if err := json.Unmarshal(data, &frontend); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(frontend, CatalogNarratives()) {
		t.Fatal("frontend narrative catalog is stale; run go run ./tools/cataloggen ./frontend/src/finding-catalog.json")
	}
}
