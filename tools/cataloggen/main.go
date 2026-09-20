package main

import (
	"encoding/json"
	"os"

	"sentinelhttp/internal/core/findingengine"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	data, err := json.MarshalIndent(findingengine.CatalogNarratives(), "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(os.Args[1], data, 0o600); err != nil {
		panic(err)
	}
}
