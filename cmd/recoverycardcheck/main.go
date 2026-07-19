// Command recoverycardcheck validates and prints one persisted recovery card.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"winkyou/pkg/recoverycard"
)

func main() {
	path := flag.String("path", "", "path to the recovery-card JSON file")
	nodeID := flag.String("node", "", "expected card node ID")
	flag.Parse()

	if strings.TrimSpace(*path) == "" || strings.TrimSpace(*nodeID) == "" {
		fmt.Fprintln(os.Stderr, "recoverycardcheck: -path and -node are required")
		os.Exit(2)
	}
	store, err := recoverycard.NewStore(*path, *nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recoverycardcheck: create store: %v\n", err)
		os.Exit(1)
	}
	card, err := store.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "recoverycardcheck: load: %v\n", err)
		os.Exit(1)
	}
	if card.Version == 0 {
		fmt.Fprintln(os.Stderr, "recoverycardcheck: card file is missing")
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"ok":   true,
		"card": card,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "recoverycardcheck: encode result: %v\n", err)
		os.Exit(1)
	}
}
