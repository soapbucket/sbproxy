// Package main provides main functionality for the proxy.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/soapbucket/sbproxy/internal/platform/storage"
	_ "github.com/soapbucket/sbproxy/internal/platform/storage"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <cdb-file> <hostname>\n", os.Args[0])
		os.Exit(1)
	}

	cdbFile := os.Args[1]
	hostname := os.Args[2]

	// Create storage instance
	settings := &storage.Settings{
		Driver: "cdb",
		DSN:    cdbFile,
	}

	store, err := storage.NewStorage(settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	// Get configuration
	ctx := context.Background()
	data, err := store.Get(ctx, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting config for %s: %v\n", hostname, err)
		os.Exit(1)
	}

	// Pretty print JSON
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	prettyJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration for %s:\n%s\n", hostname, string(prettyJSON))
}
