// Package main provides main functionality for the proxy.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	_ "github.com/soapbucket/sbproxy/internal/platform/storage"
)

const (
	// ExitSuccess is a constant for exit success.
	ExitSuccess = 0
	// ExitError is a constant for exit error.
	ExitError   = 1
)

// Config holds configuration for .
type Config struct {
	DSN        string
	ConfigFile string
	DeleteKey  string
	DeletePfx  string
	ListAll    bool
}

func main() {
	os.Exit(run())
}

func run() int {
	config := parseFlags()

	if config.DSN == "" {
		fmt.Fprintf(os.Stderr, "Error: DSN is required\n")
		fmt.Fprintf(os.Stderr, "Set via -dsn flag or STORAGE_DSN environment variable\n")
		return ExitError
	}

	// Create storage instance
	settings, err := storage.NewSettingsFromDSN(config.DSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing DSN: %v\n", err)
		return ExitError
	}

	store, err := storage.NewStorage(settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating storage: %v\n", err)
		return ExitError
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Handle different operations
	if config.ListAll {
		return listConfigs(ctx, store)
	}

	if config.DeleteKey != "" {
		return deleteConfig(ctx, store, config.DeleteKey)
	}

	if config.DeletePfx != "" {
		return deleteByPrefix(ctx, store, config.DeletePfx)
	}

	// Check if delete-prefix flag was explicitly set to empty string
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "delete-prefix" && f.Value.String() == "" {
			fmt.Fprintf(os.Stderr, "Error: Prefix cannot be empty (to prevent accidental deletion of all records)\n")
			os.Exit(ExitError)
		}
	})

	if config.ConfigFile != "" {
		return loadConfigs(ctx, store, config.ConfigFile)
	}

	fmt.Fprintf(os.Stderr, "Error: No operation specified. Use -load, -delete, -delete-prefix, or -list\n")
	flag.Usage()
	return ExitError
}

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.DSN, "dsn", os.Getenv("STORAGE_DSN"), "Database DSN (or set STORAGE_DSN env var)")
	flag.StringVar(&config.ConfigFile, "load", "", "Load configurations from file")
	flag.StringVar(&config.DeleteKey, "delete", "", "Delete configuration by hostname")
	flag.StringVar(&config.DeletePfx, "delete-prefix", "", "Delete configurations by hostname prefix")
	flag.BoolVar(&config.ListAll, "list", false, "List all configurations (keys only)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Origin Configuration Loader\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Load configurations from file\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn sqlite:///tmp/config.db -load configs.txt\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Load with PostgreSQL\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn 'postgres://user:pass@localhost/db?sslmode=disable' -load configs.txt\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Delete specific hostname\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn sqlite:///tmp/config.db -delete api.example.com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Delete by prefix\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn sqlite:///tmp/config.db -delete-prefix 'api.'\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # List all configurations\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn sqlite:///tmp/config.db -list\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "File Format:\n")
		fmt.Fprintf(os.Stderr, "  Each line: hostname <space> json-config\n")
		fmt.Fprintf(os.Stderr, "  Note: The 'id' field is auto-generated as a UUID\n")
		fmt.Fprintf(os.Stderr, "  Example: api.example.com {\"hostname\":\"api.example.com\",\"type\":\"proxy\",\"config\":{\"url\":\"https://example.com\",\"timeout\":\"30s\"}}\n")
	}

	flag.Parse()

	return config
}

func loadConfigs(ctx context.Context, store storage.Storage, filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		return ExitError
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	loaded := 0
	errors := 0

	fmt.Printf("Loading configurations from %s...\n", filename)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line: hostname json-config
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Line %d: Invalid format (expected: hostname json-config)\n", lineNum)
			errors++
			continue
		}

		hostname := strings.TrimSpace(parts[0])
		jsonConfig := strings.TrimSpace(parts[1])

		if hostname == "" {
			fmt.Fprintf(os.Stderr, "Line %d: Empty hostname\n", lineNum)
			errors++
			continue
		}

		// Parse JSON to inject UUID as the id field
		var originConfig map[string]interface{}
		if err := json.Unmarshal([]byte(jsonConfig), &originConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Line %d: Invalid JSON for %s: %v\n", lineNum, hostname, err)
			errors++
			continue
		}

		// Generate UUID and set it as the id field
		originID := uuid.New().String()
		originConfig["id"] = originID

		// Marshal back to JSON
		updatedJSON, err := json.Marshal(originConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Line %d: Error marshaling JSON for %s: %v\n", lineNum, hostname, err)
			errors++
			continue
		}

		// Store configuration (upsert)
		err = store.Put(ctx, hostname, updatedJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Line %d: Error storing config for %s: %v\n", lineNum, hostname, err)
			errors++
			continue
		}

		fmt.Printf("✓ Loaded config for %s (id: %s)\n", hostname, originID)
		loaded++
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		return ExitError
	}

	fmt.Printf("\nSummary: %d loaded, %d errors\n", loaded, errors)

	if errors > 0 {
		return ExitError
	}

	return ExitSuccess
}

func deleteConfig(ctx context.Context, store storage.Storage, hostname string) int {
	if hostname == "" {
		fmt.Fprintf(os.Stderr, "Error: Hostname cannot be empty\n")
		return ExitError
	}

	err := store.Delete(ctx, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting config for %s: %v\n", hostname, err)
		return ExitError
	}

	fmt.Printf("✓ Deleted config for %s\n", hostname)
	return ExitSuccess
}

func deleteByPrefix(ctx context.Context, store storage.Storage, prefix string) int {
	if prefix == "" {
		fmt.Fprintf(os.Stderr, "Error: Prefix cannot be empty (to prevent accidental deletion of all records)\n")
		fmt.Fprintf(os.Stderr, "Use a specific prefix or delete individual records with -delete\n")
		return ExitError
	}

	// Additional safety check
	if len(prefix) < 2 {
		fmt.Fprintf(os.Stderr, "Error: Prefix must be at least 2 characters long (safety check)\n")
		return ExitError
	}

	fmt.Printf("Deleting all configs with prefix '%s'...\n", prefix)
	fmt.Printf("WARNING: This will delete all hostnames starting with '%s'\n", prefix)
	fmt.Printf("Continue? (y/n): ")

	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled")
		return ExitSuccess
	}

	err := store.DeleteByPrefix(ctx, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting by prefix %s: %v\n", prefix, err)
		return ExitError
	}

	fmt.Printf("✓ Deleted all configs with prefix '%s'\n", prefix)
	return ExitSuccess
}

func listConfigs(ctx context.Context, store storage.Storage) int {
	fmt.Println("Note: List functionality requires database-specific queries.")
	fmt.Println("Use database tools to list all keys, or implement custom list method.")
	fmt.Println("For SQLite: sqlite3 db.db 'SELECT key FROM config_storage'")
	fmt.Println("For PostgreSQL: psql -c 'SELECT key FROM config_storage'")
	return ExitSuccess
}
