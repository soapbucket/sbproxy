// Package main provides main functionality for the proxy.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	cd "github.com/colinmarc/cdb"
	"github.com/google/uuid"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

const (
	// ExitSuccess is a constant for exit success.
	ExitSuccess = 0
	// ExitError is a constant for exit error.
	ExitError   = 1
)

// Config holds configuration for .
type Config struct {
	// Generation mode
	InputFile  string
	OutputFile string

	// Read mode
	DSN     string
	CDBFile string
	GetHost string
	DumpAll bool
}

func main() {
	os.Exit(run())
}

func run() int {
	config := parseFlags()

	// Determine operation mode
	isReadMode := config.DSN != "" || config.CDBFile != "" || config.GetHost != "" || config.DumpAll
	isGenerateMode := config.InputFile != "" || config.OutputFile != ""

	if isReadMode && isGenerateMode {
		fmt.Fprintf(os.Stderr, "Error: Cannot mix read and generate modes\n")
		flag.Usage()
		return ExitError
	}

	if !isReadMode && !isGenerateMode {
		fmt.Fprintf(os.Stderr, "Error: No operation specified\n")
		flag.Usage()
		return ExitError
	}

	// Read mode
	if isReadMode {
		// Get the actual CDB file path
		cdbFilePath := config.CDBFile

		// If DSN is provided, parse it to get the file path
		if config.DSN != "" {
			settings, err := storage.NewSettingsFromDSN(config.DSN)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Invalid DSN: %v\n", err)
				return ExitError
			}

			if settings.Driver != "cdb" {
				fmt.Fprintf(os.Stderr, "Error: DSN must be for CDB storage (cdb://), got: %s\n", settings.Driver)
				return ExitError
			}

			cdbFilePath = settings.Path
		}

		if cdbFilePath == "" {
			fmt.Fprintf(os.Stderr, "Error: -file or -dsn is required for read operations\n")
			flag.Usage()
			return ExitError
		}

		if config.GetHost != "" {
			return getConfig(cdbFilePath, config.GetHost)
		}

		if config.DumpAll {
			return dumpAll(cdbFilePath)
		}

		fmt.Fprintf(os.Stderr, "Error: Specify -get or -dump\n")
		return ExitError
	}

	// Generate mode
	if config.InputFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Input file is required\n")
		flag.Usage()
		return ExitError
	}

	if config.OutputFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Output file is required\n")
		flag.Usage()
		return ExitError
	}

	// Validate output file extension
	if !strings.HasSuffix(config.OutputFile, ".cdb") {
		fmt.Fprintf(os.Stderr, "Error: Output file must have .cdb extension\n")
		return ExitError
	}

	// Generate CDB file
	if err := generateCDB(config.InputFile, config.OutputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	fmt.Printf("\n✓ Successfully created CDB file: %s\n", config.OutputFile)
	return ExitSuccess
}

func parseFlags() Config {
	config := Config{}

	// Generation mode flags
	flag.StringVar(&config.InputFile, "input", "", "Input configuration file (generate mode)")
	flag.StringVar(&config.InputFile, "i", "", "Input configuration file (shorthand)")
	flag.StringVar(&config.OutputFile, "output", "", "Output CDB file (generate mode)")
	flag.StringVar(&config.OutputFile, "o", "", "Output CDB file (shorthand)")

	// Read mode flags
	flag.StringVar(&config.DSN, "dsn", "", "CDB DSN (e.g. cdb:///path/to/file.cdb) (read mode)")
	flag.StringVar(&config.CDBFile, "file", "", "CDB file to read (read mode)")
	flag.StringVar(&config.CDBFile, "f", "", "CDB file to read (shorthand)")
	flag.StringVar(&config.GetHost, "get", "", "Get configuration for hostname (read mode)")
	flag.StringVar(&config.GetHost, "g", "", "Get configuration for hostname (shorthand)")
	flag.BoolVar(&config.DumpAll, "dump", false, "Dump all keys and values (read mode)")
	flag.BoolVar(&config.DumpAll, "d", false, "Dump all keys and values (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CDB Generator and Reader - Create and inspect CDB files\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Generate: %s -input <file> -output <file.cdb>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Read:     %s -dsn cdb:///path/to/file.cdb -get <hostname>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Read:     %s -file <file.cdb> -get <hostname>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Dump:     %s -dsn cdb:///path/to/file.cdb -dump\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generation Mode Options:\n")
		fmt.Fprintf(os.Stderr, "  -input, -i    Input configuration file\n")
		fmt.Fprintf(os.Stderr, "  -output, -o   Output CDB file\n\n")
		fmt.Fprintf(os.Stderr, "Read Mode Options:\n")
		fmt.Fprintf(os.Stderr, "  -dsn          CDB DSN URL (e.g. cdb:///path/to/file.cdb)\n")
		fmt.Fprintf(os.Stderr, "  -file, -f     CDB file path (alternative to -dsn)\n")
		fmt.Fprintf(os.Stderr, "  -get, -g      Get configuration for hostname\n")
		fmt.Fprintf(os.Stderr, "  -dump, -d     Dump all keys and values\n\n")
		fmt.Fprintf(os.Stderr, "Input File Format (Generation Mode):\n")
		fmt.Fprintf(os.Stderr, "  Each line: hostname <space> json-config\n")
		fmt.Fprintf(os.Stderr, "  The 'id' field is auto-generated as a UUID and injected into the JSON\n")
		fmt.Fprintf(os.Stderr, "  Empty lines and lines starting with # are ignored\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  # Generate CDB file\n")
		fmt.Fprintf(os.Stderr, "  %s -input configs.txt -output configs.cdb\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i configs.txt -o configs.cdb\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Get specific hostname config (using DSN)\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn cdb:///tmp/configs.cdb -get api.example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Get specific hostname config (using file path)\n")
		fmt.Fprintf(os.Stderr, "  %s -file configs.cdb -get api.example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f configs.cdb -g api.example.com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Dump all configurations (using DSN)\n")
		fmt.Fprintf(os.Stderr, "  %s -dsn cdb:///tmp/configs.cdb -dump\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Dump all configurations (using file path)\n")
		fmt.Fprintf(os.Stderr, "  %s -file configs.cdb -dump\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f configs.cdb -d\n\n", os.Args[0])
	}

	flag.Parse()

	return config
}

func generateCDB(inputFile, outputFile string) error {
	// Open input file
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	// Remove existing output file if it exists
	if err := os.Remove(outputFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing output file: %w", err)
	}

	// Create CDB writer
	writer, err := cd.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create CDB file: %w", err)
	}
	defer func() {
		if writer != nil {
			writer.Close()
		}
	}()

	// Parse input file
	scanner := bufio.NewScanner(file)
	lineNum := 0
	loaded := 0
	errors := 0

	fmt.Printf("Processing configurations from %s...\n", inputFile)

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

		// Write to CDB (key is hostname)
		if err := writer.Put([]byte(hostname), updatedJSON); err != nil {
			fmt.Fprintf(os.Stderr, "Line %d: Error writing to CDB for %s: %v\n", lineNum, hostname, err)
			errors++
			continue
		}

		fmt.Printf("✓ Added config for %s (id: %s)\n", hostname, originID)
		loaded++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// Close the writer to finalize the CDB file
	if err := writer.Close(); err != nil {
		return fmt.Errorf("error closing CDB file: %w", err)
	}
	writer = nil // Prevent double close in defer

	fmt.Printf("\nSummary: %d configurations added, %d errors\n", loaded, errors)

	if errors > 0 {
		return fmt.Errorf("%d errors encountered during processing", errors)
	}

	if loaded == 0 {
		return fmt.Errorf("no valid configurations found in input file")
	}

	return nil
}

// getConfig retrieves and displays configuration for a specific hostname
func getConfig(cdbFile, hostname string) int {
	// Open CDB file
	db, err := cd.Open(cdbFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening CDB file: %v\n", err)
		return ExitError
	}
	defer db.Close()

	// Get the value
	data, err := db.Get([]byte(hostname))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from CDB: %v\n", err)
		return ExitError
	}

	if data == nil {
		fmt.Fprintf(os.Stderr, "Hostname not found: %s\n", hostname)
		return ExitError
	}

	// Pretty print JSON
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		fmt.Printf("Raw data: %s\n", string(data))
		return ExitError
	}

	prettyJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
		return ExitError
	}

	fmt.Printf("Configuration for %s:\n%s\n", hostname, string(prettyJSON))
	return ExitSuccess
}

// dumpAll dumps all keys and values from the CDB file
func dumpAll(cdbFile string) int {
	// Open CDB file
	file, err := os.Open(cdbFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening CDB file: %v\n", err)
		return ExitError
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting file info: %v\n", err)
		return ExitError
	}

	// CDB format: read the hash tables to find all keys
	// The CDB format stores 256 hash table pointers at the beginning
	// Each pointer is 8 bytes (4 bytes position, 4 bytes length)

	// Read the hash table pointers (256 tables * 8 bytes = 2048 bytes)
	headerSize := 256 * 8
	header := make([]byte, headerSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CDB header: %v\n", err)
		return ExitError
	}

	fmt.Printf("CDB file: %s (size: %d bytes)\n", cdbFile, stat.Size())
	fmt.Printf("Dumping all configurations:\n\n")

	count := 0
	seen := make(map[string]bool) // Track seen keys to avoid duplicates

	// Iterate through all 256 hash tables
	for i := 0; i < 256; i++ {
		offset := i * 8
		tablePos := uint32(header[offset]) | uint32(header[offset+1])<<8 |
			uint32(header[offset+2])<<16 | uint32(header[offset+3])<<24
		tableLen := uint32(header[offset+4]) | uint32(header[offset+5])<<8 |
			uint32(header[offset+6])<<16 | uint32(header[offset+7])<<24

		if tableLen == 0 {
			continue
		}

		// Read the hash table
		tableSize := tableLen * 8
		table := make([]byte, tableSize)
		if _, err := file.ReadAt(table, int64(tablePos)); err != nil {
			continue
		}

		// Iterate through hash table entries
		for j := uint32(0); j < tableLen; j++ {
			entryOffset := j * 8
			hash := uint32(table[entryOffset]) | uint32(table[entryOffset+1])<<8 |
				uint32(table[entryOffset+2])<<16 | uint32(table[entryOffset+3])<<24
			recPos := uint32(table[entryOffset+4]) | uint32(table[entryOffset+5])<<8 |
				uint32(table[entryOffset+6])<<16 | uint32(table[entryOffset+7])<<24

			if recPos == 0 {
				continue // Empty slot
			}

			// Read the record at recPos
			recHeader := make([]byte, 8)
			if _, err := file.ReadAt(recHeader, int64(recPos)); err != nil {
				continue
			}

			keyLen := uint32(recHeader[0]) | uint32(recHeader[1])<<8 |
				uint32(recHeader[2])<<16 | uint32(recHeader[3])<<24
			valLen := uint32(recHeader[4]) | uint32(recHeader[5])<<8 |
				uint32(recHeader[6])<<16 | uint32(recHeader[7])<<24

			// Read key
			keyData := make([]byte, keyLen)
			if _, err := file.ReadAt(keyData, int64(recPos+8)); err != nil {
				continue
			}

			key := string(keyData)

			// Skip if we've already seen this key (handle duplicates)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Read value
			valData := make([]byte, valLen)
			if _, err := file.ReadAt(valData, int64(recPos+8+keyLen)); err != nil {
				continue
			}

			// Parse and pretty print JSON
			var config map[string]interface{}
			if err := json.Unmarshal(valData, &config); err != nil {
				fmt.Printf("--- %s ---\n", key)
				fmt.Printf("(Invalid JSON: %s)\n\n", string(valData))
				count++
				continue
			}

			prettyJSON, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				fmt.Printf("--- %s ---\n", key)
				fmt.Printf("%s\n\n", string(valData))
				count++
				continue
			}

			fmt.Printf("--- %s ---\n", key)
			fmt.Printf("%s\n\n", string(prettyJSON))
			count++

			// Avoid checking hash in production - it's validation
			_ = hash
		}
	}

	fmt.Printf("Total configurations: %d\n", count)
	return ExitSuccess
}
