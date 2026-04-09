// Package main provides encryption and decryption utilities for securing sensitive configuration values.
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
)

var (
	// Commands
	command string

	// Provider flags
	provider      string
	encryptionKey string
	signingKey    string
	gcpProject    string
	gcpLocation   string
	gcpKeyRing    string
	gcpKeyID      string
	awsRegion     string
	awsKeyID      string

	// Input/output flags
	value  string
	stdin  bool
	genKey bool
)

func init() {
	flag.StringVar(&command, "c", "", "Command: encrypt, decrypt, sign, verify")
	flag.StringVar(&provider, "p", "local", "Provider: local, gcp, aws")

	// Key flags
	flag.StringVar(&encryptionKey, "encryption-key", "", "Encryption key (base64-encoded 32-byte key for local)")
	flag.StringVar(&signingKey, "signing-key", "", "Signing key (base64-encoded key for local, optional - uses encryption key if not provided)")

	// GCP KMS flags
	flag.StringVar(&gcpProject, "gcp-project", "", "GCP project ID")
	flag.StringVar(&gcpLocation, "gcp-location", "", "GCP location (e.g., global, us-east1)")
	flag.StringVar(&gcpKeyRing, "gcp-keyring", "", "GCP key ring name")
	flag.StringVar(&gcpKeyID, "gcp-key", "", "GCP key ID")

	// AWS KMS flags
	flag.StringVar(&awsRegion, "aws-region", "", "AWS region")
	flag.StringVar(&awsKeyID, "aws-key", "", "AWS KMS key ID or ARN")

	// Input/output flags
	flag.StringVar(&value, "v", "", "Value to encrypt/decrypt/sign/verify")
	flag.BoolVar(&stdin, "stdin", false, "Read value from stdin")
	flag.BoolVar(&genKey, "generate-key", false, "Generate a random 32-byte key for local encryption")
}

func main() {
	flag.Parse()

	// Handle key generation
	if genKey {
		key, err := crypto.GenerateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(key)
		return
	}

	// Validate command
	if command == "" {
		fmt.Fprintf(os.Stderr, "Error: command is required (-c encrypt|decrypt|sign|verify)\n")
		printUsage()
		os.Exit(1)
	}

	if command != "encrypt" && command != "decrypt" && command != "sign" && command != "verify" {
		fmt.Fprintf(os.Stderr, "Error: invalid command '%s' (must be 'encrypt', 'decrypt', 'sign', or 'verify')\n", command)
		printUsage()
		os.Exit(1)
	}

	// Get value from stdin or flag
	var inputValue string
	if stdin {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			inputValue = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	} else if value != "" {
		inputValue = value
	} else {
		fmt.Fprintf(os.Stderr, "Error: value is required (-v <value> or --stdin)\n")
		printUsage()
		os.Exit(1)
	}

	// Build configuration
	settings := &crypto.Settings{
		Driver: provider,
		Params: make(map[string]string),
	}

	// Load provider-specific configuration
	switch provider {
	case "local":
		encKey := getEnvOrFlag("CRYPTO_ENCRYPTION_KEY", encryptionKey)
		if encKey == "" {
			// Fallback to old env var for backward compatibility
			encKey = getEnvOrFlag("CRYPTO_LOCAL_KEY", encryptionKey)
		}
		if encKey == "" {
			fmt.Fprintf(os.Stderr, "Error: encryption key is required (--encryption-key or CRYPTO_ENCRYPTION_KEY env var)\n")
			os.Exit(1)
		}
		settings.Params[crypto.ParamEncryptionKey] = encKey

		// Set signing key if provided
		if signKey := getEnvOrFlag("CRYPTO_SIGNING_KEY", signingKey); signKey != "" {
			settings.Params[crypto.ParamSigningKey] = signKey
		}

	case "gcp":
		settings.Params[crypto.ParamProjectID] = getEnvOrFlag("GCP_PROJECT_ID", gcpProject)
		settings.Params[crypto.ParamLocation] = getEnvOrFlag("GCP_LOCATION", gcpLocation)
		settings.Params[crypto.ParamKeyRing] = getEnvOrFlag("GCP_KEYRING", gcpKeyRing)
		settings.Params[crypto.ParamKeyID] = getEnvOrFlag("GCP_KEY_ID", gcpKeyID)

		if settings.Params[crypto.ParamProjectID] == "" || settings.Params[crypto.ParamLocation] == "" ||
			settings.Params[crypto.ParamKeyRing] == "" || settings.Params[crypto.ParamKeyID] == "" {
			fmt.Fprintf(os.Stderr, "Error: GCP KMS requires project, location, keyring, and key ID\n")
			fmt.Fprintf(os.Stderr, "  Use flags: --gcp-project, --gcp-location, --gcp-keyring, --gcp-key\n")
			fmt.Fprintf(os.Stderr, "  Or env vars: GCP_PROJECT_ID, GCP_LOCATION, GCP_KEYRING, GCP_KEY_ID\n")
			os.Exit(1)
		}

	case "aws":
		settings.Params[crypto.ParamRegion] = getEnvOrFlag("AWS_REGION", awsRegion)
		settings.Params[crypto.ParamKeyID] = getEnvOrFlag("AWS_KMS_KEY_ID", awsKeyID)

		if settings.Params[crypto.ParamRegion] == "" || settings.Params[crypto.ParamKeyID] == "" {
			fmt.Fprintf(os.Stderr, "Error: AWS KMS requires region and key ID\n")
			fmt.Fprintf(os.Stderr, "  Use flags: --aws-region, --aws-key\n")
			fmt.Fprintf(os.Stderr, "  Or env vars: AWS_REGION, AWS_KMS_KEY_ID\n")
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: invalid provider '%s'\n", provider)
		os.Exit(1)
	}

	// Create crypto instance
	cryptoInstance, err := crypto.NewCrypto(settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating crypto instance: %v\n", err)
		os.Exit(1)
	}

	// Execute command
	switch command {
	case "encrypt":
		ciphertext, err := cryptoInstance.Encrypt([]byte(inputValue))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(ciphertext))

	case "decrypt":
		plaintext, err := cryptoInstance.Decrypt([]byte(inputValue))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(plaintext))

	case "sign":
		signature, err := cryptoInstance.Sign([]byte(inputValue))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
			os.Exit(1)
		}
		// Output signature as base64 for easy handling
		fmt.Println(base64.StdEncoding.EncodeToString(signature))

	case "verify":
		// For verify command, we need both data and signature
		// The input should be in format: data|signature (base64 encoded signature)
		parts := splitInputForVerify(inputValue)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Error: verify command requires data and signature separated by '|'\n")
			fmt.Fprintf(os.Stderr, "Format: 'data|base64_signature'\n")
			os.Exit(1)
		}

		data := parts[0]
		signatureB64 := parts[1]

		// Decode signature
		signature, err := base64.StdEncoding.DecodeString(signatureB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding signature: %v\n", err)
			os.Exit(1)
		}

		valid, err := cryptoInstance.Verify([]byte(data), signature)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error verifying: %v\n", err)
			os.Exit(1)
		}

		if valid {
			fmt.Println("true")
		} else {
			fmt.Println("false")
		}
	}
}

func getEnvOrFlag(envVar, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(envVar)
}

func splitInputForVerify(input string) []string {
	// Split on the first '|' character
	for i, char := range input {
		if char == '|' {
			return []string{input[:i], input[i+1:]}
		}
	}
	return []string{input} // Return single element if no separator found
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	fmt.Fprintf(os.Stderr, "  Generate a new encryption key:\n")
	fmt.Fprintf(os.Stderr, "    crypto --generate-key\n\n")
	fmt.Fprintf(os.Stderr, "  Encrypt a value:\n")
	fmt.Fprintf(os.Stderr, "    crypto -c encrypt -p local -v 'my-secret' --encryption-key <key>\n")
	fmt.Fprintf(os.Stderr, "    echo 'my-secret' | crypto -c encrypt -p local --stdin --encryption-key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  Decrypt a value:\n")
	fmt.Fprintf(os.Stderr, "    crypto -c decrypt -p local -v 'local:...' --encryption-key <key>\n")
	fmt.Fprintf(os.Stderr, "    echo 'local:...' | crypto -c decrypt -p local --stdin --encryption-key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  Sign a value:\n")
	fmt.Fprintf(os.Stderr, "    crypto -c sign -p local -v 'my-data' --encryption-key <key>\n")
	fmt.Fprintf(os.Stderr, "    echo 'my-data' | crypto -c sign -p local --stdin --encryption-key <key>\n\n")
	fmt.Fprintf(os.Stderr, "  Verify a signature:\n")
	fmt.Fprintf(os.Stderr, "    crypto -c verify -p local -v 'my-data|<base64-signature>' --encryption-key <key>\n")
	fmt.Fprintf(os.Stderr, "    echo 'my-data|<base64-signature>' | crypto -c verify -p local --stdin --encryption-key <key>\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
	fmt.Fprintf(os.Stderr, "  CRYPTO_ENCRYPTION_KEY  Encryption key (fallback: CRYPTO_LOCAL_KEY)\n")
	fmt.Fprintf(os.Stderr, "  CRYPTO_SIGNING_KEY     Signing key (optional, uses encryption key if not provided)\n")
	fmt.Fprintf(os.Stderr, "  GCP_PROJECT_ID         GCP project ID\n")
	fmt.Fprintf(os.Stderr, "  GCP_LOCATION           GCP location\n")
	fmt.Fprintf(os.Stderr, "  GCP_KEYRING            GCP key ring\n")
	fmt.Fprintf(os.Stderr, "  GCP_KEY_ID             GCP key ID\n")
	fmt.Fprintf(os.Stderr, "  AWS_REGION             AWS region\n")
	fmt.Fprintf(os.Stderr, "  AWS_KMS_KEY_ID         AWS KMS key ID\n")
}
