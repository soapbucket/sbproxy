// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import (
	"encoding/base64"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// base64Pattern matches strings containing only base64-safe characters.
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

var (
	constructors   = make(map[string]ConstructorFn)
	constructorsMu sync.RWMutex
)

// ConstructorFn is a function type for constructor fn callbacks.
type ConstructorFn func(Settings) (Crypto, error)

// Register registers .
func Register(driver string, fn ConstructorFn) {
	constructorsMu.Lock()
	constructors[driver] = fn
	constructorsMu.Unlock()
}

// NewCrypto creates and initializes a new Crypto.
func NewCrypto(settings Settings) (Crypto, error) {
	if settings.Driver == "" {
		settings.Driver = string(ProviderLocal)
	}

	constructorsMu.RLock()
	fn, ok := constructors[settings.Driver]
	constructorsMu.RUnlock()

	if !ok {
		slog.Error("unsupported driver", "driver", settings.Driver)
		return nil, ErrInvalidProvider
	}

	crypto, err := fn(settings)
	if err != nil {
		return nil, err
	}

	// Apply metrics wrapper if enabled
	if settings.EnableMetrics {
		crypto = NewMetricsCrypto(crypto, settings.Driver)
	}

	// Apply tracing wrapper if enabled
	if settings.EnableTracing {
		crypto = NewTracedCrypto(crypto)
	}

	return crypto, nil
}

// AvailableDrivers performs the available drivers operation.
func AvailableDrivers() []string {
	var names []string

	constructorsMu.RLock()
	for name := range constructors {
		names = append(names, name)
	}
	constructorsMu.RUnlock()

	sort.Strings(names)
	return names
}

// IsEncrypted checks if a string is encrypted (has a provider prefix).
// The value after the prefix must be at least 16 characters and contain
// only base64-safe characters to avoid false positives on arbitrary text.
func IsEncrypted(value string) bool {
	prefixes := []string{"local:", "gcp:", "aws:"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			remainder := value[len(prefix):]
			if len(remainder) >= 16 && base64Pattern.MatchString(remainder) {
				return true
			}
			return false
		}
	}
	return false
}

// GetProvider extracts the provider from an encrypted value
func GetProvider(value string) (Provider, error) {
	if strings.HasPrefix(value, "local:") {
		return ProviderLocal, nil
	}
	if strings.HasPrefix(value, "gcp:") {
		return ProviderGCP, nil
	}
	if strings.HasPrefix(value, "aws:") {
		return ProviderAWS, nil
	}
	return "", ErrInvalidProvider
}

// StripPrefix removes the provider prefix from an encrypted value
func StripPrefix(value string) string {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return value
}

// AddPrefix adds the provider prefix to a ciphertext
func AddPrefix(provider Provider, ciphertext string) string {
	return string(provider) + ":" + ciphertext
}

// EncodeBase64 encodes bytes to base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes base64 string to bytes
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
