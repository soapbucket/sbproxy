package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// KeyPrefix is the prefix for all SoapBucket virtual keys.
	KeyPrefix = "sk-sb-"
	// keyRandomBytes is the number of random bytes used in key generation (32 bytes = 64 hex chars).
	keyRandomBytes = 32
)

// GenerateKey creates a new virtual key with the "sk-sb-" prefix.
// It returns the raw key (to be shown once to the user) and the hashed key (for storage).
func GenerateKey() (rawKey string, hashedKey string, err error) {
	b := make([]byte, keyRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	rawKey = KeyPrefix + hex.EncodeToString(b)
	hashedKey = HashKey(rawKey)
	return rawKey, hashedKey, nil
}

// HashKey returns the SHA256 hex hash of a raw key.
func HashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}
