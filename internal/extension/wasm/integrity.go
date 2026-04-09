package wasm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// VerifyIntegrity checks that the SHA-256 hash of wasmBytes matches expected.
func VerifyIntegrity(wasmBytes []byte, expectedHash string) error {
	if expectedHash == "" {
		return nil // No verification requested
	}
	hash := sha256.Sum256(wasmBytes)
	actual := hex.EncodeToString(hash[:])
	if actual != expectedHash {
		return fmt.Errorf("wasm module integrity check failed: expected %s, got %s", expectedHash, actual)
	}
	return nil
}
