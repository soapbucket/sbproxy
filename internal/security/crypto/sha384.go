// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package crypto

import (
	"crypto/sha512"
	"encoding/hex"
)

// GetSHA384 returns the sha384.
func GetSHA384(s string) string {
	hasher := sha512.New384()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}
