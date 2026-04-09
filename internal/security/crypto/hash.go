// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package crypto

import (
	"encoding/hex"
	"hash"
	"sync"

	"github.com/cespare/xxhash/v2"
)

// Pool for xxhash hashers to reduce allocations
// xxhash is significantly faster than MD5 for non-cryptographic hashing
var hashPool = sync.Pool{
	New: func() interface{} {
		return xxhash.New()
	},
}

// GetHash returns the xxhash64 hash of the data as a hex string
// This is much faster than MD5 and suitable for cache keys and non-cryptographic uses
func GetHash(data []byte) string {
	hasher := hashPool.Get().(hash.Hash64)
	hasher.Reset()
	hasher.Write(data)

	// Get the 64-bit hash value
	sum64 := hasher.Sum64()

	// Return to pool
	hashPool.Put(hasher)

	// Convert to hex string (16 characters for 64-bit hash)
	buf := make([]byte, 8)
	buf[0] = byte(sum64 >> 56)
	buf[1] = byte(sum64 >> 48)
	buf[2] = byte(sum64 >> 40)
	buf[3] = byte(sum64 >> 32)
	buf[4] = byte(sum64 >> 24)
	buf[5] = byte(sum64 >> 16)
	buf[6] = byte(sum64 >> 8)
	buf[7] = byte(sum64)

	return hex.EncodeToString(buf)
}

// GetHashFromString returns the xxhash64 hash of the string as a hex string
func GetHashFromString(s string) string {
	return GetHash([]byte(s))
}
