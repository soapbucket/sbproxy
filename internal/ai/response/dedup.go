// dedup.go detects identical responses from different AI providers.
//
// When the same prompt is sent to multiple providers (e.g., for quality
// comparison or shadow testing), responses may be identical. The
// deduplicator tracks content hashes and reports when a response matches
// one already seen, enabling callers to avoid redundant processing or
// storage.
//
// The deduplicator uses SHA-256 for content hashing and bounds its memory
// usage to a configurable maximum number of entries.
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

const defaultMaxDedupEntries = 10000

// Deduplicator detects identical responses from different providers.
type Deduplicator struct {
	mu         sync.RWMutex
	hashes     map[string]string // response hash -> first provider that returned it
	maxEntries int
}

// NewDeduplicator creates a new response deduplicator. If maxEntries is zero
// or negative, defaultMaxDedupEntries (10000) is used.
func NewDeduplicator(maxEntries int) *Deduplicator {
	if maxEntries <= 0 {
		maxEntries = defaultMaxDedupEntries
	}
	return &Deduplicator{
		hashes:     make(map[string]string),
		maxEntries: maxEntries,
	}
}

// Check returns the provider name and true if this response was already seen
// from a different provider. Returns empty string and false if the response
// is new.
func (d *Deduplicator) Check(response []byte) (string, bool) {
	h := Hash(response)

	d.mu.RLock()
	provider, ok := d.hashes[h]
	d.mu.RUnlock()

	return provider, ok
}

// Record stores the response hash with its provider. If the deduplicator
// is at capacity, the oldest entries are not evicted (simple bounded map).
// Duplicate hashes are not overwritten, preserving the first provider.
func (d *Deduplicator) Record(response []byte, provider string) {
	h := Hash(response)

	d.mu.Lock()
	defer d.mu.Unlock()

	// Do not overwrite existing entries
	if _, exists := d.hashes[h]; exists {
		return
	}

	// If at capacity, skip recording to prevent unbounded growth.
	// Callers should create a new Deduplicator when the old one fills up,
	// or call Reset periodically.
	if len(d.hashes) >= d.maxEntries {
		return
	}

	d.hashes[h] = provider
}

// Reset clears all stored hashes.
func (d *Deduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hashes = make(map[string]string)
}

// Len returns the number of stored hashes.
func (d *Deduplicator) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.hashes)
}

// Hash generates a SHA-256 content hash of a response body, returned as
// a hex-encoded string.
func Hash(response []byte) string {
	h := sha256.Sum256(response)
	return hex.EncodeToString(h[:])
}
