// Copyright 2026 Soap Bucket LLC. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package vault

import (
	"sync"
	"time"
)

// SecretMetadata tracks metadata for a resolved secret, including when it
// was first and last resolved and the total number of resolutions.
type SecretMetadata struct {
	Name          string    `json:"name"`
	Source        string    `json:"source"`          // which vault backend resolved this secret
	FirstResolved time.Time `json:"first_resolved"`
	LastResolved  time.Time `json:"last_resolved"`
	ResolveCount  int64     `json:"resolve_count"`
}

// MetadataTracker tracks metadata for all resolved secrets. It is safe for
// concurrent use from multiple goroutines.
type MetadataTracker struct {
	mu      sync.RWMutex
	entries map[string]*SecretMetadata
}

// NewMetadataTracker creates a new MetadataTracker.
func NewMetadataTracker() *MetadataTracker {
	return &MetadataTracker{
		entries: make(map[string]*SecretMetadata),
	}
}

// Record updates metadata for a secret after resolution. If this is the
// first time the secret has been seen, FirstResolved is set. LastResolved
// and ResolveCount are always updated.
func (mt *MetadataTracker) Record(name, source string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	now := time.Now()
	entry, exists := mt.entries[name]
	if !exists {
		mt.entries[name] = &SecretMetadata{
			Name:          name,
			Source:        source,
			FirstResolved: now,
			LastResolved:  now,
			ResolveCount:  1,
		}
		return
	}

	entry.Source = source
	entry.LastResolved = now
	entry.ResolveCount++
}

// Get returns metadata for a specific secret, or nil if not tracked.
func (mt *MetadataTracker) Get(name string) *SecretMetadata {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	entry, exists := mt.entries[name]
	if !exists {
		return nil
	}

	// Return a copy to prevent data races on the caller side
	copy := *entry
	return &copy
}

// All returns metadata for all tracked secrets. The returned map contains
// copies of each entry.
func (mt *MetadataTracker) All() map[string]*SecretMetadata {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	out := make(map[string]*SecretMetadata, len(mt.entries))
	for k, v := range mt.entries {
		copy := *v
		out[k] = &copy
	}
	return out
}

// Len returns the number of tracked secrets.
func (mt *MetadataTracker) Len() int {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return len(mt.entries)
}

// Remove removes metadata for a specific secret.
func (mt *MetadataTracker) Remove(name string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	delete(mt.entries, name)
}
