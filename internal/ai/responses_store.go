// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"sync"
	"time"
)

// ResponseStore persists response objects for the Responses API.
type ResponseStore interface {
	// Store saves a response object.
	Store(ctx context.Context, resp *ResponseObject) error
	// Get retrieves a response object by ID.
	Get(ctx context.Context, id string) (*ResponseObject, error)
	// Delete removes a response object by ID.
	Delete(ctx context.Context, id string) error
	// List returns stored responses in insertion order, with optional pagination.
	List(ctx context.Context, limit int, after string) ([]*ResponseObject, error)
}

// MemoryResponseStore is a bounded, TTL-aware in-memory implementation of ResponseStore.
type MemoryResponseStore struct {
	mu      sync.RWMutex
	store   map[string]*ResponseObject
	order   []string      // insertion order for List and eviction
	maxSize int           // max stored responses
	ttl     time.Duration // auto-expire after TTL

	done chan struct{}
	once sync.Once
}

// NewMemoryResponseStore creates a new in-memory response store.
// maxSize controls the maximum number of stored responses (0 defaults to 10000).
// ttl controls auto-expiry (0 defaults to 1 hour).
func NewMemoryResponseStore(maxSize int, ttl time.Duration) *MemoryResponseStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	s := &MemoryResponseStore{
		store:   make(map[string]*ResponseObject),
		order:   make([]string, 0, 64),
		maxSize: maxSize,
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// Store saves a response object. If the store is at capacity, the oldest entry is evicted.
func (s *MemoryResponseStore) Store(_ context.Context, resp *ResponseObject) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If this ID already exists, just update in place
	if _, exists := s.store[resp.ID]; exists {
		s.store[resp.ID] = resp
		return nil
	}

	// Evict oldest if at capacity
	for len(s.store) >= s.maxSize && len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.store, oldest)
	}

	s.store[resp.ID] = resp
	s.order = append(s.order, resp.ID)
	return nil
}

// Get retrieves a response by ID. Returns nil and no error if not found.
func (s *MemoryResponseStore) Get(_ context.Context, id string) (*ResponseObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp, ok := s.store[id]
	if !ok {
		return nil, nil
	}
	return resp, nil
}

// Delete removes a response by ID.
func (s *MemoryResponseStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.store, id)
	// Remove from order slice
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// List returns up to limit responses in insertion order. If after is non-empty,
// results start after that cursor ID.
func (s *MemoryResponseStore) List(_ context.Context, limit int, after string) ([]*ResponseObject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 20
	}

	startIdx := 0
	if after != "" {
		for i, id := range s.order {
			if id == after {
				startIdx = i + 1
				break
			}
		}
	}

	var results []*ResponseObject
	for i := startIdx; i < len(s.order) && len(results) < limit; i++ {
		if resp, ok := s.store[s.order[i]]; ok {
			results = append(results, resp)
		}
	}
	return results, nil
}

// Len returns the number of stored responses.
func (s *MemoryResponseStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.store)
}

// Close stops the background cleanup goroutine.
func (s *MemoryResponseStore) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}

// cleanup runs a periodic TTL sweep in the background.
func (s *MemoryResponseStore) cleanup() {
	ticker := time.NewTicker(s.ttl / 4)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.expireOld()
		}
	}
}

// expireOld removes entries older than the configured TTL.
func (s *MemoryResponseStore) expireOld() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Unix() - int64(s.ttl.Seconds())
	// Walk from oldest to newest; stop at first non-expired entry.
	removed := 0
	for _, id := range s.order {
		resp, ok := s.store[id]
		if !ok {
			removed++
			continue
		}
		if resp.CreatedAt < cutoff {
			delete(s.store, id)
			removed++
		} else {
			break
		}
	}
	if removed > 0 {
		s.order = s.order[removed:]
	}
}
