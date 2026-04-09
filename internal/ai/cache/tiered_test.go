package cache

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// mockL2Store is a simple in-memory L2Store for testing.
type mockL2Store struct {
	mu    sync.Mutex
	items map[string]*CachedResponse
}

func newMockL2Store() *mockL2Store {
	return &mockL2Store{items: make(map[string]*CachedResponse)}
}

func (m *mockL2Store) Get(_ context.Context, key string) (*CachedResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resp, ok := m.items[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return resp, nil
}

func (m *mockL2Store) Set(_ context.Context, key string, resp *CachedResponse, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = resp
	return nil
}

func (m *mockL2Store) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

// mockVectorStore is a simple in-memory VectorStore for testing semantic lookups.
type mockVectorStore struct {
	mu      sync.Mutex
	entries []VectorEntry
}

func newMockVectorStore() *mockVectorStore {
	return &mockVectorStore{}
}

func (m *mockVectorStore) Search(_ context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var results []VectorEntry
	for _, e := range m.entries {
		sim := cosineSimilarity(embedding, e.Embedding)
		if sim >= threshold {
			entry := e
			entry.Similarity = sim
			results = append(results, entry)
		}
	}
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *mockVectorStore) Store(_ context.Context, entry VectorEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockVectorStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.entries {
		if e.Key == key {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockVectorStore) Size(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.entries)), nil
}

func (m *mockVectorStore) Health(_ context.Context) CacheHealth {
	return CacheHealth{Healthy: true, StoreType: "mock"}
}

func newTestConfig() TieredCacheConfig {
	return TieredCacheConfig{
		Enabled:           true,
		L1MaxEntries:      1000,
		L1TTL:             5 * time.Minute,
		L2Enabled:         true,
		L2TTL:             30 * time.Minute,
		SemanticEnabled:   true,
		SemanticThreshold: 0.95,
		CoalesceEnabled:   true,
		CoalesceWindow:    100 * time.Millisecond,
		SWREnabled:        true,
		SWRTTL:            10 * time.Minute,
	}
}

func newTestResponse(key, model string) *CachedResponse {
	return &CachedResponse{
		Key:       key,
		Response:  json.RawMessage(`{"choices":[{"message":{"content":"Hello!"}}]}`),
		Model:     model,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func newTestSemanticCache(store VectorStore) *SemanticCache {
	return &SemanticCache{
		store:    store,
		config:   &SemanticCacheConfig{SimilarityThreshold: 0.95, TTLSeconds: 3600, MaxEntries: 1000},
		excludes: make(map[string]bool),
	}
}

func TestTieredCache_L1Hit(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	resp := newTestResponse("key1", "gpt-4o")
	tc.l1.Set("key1", resp)

	got, err := tc.Lookup(ctx, "key1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected L1 hit, got nil")
	}
	if string(got.Response) != string(resp.Response) {
		t.Errorf("response mismatch: got %s, want %s", got.Response, resp.Response)
	}

	snap := tc.metrics.Snapshot()
	if snap.L1Hits != 1 {
		t.Errorf("expected L1Hits=1, got %d", snap.L1Hits)
	}
}

func TestTieredCache_L1Miss_L2Hit(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	resp := newTestResponse("key2", "gpt-4o")
	l2.Set(ctx, "key2", resp, 30*time.Minute)

	got, err := tc.Lookup(ctx, "key2", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected L2 hit, got nil")
	}
	if string(got.Response) != string(resp.Response) {
		t.Errorf("response mismatch")
	}

	// Verify promoted to L1.
	l1got := tc.l1.Get("key2")
	if l1got == nil {
		t.Error("expected L2 hit to be promoted to L1")
	}

	snap := tc.metrics.Snapshot()
	if snap.L1Misses != 1 {
		t.Errorf("expected L1Misses=1, got %d", snap.L1Misses)
	}
	if snap.L2Hits != 1 {
		t.Errorf("expected L2Hits=1, got %d", snap.L2Hits)
	}
}

func TestTieredCache_L1L2Miss_SemanticHit(t *testing.T) {
	l2 := newMockL2Store()
	vs := newMockVectorStore()
	sc := newTestSemanticCache(vs)

	config := newTestConfig()
	tc := NewTieredCache(config, l2, sc)
	ctx := context.Background()

	// Store a vector entry directly in the vector store.
	embedding := []float32{1.0, 0.0, 0.0}
	vs.Store(ctx, VectorEntry{
		Key:       "semantic-key",
		Embedding: embedding,
		Response:  json.RawMessage(`{"result":"semantic"}`),
		Model:     "gpt-4o",
		CreatedAt: time.Now(),
		TTL:       time.Hour,
	})

	// Look up with the same embedding (converted to float64).
	queryEmb := []float64{1.0, 0.0, 0.0}
	got, err := tc.Lookup(ctx, "exact-key", queryEmb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected semantic hit, got nil")
	}
	if string(got.Response) != `{"result":"semantic"}` {
		t.Errorf("unexpected response: %s", got.Response)
	}

	snap := tc.metrics.Snapshot()
	if snap.SemanticHits != 1 {
		t.Errorf("expected SemanticHits=1, got %d", snap.SemanticHits)
	}
}

func TestTieredCache_AllMiss(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	got, err := tc.Lookup(ctx, "nonexistent", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %v", got)
	}

	snap := tc.metrics.Snapshot()
	if snap.L1Misses != 1 {
		t.Errorf("expected L1Misses=1, got %d", snap.L1Misses)
	}
	if snap.L2Misses != 1 {
		t.Errorf("expected L2Misses=1, got %d", snap.L2Misses)
	}
}

func TestTieredCache_Store_L1AndL2(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	resp := newTestResponse("store-key", "gpt-4o")
	err := tc.Store(ctx, "store-key", resp, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify in L1.
	l1got := tc.l1.Get("store-key")
	if l1got == nil {
		t.Error("expected response stored in L1")
	}

	// Verify in L2.
	l2got, err := l2.Get(ctx, "store-key")
	if err != nil {
		t.Fatalf("L2 get error: %v", err)
	}
	if l2got == nil {
		t.Error("expected response stored in L2")
	}

	snap := tc.metrics.Snapshot()
	if snap.Stores != 1 {
		t.Errorf("expected Stores=1, got %d", snap.Stores)
	}
}

func TestTieredCache_TTLExpiry(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	resp := &CachedResponse{
		Key:       "expired-key",
		Response:  json.RawMessage(`{"expired":true}`),
		Model:     "gpt-4o",
		CreatedAt: time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-1 * time.Minute), // Already expired.
	}
	tc.l1.Set("expired-key", resp)

	got, err := tc.Lookup(ctx, "expired-key", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for expired entry, got %v", got)
	}

	// Verify evicted from L1.
	if tc.l1.Get("expired-key") != nil {
		t.Error("expired entry should be removed from L1")
	}
}

func TestTieredCache_SWR_ServeStale(t *testing.T) {
	l2 := newMockL2Store()
	config := newTestConfig()
	config.SWREnabled = true
	config.SWRTTL = 10 * time.Minute
	tc := NewTieredCache(config, l2, nil)
	ctx := context.Background()

	// Create an entry that is expired but within SWR window.
	resp := &CachedResponse{
		Key:       "swr-key",
		Response:  json.RawMessage(`{"stale":true}`),
		Model:     "gpt-4o",
		CreatedAt: time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-1 * time.Minute),          // Expired 1 min ago.
		SWRUntil:  time.Now().Add(9 * time.Minute),           // Servable for 9 more min.
	}
	tc.l1.Set("swr-key", resp)

	got, err := tc.Lookup(ctx, "swr-key", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected SWR to serve stale entry")
	}
	if string(got.Response) != `{"stale":true}` {
		t.Errorf("unexpected response: %s", got.Response)
	}

	snap := tc.metrics.Snapshot()
	if snap.SWRServed != 1 {
		t.Errorf("expected SWRServed=1, got %d", snap.SWRServed)
	}
}

func TestTieredCache_Coalesce_Dedup(t *testing.T) {
	l2 := newMockL2Store()
	config := newTestConfig()
	config.CoalesceEnabled = true
	tc := NewTieredCache(config, l2, nil)
	ctx := context.Background()

	// First requester starts coalescing.
	isFirst := tc.StartCoalesce("coal-key")
	if !isFirst {
		t.Fatal("expected first requester to be the leader")
	}

	// Second requester should not be first.
	isFirst2 := tc.StartCoalesce("coal-key")
	if isFirst2 {
		t.Fatal("expected second requester to NOT be the leader")
	}

	// Complete the coalesced request in a goroutine.
	resp := newTestResponse("coal-key", "gpt-4o")
	go func() {
		time.Sleep(10 * time.Millisecond)
		tc.CompleteCoalesce("coal-key", resp, nil)
	}()

	// Second requester waits for result.
	got, err := tc.WaitCoalesce(ctx, "coal-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected coalesced response, got nil")
	}
	if string(got.Response) != string(resp.Response) {
		t.Errorf("response mismatch")
	}

	snap := tc.metrics.Snapshot()
	if snap.CoalesceHits != 1 {
		t.Errorf("expected CoalesceHits=1, got %d", snap.CoalesceHits)
	}
}

func TestTieredCache_Coalesce_Timeout(t *testing.T) {
	l2 := newMockL2Store()
	config := newTestConfig()
	config.CoalesceEnabled = true
	tc := NewTieredCache(config, l2, nil)

	tc.StartCoalesce("timeout-key")

	// Create a context that expires quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// This should not be the first requester.
	tc.StartCoalesce("timeout-key")

	got, err := tc.WaitCoalesce(ctx, "timeout-key")
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if got != nil {
		t.Errorf("expected nil on timeout, got response")
	}

	// Clean up the inflight entry.
	tc.CompleteCoalesce("timeout-key", nil, fmt.Errorf("cancelled"))
}

func TestTieredCache_Invalidate(t *testing.T) {
	l2 := newMockL2Store()
	vs := newMockVectorStore()
	sc := newTestSemanticCache(vs)
	tc := NewTieredCache(newTestConfig(), l2, sc)
	ctx := context.Background()

	resp := newTestResponse("inv-key", "gpt-4o")
	tc.Store(ctx, "inv-key", resp, nil)

	// Verify stored.
	if tc.l1.Get("inv-key") == nil {
		t.Fatal("expected response in L1 before invalidation")
	}

	err := tc.Invalidate(ctx, "inv-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify removed from L1.
	if tc.l1.Get("inv-key") != nil {
		t.Error("expected entry removed from L1 after invalidation")
	}

	// Verify removed from L2.
	_, err = l2.Get(ctx, "inv-key")
	if err == nil {
		t.Error("expected entry removed from L2 after invalidation")
	}
}

func TestTieredCache_Metrics(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	// Generate some L1 hits and misses.
	resp := newTestResponse("m-key", "gpt-4o")
	tc.l1.Set("m-key", resp)

	tc.Lookup(ctx, "m-key", nil)   // L1 hit
	tc.Lookup(ctx, "m-key", nil)   // L1 hit
	tc.Lookup(ctx, "miss-1", nil)  // L1 miss, L2 miss
	tc.Store(ctx, "new-1", newTestResponse("new-1", "gpt-4o"), nil)

	snap := tc.metrics.Snapshot()
	if snap.L1Hits != 2 {
		t.Errorf("expected L1Hits=2, got %d", snap.L1Hits)
	}
	if snap.L1Misses != 1 {
		t.Errorf("expected L1Misses=1, got %d", snap.L1Misses)
	}
	if snap.L2Misses != 1 {
		t.Errorf("expected L2Misses=1, got %d", snap.L2Misses)
	}
	if snap.Stores != 1 {
		t.Errorf("expected Stores=1, got %d", snap.Stores)
	}
}

func TestTieredCache_ConcurrentAccess(t *testing.T) {
	l2 := newMockL2Store()
	tc := NewTieredCache(newTestConfig(), l2, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	const goroutines = 50
	const opsPerGoroutine = 100

	// Pre-populate some entries.
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("conc-%d", i)
		tc.l1.Set(key, newTestResponse(key, "gpt-4o"))
	}

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				key := fmt.Sprintf("conc-%d", i%20)
				switch i % 3 {
				case 0:
					tc.Lookup(ctx, key, nil)
				case 1:
					tc.Store(ctx, key, newTestResponse(key, "gpt-4o"), nil)
				case 2:
					tc.Invalidate(ctx, key)
				}
			}
		}(g)
	}
	wg.Wait()

	// Just verify no panics or deadlocks occurred.
	snap := tc.metrics.Snapshot()
	if snap.L1Hits+snap.L1Misses == 0 {
		t.Error("expected some L1 operations")
	}
}

func TestBuildCacheKey_Deterministic(t *testing.T) {
	msgs := json.RawMessage(`[{"role":"user","content":"Hello"}]`)
	temp := 0.7

	key1 := BuildCacheKey("gpt-4o", msgs, &temp, 1000)
	key2 := BuildCacheKey("gpt-4o", msgs, &temp, 1000)

	if key1 != key2 {
		t.Errorf("expected deterministic keys, got %s and %s", key1, key2)
	}

	// Same content, different JSON formatting should produce same key.
	msgs2 := json.RawMessage(`[{"content":"Hello","role":"user"}]`)
	key3 := BuildCacheKey("gpt-4o", msgs2, &temp, 1000)
	if key1 != key3 {
		t.Errorf("expected normalized keys to match, got %s and %s", key1, key3)
	}
}

func TestBuildCacheKey_DifferentInputs(t *testing.T) {
	msgs := json.RawMessage(`[{"role":"user","content":"Hello"}]`)
	temp := 0.7

	key1 := BuildCacheKey("gpt-4o", msgs, &temp, 1000)

	// Different model.
	key2 := BuildCacheKey("gpt-3.5-turbo", msgs, &temp, 1000)
	if key1 == key2 {
		t.Error("different models should produce different keys")
	}

	// Different temperature.
	temp2 := 0.9
	key3 := BuildCacheKey("gpt-4o", msgs, &temp2, 1000)
	if key1 == key3 {
		t.Error("different temperatures should produce different keys")
	}

	// Nil temperature vs non-nil.
	key4 := BuildCacheKey("gpt-4o", msgs, nil, 1000)
	if key1 == key4 {
		t.Error("nil temperature should produce different key than non-nil")
	}

	// Different max_tokens.
	key5 := BuildCacheKey("gpt-4o", msgs, &temp, 2000)
	if key1 == key5 {
		t.Error("different max_tokens should produce different keys")
	}

	// Different messages.
	msgs2 := json.RawMessage(`[{"role":"user","content":"Goodbye"}]`)
	key6 := BuildCacheKey("gpt-4o", msgs2, &temp, 1000)
	if key1 == key6 {
		t.Error("different messages should produce different keys")
	}
}

func TestL1Cache_MaxEntries(t *testing.T) {
	// Create a cache with max 32 entries (2 per shard).
	c := NewL1Cache(32)

	// Insert more than max entries.
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("evict-%d", i)
		c.Set(key, &CachedResponse{
			Key:       key,
			Response:  json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
			Model:     "gpt-4o",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
	}

	// Size should not exceed max.
	size := c.Size()
	if size > 32 {
		t.Errorf("expected size <= 32 after eviction, got %d", size)
	}
}

func TestCoalescer_BasicDedup(t *testing.T) {
	c := NewCoalescer(100 * time.Millisecond)

	// First request.
	isFirst := c.Start("dedup-key")
	if !isFirst {
		t.Fatal("expected first requester to be leader")
	}

	// Second request should not be first.
	isFirst2 := c.Start("dedup-key")
	if isFirst2 {
		t.Fatal("expected second requester to NOT be leader")
	}

	// Complete from another goroutine.
	resp := newTestResponse("dedup-key", "gpt-4o")
	go func() {
		time.Sleep(5 * time.Millisecond)
		c.Complete("dedup-key", resp, nil)
	}()

	got, err := c.Wait(context.Background(), "dedup-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected response from coalesced wait")
	}
}

func TestCoalescer_Error(t *testing.T) {
	c := NewCoalescer(100 * time.Millisecond)

	c.Start("err-key")
	c.Start("err-key") // Second requester.

	// Complete with error.
	expectedErr := fmt.Errorf("upstream failure")
	go func() {
		time.Sleep(5 * time.Millisecond)
		c.Complete("err-key", nil, expectedErr)
	}()

	got, err := c.Wait(context.Background(), "err-key")
	if err == nil {
		t.Fatal("expected error from coalesced wait")
	}
	if err.Error() != expectedErr.Error() {
		t.Errorf("expected error %q, got %q", expectedErr, err)
	}
	if got != nil {
		t.Error("expected nil response on error")
	}
}

func TestTieredCache_Disabled(t *testing.T) {
	config := newTestConfig()
	config.Enabled = false
	tc := NewTieredCache(config, nil, nil)
	ctx := context.Background()

	// Lookup should return nil when disabled.
	got, err := tc.Lookup(ctx, "any-key", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil when cache is disabled")
	}

	// Store should be a no-op.
	err = tc.Store(ctx, "any-key", newTestResponse("any-key", "gpt-4o"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.l1.Get("any-key") != nil {
		t.Error("store should be no-op when disabled")
	}
}

func TestTieredCache_Store_SetsSWRUntil(t *testing.T) {
	config := newTestConfig()
	config.SWREnabled = true
	config.SWRTTL = 15 * time.Minute
	tc := NewTieredCache(config, newMockL2Store(), nil)
	ctx := context.Background()

	resp := &CachedResponse{
		Key:       "swr-store-key",
		Response:  json.RawMessage(`{"ok":true}`),
		Model:     "gpt-4o",
		CreatedAt: time.Now(),
	}
	tc.Store(ctx, "swr-store-key", resp, nil)

	stored := tc.l1.Get("swr-store-key")
	if stored == nil {
		t.Fatal("expected stored response")
	}
	if stored.SWRUntil.IsZero() {
		t.Error("expected SWRUntil to be set")
	}
	if stored.ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}
	// SWRUntil should be after ExpiresAt.
	if !stored.SWRUntil.After(stored.ExpiresAt) {
		t.Error("expected SWRUntil to be after ExpiresAt")
	}
}

func TestTieredCache_CoalesceDisabled(t *testing.T) {
	config := newTestConfig()
	config.CoalesceEnabled = false
	tc := NewTieredCache(config, newMockL2Store(), nil)

	// StartCoalesce should always return true when disabled.
	if !tc.StartCoalesce("any") {
		t.Error("expected StartCoalesce to return true when coalescing is disabled")
	}

	// WaitCoalesce should return nil immediately.
	got, err := tc.WaitCoalesce(context.Background(), "any")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil when coalescing is disabled")
	}
}

func TestTieredCache_MultipleCoalescedWaiters(t *testing.T) {
	config := newTestConfig()
	config.CoalesceEnabled = true
	tc := NewTieredCache(config, newMockL2Store(), nil)
	ctx := context.Background()

	// First requester.
	tc.StartCoalesce("multi-key")

	// Start multiple waiters.
	var wg sync.WaitGroup
	var hits atomic.Int64
	const waiters = 10

	for i := 0; i < waiters; i++ {
		tc.StartCoalesce("multi-key") // All return false.
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := tc.WaitCoalesce(ctx, "multi-key")
			if err == nil && got != nil {
				hits.Add(1)
			}
		}()
	}

	// Small delay then complete.
	time.Sleep(5 * time.Millisecond)
	tc.CompleteCoalesce("multi-key", newTestResponse("multi-key", "gpt-4o"), nil)

	wg.Wait()
	if hits.Load() != int64(waiters) {
		t.Errorf("expected %d coalesce hits, got %d", waiters, hits.Load())
	}
}
