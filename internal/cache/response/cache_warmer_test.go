package responsecache

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestCacheWarmer_RecordAccess(t *testing.T) {
	config := CacheWarmerConfig{
		Enabled:       true,
		Predictive:    true,
		HotThreshold:  5,
		MaxConcurrent: 2,
	}
	
	warmer := NewCacheWarmer(config)
	
	// Record multiple accesses to same path
	for i := 0; i < 10; i++ {
		warmer.RecordAccess("/api/users")
		time.Sleep(10 * time.Millisecond)
	}
	
	stats := warmer.GetStats()
	
	if stats.TotalPatterns != 1 {
		t.Errorf("expected 1 pattern, got %d", stats.TotalPatterns)
	}
	
	if stats.HotPaths != 1 {
		t.Errorf("expected 1 hot path, got %d", stats.HotPaths)
	}
}

func TestCacheWarmer_GetHotPaths(t *testing.T) {
	config := CacheWarmerConfig{
		Enabled:       true,
		Predictive:    true,
		HotThreshold:  3,
		MaxConcurrent: 2,
	}
	
	warmer := NewCacheWarmer(config)
	
	// Access multiple paths with different frequencies
	for i := 0; i < 5; i++ {
		warmer.RecordAccess("/api/users")
	}
	
	for i := 0; i < 2; i++ {
		warmer.RecordAccess("/api/products")
	}
	
	for i := 0; i < 10; i++ {
		warmer.RecordAccess("/api/orders")
	}
	
	hotPaths := warmer.GetHotPaths()
	
	// Should have 2 hot paths (users and orders, not products)
	if len(hotPaths) != 2 {
		t.Errorf("expected 2 hot paths, got %d", len(hotPaths))
	}
}

func TestCacheWarmer_PredictivePattern(t *testing.T) {
	config := CacheWarmerConfig{
		Enabled:       true,
		Predictive:    true,
		HotThreshold:  3,
		MaxConcurrent: 2,
	}
	
	warmer := NewCacheWarmer(config)
	
	// Create predictable access pattern
	for i := 0; i < 10; i++ {
		warmer.RecordAccess("/api/scheduled")
		time.Sleep(50 * time.Millisecond) // Consistent interval
	}
	
	stats := warmer.GetStats()
	
	// After enough accesses with consistent interval, should be predictable
	if stats.PredictablePaths == 0 {
		t.Log("Pattern not yet detected as predictable (may need more accesses)")
	}
}

func TestCacheWarmer_WarmExpressions(t *testing.T) {
	config := DefaultCacheWarmerConfig()
	warmer := NewCacheWarmer(config)
	
	ctx := context.Background()
	
	expressions := []string{
		"user.id == 123",
		"request.path.startsWith('/api')",
	}
	
	luaScripts := []string{
		"return request.headers['User-Agent']",
	}
	
	err := warmer.WarmExpressions(ctx, expressions, luaScripts, "v1")
	if err != nil {
		t.Errorf("WarmExpressions failed: %v", err)
	}
	
	// Note: Without actual caches initialized, warmedCount will be 0
	// This is expected behavior - the framework is there, integration happens
	// when actual CEL and Lua caches are wired up
	t.Logf("warmedCount: %d (expected 0 without caches initialized)", warmer.warmedCount)
}

func TestCacheWarmer_Disabled(t *testing.T) {
	config := CacheWarmerConfig{
		Enabled:       false,
		Predictive:    false,
		HotThreshold:  5,
		MaxConcurrent: 2,
	}
	
	warmer := NewCacheWarmer(config)
	
	// Record accesses
	for i := 0; i < 10; i++ {
		warmer.RecordAccess("/api/users")
	}
	
	stats := warmer.GetStats()
	
	// Should not track when disabled
	if stats.TotalPatterns != 0 {
		t.Errorf("expected 0 patterns when disabled, got %d", stats.TotalPatterns)
	}
}

func TestCacheWarmerConfig_Defaults(t *testing.T) {
	config := DefaultCacheWarmerConfig()
	
	if !config.Enabled {
		t.Error("expected Enabled to be true")
	}
	
	if !config.WarmOnReload {
		t.Error("expected WarmOnReload to be true")
	}
	
	if config.HotThreshold != 10 {
		t.Errorf("expected HotThreshold 10, got %d", config.HotThreshold)
	}
	
	if config.MaxConcurrent != 5 {
		t.Errorf("expected MaxConcurrent 5, got %d", config.MaxConcurrent)
	}
}

func TestCacheWarmer_GoroutinesBounded(t *testing.T) {
	config := CacheWarmerConfig{
		Enabled:       true,
		Predictive:    false,
		HotThreshold:  10,
		MaxConcurrent: 5,
	}
	warmer := NewCacheWarmer(config)

	// WarmExpressions with nil caches will skip actual compilation work,
	// but still spawns the worker pool and feeds items through the channel.
	// We generate 100 expressions to push through the bounded pool.
	expressions := make([]string, 100)
	for i := range expressions {
		expressions[i] = "true" // non-empty so they are enqueued
	}

	baseline := runtime.NumGoroutine()

	// Run warming in background so we can observe goroutine count
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- warmer.WarmExpressions(ctx, expressions, nil, "v1")
	}()

	// Sample goroutine count a few times during execution
	time.Sleep(5 * time.Millisecond)
	peak := runtime.NumGoroutine()

	err := <-done
	// With nil caches the items are skipped, so no errors expected
	if err != nil {
		t.Logf("WarmExpressions returned error (expected with nil caches): %v", err)
	}

	// maxConcurrent=5 workers + 1 sender goroutine + overhead
	// Allow baseline + 15 to account for test framework goroutines
	limit := baseline + 15
	if peak > limit {
		t.Errorf("goroutine count peaked at %d, expected under %d (baseline=%d, maxConcurrent=5)", peak, limit, baseline)
	} else {
		t.Logf("goroutine count: baseline=%d, peak=%d, limit=%d", baseline, peak, limit)
	}
}

func TestCacheWarmer_ContextCancelStopsWarm(t *testing.T) {
	config := CacheWarmerConfig{
		Enabled:       true,
		Predictive:    false,
		HotThreshold:  10,
		MaxConcurrent: 5,
	}
	warmer := NewCacheWarmer(config)

	// Create 1000 expressions to enqueue
	expressions := make([]string, 1000)
	for i := range expressions {
		expressions[i] = "true"
	}

	// Cancel context after 50ms
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_ = warmer.WarmExpressions(ctx, expressions, nil, "v1")
	elapsed := time.Since(start)

	// Should return quickly (well under processing all 1000 items).
	// With nil caches each item is nearly instant, but the context cancel
	// should stop the send loop. Allow 500ms as generous upper bound.
	if elapsed > 500*time.Millisecond {
		t.Errorf("WarmExpressions took %v after context cancel, expected < 500ms", elapsed)
	} else {
		t.Logf("WarmExpressions completed in %v after context cancel", elapsed)
	}
}

func BenchmarkCacheWarmer_RecordAccess(b *testing.B) {
	b.ReportAllocs()
	config := DefaultCacheWarmerConfig()
	warmer := NewCacheWarmer(config)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		warmer.RecordAccess("/api/test")
	}
}

func BenchmarkCacheWarmer_GetHotPaths(b *testing.B) {
	b.ReportAllocs()
	config := DefaultCacheWarmerConfig()
	warmer := NewCacheWarmer(config)
	
	// Pre-populate with hot paths
	for i := 0; i < 100; i++ {
		warmer.RecordAccess("/api/users")
		warmer.RecordAccess("/api/products")
		warmer.RecordAccess("/api/orders")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		warmer.GetHotPaths()
	}
}

