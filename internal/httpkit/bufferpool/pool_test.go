package bufferpool

import (
	"sync"
	"testing"
	"time"
)

// Test TieredBufferPool (existing tests)
func TestTieredBufferPool_GetPut(t *testing.T) {
	t.Parallel()
	pool := NewTieredBufferPool()
	
	tests := []struct {
		name string
		size int
		want int
	}{
		{"small", 2048, SmallSize},
		{"medium", 32768, MediumSize},
		{"large", 512 * 1024, LargeSize},
		{"xlarge", 5 * 1024 * 1024, XLargeSize},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := pool.Get(tt.size)
			if buf == nil {
				t.Fatal("Get returned nil")
			}
			if cap(*buf) != tt.want {
				t.Errorf("Get() capacity = %d, want %d", cap(*buf), tt.want)
			}
			
			// Put back
			pool.Put(buf)
		})
	}
}

func TestTieredBufferPool_Stats(t *testing.T) {
	t.Parallel()
	pool := NewTieredBufferPool()
	
	// Get some buffers
	buf1 := pool.Get(1024)
	buf2 := pool.Get(32768)
	buf3 := pool.Get(512 * 1024)
	
	stats := pool.Stats()
	if stats.SmallGets != 1 {
		t.Errorf("SmallGets = %d, want 1", stats.SmallGets)
	}
	if stats.MediumGets != 1 {
		t.Errorf("MediumGets = %d, want 1", stats.MediumGets)
	}
	if stats.LargeGets != 1 {
		t.Errorf("LargeGets = %d, want 1", stats.LargeGets)
	}
	
	// Put back
	pool.Put(buf1)
	pool.Put(buf2)
	pool.Put(buf3)
}

// Test AdaptiveBufferPool
func TestAdaptiveBufferPool_Basic(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour // Don't adjust during test
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	// Test getting buffers
	tests := []struct {
		name string
		size int
	}{
		{"small", 2048},
		{"medium", 32768},
		{"large", 512 * 1024},
		{"xlarge", 5 * 1024 * 1024},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := pool.Get(tt.size)
			if buf == nil {
				t.Fatal("Get returned nil")
			}
			if len(*buf) != tt.size {
				t.Errorf("Get() length = %d, want %d", len(*buf), tt.size)
			}
			
			// Put back
			pool.Put(buf)
		})
	}
}

func TestAdaptiveBufferPool_GetPutConcurrent(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour // Don't adjust during test
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	const goroutines = 100
	const iterations = 100
	
	var wg sync.WaitGroup
	wg.Add(goroutines)
	
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < iterations; j++ {
				// Vary size to test different tiers
				size := (id*100 + j*10) % (10 * 1024 * 1024)
				if size < 1024 {
					size = 1024
				}
				
				buf := pool.Get(size)
				if buf == nil {
					t.Errorf("Get returned nil for size %d", size)
					return
				}
				
				// Simulate work
				(*buf)[0] = byte(id)
				
				// Put back
				pool.Put(buf)
			}
		}(i)
	}
	
	wg.Wait()
}

func TestAdaptiveBufferPool_Stats(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	// Get some buffers
	sizes := []int{1024, 32768, 512 * 1024}
	bufs := make([]*[]byte, len(sizes))
	
	for i, size := range sizes {
		bufs[i] = pool.Get(size)
	}
	
	stats := pool.Stats()
	if stats.TierCount != len(config.InitialSizes) {
		t.Errorf("TierCount = %d, want %d", stats.TierCount, len(config.InitialSizes))
	}
	if stats.TotalGets < int64(len(sizes)) {
		t.Errorf("TotalGets = %d, want >= %d", stats.TotalGets, len(sizes))
	}
	
	// Put back
	for _, buf := range bufs {
		pool.Put(buf)
	}
	
	stats = pool.Stats()
	if stats.TotalPuts != int64(len(sizes)) {
		t.Errorf("TotalPuts = %d, want %d", stats.TotalPuts, len(sizes))
	}
}

func TestAdaptiveBufferPool_AdjustSizes(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour // Manual control
	config.HistorySize = 1000
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	// Record usage pattern: mostly small buffers
	for i := 0; i < 500; i++ {
		buf := pool.Get(2048) // 2KB
		pool.Put(buf)
	}
	
	// Some medium buffers
	for i := 0; i < 300; i++ {
		buf := pool.Get(32768) // 32KB
		pool.Put(buf)
	}
	
	// Few large buffers
	for i := 0; i < 100; i++ {
		buf := pool.Get(512 * 1024) // 512KB
		pool.Put(buf)
	}
	
	// Record initial tier sizes
	initialStats := pool.Stats()
	initialTierCount := initialStats.TierCount
	
	// Trigger adjustment
	pool.AdjustSizes()
	
	// Check stats after adjustment
	newStats := pool.Stats()
	
	// Tiers should still exist (might change based on data)
	if newStats.TierCount < pool.minTiers {
		t.Errorf("TierCount after adjustment = %d, want >= %d", newStats.TierCount, pool.minTiers)
	}
	if newStats.TierCount > pool.maxTiers {
		t.Errorf("TierCount after adjustment = %d, want <= %d", newStats.TierCount, pool.maxTiers)
	}
	
	t.Logf("Initial tier count: %d", initialTierCount)
	t.Logf("New tier count: %d", newStats.TierCount)
	
	for i, tier := range newStats.Tiers {
		t.Logf("Tier %d: name=%s, size=%d bytes, gets=%d, puts=%d, allocs=%d",
			i, tier.Name, tier.Size, tier.Gets, tier.Puts, tier.Allocations)
	}
}

func TestAdaptiveBufferPool_AdjustSizesWithInsufficientData(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour
	config.HistorySize = 1000
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	// Record only a few requests (less than 100)
	for i := 0; i < 50; i++ {
		buf := pool.Get(2048)
		pool.Put(buf)
	}
	
	initialStats := pool.Stats()
	initialTierCount := initialStats.TierCount
	
	// Trigger adjustment - should not change tiers
	pool.AdjustSizes()
	
	newStats := pool.Stats()
	if newStats.TierCount != initialTierCount {
		t.Errorf("TierCount changed with insufficient data: initial=%d, new=%d",
			initialTierCount, newStats.TierCount)
	}
}

func TestAdaptiveBufferPool_PercentileCalculation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []int
		p    float64
		want int
	}{
		{"p50 of 1-10", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.50, 5},
		{"p90 of 1-10", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.90, 9},
		{"p99 of 1-10", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.99, 9}, // p99 of 10 elements = index 8.91 -> 9
		{"empty data", []int{}, 0.50, 0},
		{"single element", []int{42}, 0.50, 42},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Data should be sorted for percentile
			got := percentile(tt.data, tt.p)
			if got != tt.want {
				t.Errorf("percentile(%v, %.2f) = %d, want %d", tt.data, tt.p, got, tt.want)
			}
		})
	}
}

func TestSizesChangedSignificantly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		oldSizes  []int
		newSizes  []int
		threshold float64
		want      bool
	}{
		{
			name:      "no change",
			oldSizes:  []int{1024, 4096, 16384},
			newSizes:  []int{1024, 4096, 16384},
			threshold: 0.10,
			want:      false,
		},
		{
			name:      "small change within threshold",
			oldSizes:  []int{1024, 4096, 16384},
			newSizes:  []int{1024, 4200, 16384},
			threshold: 0.10,
			want:      false,
		},
		{
			name:      "significant change",
			oldSizes:  []int{1024, 4096, 16384},
			newSizes:  []int{1024, 8192, 16384},
			threshold: 0.10,
			want:      true,
		},
		{
			name:      "different lengths",
			oldSizes:  []int{1024, 4096},
			newSizes:  []int{1024, 4096, 16384},
			threshold: 0.10,
			want:      true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sizesChangedSignificantly(tt.oldSizes, tt.newSizes, tt.threshold)
			if got != tt.want {
				t.Errorf("sizesChangedSignificantly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdaptiveBufferPool_RecordSize(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.HistorySize = 10
	config.AdjustInterval = 1 * time.Hour
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	// Record sizes
	sizes := []int{1024, 2048, 4096, 8192, 16384}
	for _, size := range sizes {
		pool.recordSize(size)
	}
	
	// Check that sizes were recorded
	pool.historyMu.Lock()
	recorded := 0
	for _, size := range pool.sizeHistory {
		if size > 0 {
			recorded++
		}
	}
	pool.historyMu.Unlock()
	
	if recorded != len(sizes) {
		t.Errorf("recorded sizes = %d, want %d", recorded, len(sizes))
	}
}

func TestAdaptiveBufferPool_Shutdown(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 10 * time.Millisecond
	
	pool := NewAdaptiveBufferPool(config)
	
	// Let it run for a bit
	time.Sleep(50 * time.Millisecond)
	
	// Shutdown
	pool.Shutdown()
	
	// Ensure background goroutine stopped
	// If it doesn't stop, test will timeout
}

func TestDefaultAdaptivePool(t *testing.T) {
	// Test initialization
	config := DefaultAdaptiveConfig()
	InitDefaultAdaptivePool(config)
	defer func() {
		if DefaultAdaptivePool != nil {
			DefaultAdaptivePool.Shutdown()
			DefaultAdaptivePool = nil
		}
	}()
	
	// Test GetAdaptive/PutAdaptive
	buf := GetAdaptive(2048)
	if buf == nil {
		t.Fatal("GetAdaptive returned nil")
	}
	if len(*buf) != 2048 {
		t.Errorf("GetAdaptive() length = %d, want 2048", len(*buf))
	}
	
	PutAdaptive(buf)
}

func TestDefaultAdaptivePool_WithoutInit(t *testing.T) {
	// Test fallback to regular pool when DefaultAdaptivePool is nil
	DefaultAdaptivePool = nil
	
	buf := GetAdaptive(2048)
	if buf == nil {
		t.Fatal("GetAdaptive returned nil")
	}
	
	PutAdaptive(buf)
}

// TestAdaptiveBufferPool_BufferClearing verifies that buffers are properly cleared
// when returned to the pool to prevent data leaks
func TestAdaptiveBufferPool_BufferClearing(t *testing.T) {
	t.Parallel()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	// Get a buffer and write sensitive data to it
	buf := pool.Get(1024)
	sensitiveData := "SECRET_PASSWORD_123"
	copy(*buf, sensitiveData)
	
	// Verify data is present
	if string((*buf)[:len(sensitiveData)]) != sensitiveData {
		t.Fatal("Failed to write test data to buffer")
	}
	
	// Return buffer to pool (should be cleared)
	pool.Put(buf)
	
	// Get a new buffer (might be the same one)
	buf2 := pool.Get(1024)
	
	// Verify buffer is zeroed (no data from previous use)
	for i := 0; i < len(sensitiveData); i++ {
		if (*buf2)[i] != 0 {
			t.Errorf("Buffer not properly cleared at index %d: got %v, want 0", i, (*buf2)[i])
		}
	}
	
	pool.Put(buf2)
}

// TestTieredBufferPool_BufferClearing verifies that tiered buffers are also cleared
func TestTieredBufferPool_BufferClearing(t *testing.T) {
	t.Parallel()
	pool := NewTieredBufferPool()
	
	// Get a buffer and write sensitive data
	buf := pool.Get(1024)
	sensitiveData := "API_KEY_XYZ789"
	copy(*buf, sensitiveData)
	
	// Verify data is present
	if string((*buf)[:len(sensitiveData)]) != sensitiveData {
		t.Fatal("Failed to write test data to buffer")
	}
	
	// Return buffer to pool (should be cleared)
	pool.Put(buf)
	
	// Get a new buffer (might be the same one)
	buf2 := pool.Get(1024)
	
	// Verify buffer is zeroed
	for i := 0; i < len(sensitiveData); i++ {
		if (*buf2)[i] != 0 {
			t.Errorf("Buffer not properly cleared at index %d: got %v, want 0", i, (*buf2)[i])
		}
	}
	
	pool.Put(buf2)
}

func BenchmarkTieredBufferPool_Get(b *testing.B) {
	b.ReportAllocs()
	pool := NewTieredBufferPool()
	sizes := []int{1024, 4096, 32768, 512 * 1024}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		size := sizes[i%len(sizes)]
		buf := pool.Get(size)
		pool.Put(buf)
	}
}

func BenchmarkAdaptiveBufferPool_Get(b *testing.B) {
	b.ReportAllocs()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	sizes := []int{1024, 4096, 32768, 512 * 1024}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		size := sizes[i%len(sizes)]
		buf := pool.Get(size)
		pool.Put(buf)
	}
}

func BenchmarkAdaptiveBufferPool_GetParallel(b *testing.B) {
	b.ReportAllocs()
	config := DefaultAdaptiveConfig()
	config.AdjustInterval = 1 * time.Hour
	
	pool := NewAdaptiveBufferPool(config)
	defer pool.Shutdown()
	
	sizes := []int{1024, 4096, 32768, 512 * 1024}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			size := sizes[i%len(sizes)]
			buf := pool.Get(size)
			pool.Put(buf)
			i++
		}
	})
}

