// Package bufferpool provides a sync.Pool-based buffer recycling mechanism to reduce GC pressure.
package bufferpool

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ---- bytes.Buffer pool (for io.Writer callers) ----
//
// These complement the raw []byte tiered pools above. Use GetBuffer/PutBuffer
// when you need an io.Writer-compatible buffer (e.g., json.NewEncoder,
// template.Execute, http.ResponseWriter capture). Use Get/Put when you need
// a fixed-size byte slice for sized reads or copies.

var (
	smallBufPool  = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 512)) }}
	mediumBufPool = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) }}
	largeBufPool  = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 32768)) }}
)

// GetBuffer returns a reset *bytes.Buffer from the pool, selecting the
// smallest tier whose capacity is >= sizeHint. Pass 0 for a small (512 B)
// buffer. The returned buffer is empty (Reset has been called).
func GetBuffer(sizeHint int) *bytes.Buffer {
	var b *bytes.Buffer
	switch {
	case sizeHint <= 512:
		b = smallBufPool.Get().(*bytes.Buffer)
	case sizeHint <= 4096:
		b = mediumBufPool.Get().(*bytes.Buffer)
	default:
		b = largeBufPool.Get().(*bytes.Buffer)
	}
	b.Reset()
	return b
}

// PutBuffer returns a *bytes.Buffer to the appropriate pool tier.
// Buffers whose capacity exceeds MaxPoolBufferSize are discarded to prevent
// unbounded pool growth. Nil buffers are silently ignored.
func PutBuffer(b *bytes.Buffer) {
	if b == nil {
		return
	}
	c := b.Cap()
	if c > MaxPoolBufferSize {
		// Let GC reclaim oversized buffers.
		return
	}
	switch {
	case c <= 512:
		smallBufPool.Put(b)
	case c <= 4096:
		mediumBufPool.Put(b)
	default:
		largeBufPool.Put(b)
	}
}

var (
	// Metrics for buffer pool monitoring
	bufferPoolGets = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_bufferpool_gets_total",
		Help: "Total number of buffer gets per size tier",
	}, []string{"tier"})

	bufferPoolPuts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_bufferpool_puts_total",
		Help: "Total number of buffer puts per size tier",
	}, []string{"tier"})

	bufferSizeRequested = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "sb_bufferpool_size_requested_bytes",
		Help: "Distribution of requested buffer sizes",
		Buckets: []float64{
			1024,      // 1KB
			4096,      // 4KB
			16384,     // 16KB
			65536,     // 64KB
			262144,    // 256KB
			1048576,   // 1MB
			4194304,   // 4MB
			10485760,  // 10MB
		},
	})

	bufferPoolAllocations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_bufferpool_allocations_total",
		Help: "Total number of new buffer allocations (pool miss)",
	}, []string{"tier"})

	bufferPoolTierSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_bufferpool_tier_size_bytes",
		Help: "Current size of each buffer pool tier",
	}, []string{"tier"})

	bufferPoolTierUtilization = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_bufferpool_tier_utilization_percent",
		Help: "Utilization percentage of each buffer pool tier",
	}, []string{"tier"})
)

// TieredBufferPool provides multiple buffer pools for different size ranges
type TieredBufferPool struct {
	small  *sync.Pool // 0-4KB
	medium *sync.Pool // 4KB-64KB
	large  *sync.Pool // 64KB-1MB
	xlarge *sync.Pool // 1MB+
	
	// Metrics
	smallGets  int64
	mediumGets int64
	largeGets  int64
	xlargeGets int64
}

const (
	// SmallSize is a constant for small size.
	SmallSize  = 4 * 1024      // 4KB
	// MediumSize is a constant for medium size.
	MediumSize = 64 * 1024     // 64KB
	// LargeSize is a constant for large size.
	LargeSize  = 1024 * 1024   // 1MB
	// XLargeSize is a constant for x large size.
	XLargeSize = 10 * 1024 * 1024 // 10MB
)

// DefaultPool is the global default tiered buffer pool
var DefaultPool = NewTieredBufferPool()

// NewTieredBufferPool creates a new tiered buffer pool
func NewTieredBufferPool() *TieredBufferPool {
	return &TieredBufferPool{
		small: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, SmallSize)
				return &buf
			},
		},
		medium: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, MediumSize)
				return &buf
			},
		},
		large: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, LargeSize)
				return &buf
			},
		},
		xlarge: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, XLargeSize)
				return &buf
			},
		},
	}
}

// Get returns a buffer of appropriate size from the pool
func (p *TieredBufferPool) Get(size int) *[]byte {
	switch {
	case size <= SmallSize:
		atomic.AddInt64(&p.smallGets, 1)
		return p.small.Get().(*[]byte)
	case size <= MediumSize:
		atomic.AddInt64(&p.mediumGets, 1)
		return p.medium.Get().(*[]byte)
	case size <= LargeSize:
		atomic.AddInt64(&p.largeGets, 1)
		return p.large.Get().(*[]byte)
	default:
		atomic.AddInt64(&p.xlargeGets, 1)
		return p.xlarge.Get().(*[]byte)
	}
}

// Put returns a buffer to the appropriate pool
func (p *TieredBufferPool) Put(buf *[]byte) {
	if buf == nil {
		return
	}
	
	size := cap(*buf)
	
	// Reset buffer to full capacity and zero contents
	*buf = (*buf)[:cap(*buf)]
	clear(*buf)

	switch {
	case size <= SmallSize:
		p.small.Put(buf)
	case size <= MediumSize:
		p.medium.Put(buf)
	case size <= LargeSize:
		p.large.Put(buf)
	case size <= XLargeSize:
		p.xlarge.Put(buf)
	// Don't pool buffers larger than XLarge
	}
}

// Stats returns buffer pool statistics
func (p *TieredBufferPool) Stats() BufferPoolStats {
	return BufferPoolStats{
		SmallGets:  atomic.LoadInt64(&p.smallGets),
		MediumGets: atomic.LoadInt64(&p.mediumGets),
		LargeGets:  atomic.LoadInt64(&p.largeGets),
		XLargeGets: atomic.LoadInt64(&p.xlargeGets),
	}
}

// BufferPoolStats contains buffer pool statistics
type BufferPoolStats struct {
	SmallGets  int64
	MediumGets int64
	LargeGets  int64
	XLargeGets int64
}

// Total returns the total number of gets across all tiers
func (s BufferPoolStats) Total() int64 {
	return s.SmallGets + s.MediumGets + s.LargeGets + s.XLargeGets
}

// Helper functions for convenience
func Get(size int) *[]byte {
	return DefaultPool.Get(size)
}

// Put performs the put operation.
func Put(buf *[]byte) {
	DefaultPool.Put(buf)
}

// Stats performs the stats operation.
func Stats() BufferPoolStats {
	return DefaultPool.Stats()
}

// ===== Adaptive Buffer Pool Implementation =====

// BufferTier represents a single tier in the adaptive buffer pool
type BufferTier struct {
	size      int
	pool      *sync.Pool
	gets      int64
	puts      int64
	allocates int64 // Track new allocations (pool misses)
	name      string
}

// AdaptiveBufferPool dynamically adjusts buffer sizes based on usage patterns
type AdaptiveBufferPool struct {
	mu          sync.RWMutex
	tiers       []*BufferTier
	sizeHistory []atomic.Int64 // Lock-free ring buffer for size history
	historySize int
	historyIdx  atomic.Int64 // Atomic index for lock-free writes
	sampleCount atomic.Int64 // Counter for sampling (record every 16th call)

	// Configuration
	adjustInterval time.Duration
	targetCoverage float64 // Target percentage of requests covered by optimal tier (default: 0.90)
	minTiers       int
	maxTiers       int

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// AdaptiveBufferPoolConfig configures the adaptive buffer pool
type AdaptiveBufferPoolConfig struct {
	// Initial tier sizes (optional, uses defaults if nil)
	InitialSizes []int
	
	// Adjustment interval (default: 5 minutes)
	AdjustInterval time.Duration
	
	// Target coverage: percentage of requests that should use optimal tier (default: 0.90)
	TargetCoverage float64
	
	// Size history to keep for analysis (default: 10000)
	HistorySize int
	
	// Min/max number of tiers (defaults: 3-8)
	MinTiers int
	MaxTiers int
}

// DefaultAdaptiveConfig returns default configuration
func DefaultAdaptiveConfig() AdaptiveBufferPoolConfig {
	return AdaptiveBufferPoolConfig{
		InitialSizes: []int{
			4 * 1024,      // 4KB
			64 * 1024,     // 64KB
			1024 * 1024,   // 1MB
			10 * 1024 * 1024, // 10MB
		},
		AdjustInterval: 5 * time.Minute,
		TargetCoverage: 0.90,
		HistorySize:    10000,
		MinTiers:       3,
		MaxTiers:       8,
	}
}

// NewAdaptiveBufferPool creates a new adaptive buffer pool
func NewAdaptiveBufferPool(config AdaptiveBufferPoolConfig) *AdaptiveBufferPool {
	// Apply defaults
	if config.AdjustInterval == 0 {
		config.AdjustInterval = 5 * time.Minute
	}
	if config.TargetCoverage == 0 {
		config.TargetCoverage = 0.90
	}
	if config.HistorySize == 0 {
		config.HistorySize = 10000
	}
	if config.MinTiers == 0 {
		config.MinTiers = 3
	}
	if config.MaxTiers == 0 {
		config.MaxTiers = 8
	}
	if config.InitialSizes == nil {
		config.InitialSizes = DefaultAdaptiveConfig().InitialSizes
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &AdaptiveBufferPool{
		tiers:          make([]*BufferTier, 0, len(config.InitialSizes)),
		sizeHistory:    make([]atomic.Int64, config.HistorySize),
		historySize:    config.HistorySize,
		adjustInterval: config.AdjustInterval,
		targetCoverage: config.TargetCoverage,
		minTiers:       config.MinTiers,
		maxTiers:       config.MaxTiers,
		ctx:            ctx,
		cancel:         cancel,
	}
	
	// Initialize tiers
	for i, size := range config.InitialSizes {
		tier := pool.createTier(size, getTierName(i))
		pool.tiers = append(pool.tiers, tier)
		
		// Update metrics
		bufferPoolTierSize.WithLabelValues(tier.name).Set(float64(size))
	}
	
	// Start background adjustment goroutine
	pool.wg.Add(1)
	go pool.adjustSizesPeriodically()
	
	return pool
}

// createTier creates a new buffer tier
func (p *AdaptiveBufferPool) createTier(size int, name string) *BufferTier {
	tier := &BufferTier{
		size: size,
		name: name,
	}
	
	// Create pool with closure capturing tier pointer
	tier.pool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, size)
			atomic.AddInt64(&tier.allocates, 1)
			bufferPoolAllocations.WithLabelValues(name).Inc()
			return &buf
		},
	}
	
	return tier
}

// Get returns a buffer of appropriate size from the pool
func (p *AdaptiveBufferPool) Get(size int) *[]byte {
	// Record size for histogram analysis
	bufferSizeRequested.Observe(float64(size))
	
	// Track size history for adjustment
	p.recordSize(size)
	
	// Find appropriate tier (read lock for performance)
	p.mu.RLock()
	tier := p.findTier(size)
	p.mu.RUnlock()
	
	if tier == nil {
		// No suitable tier found, allocate directly
		buf := make([]byte, size)
		return &buf
	}
	
	// Get from pool
	atomic.AddInt64(&tier.gets, 1)
	bufferPoolGets.WithLabelValues(tier.name).Inc()
	
	buf := tier.pool.Get().(*[]byte)
	*buf = (*buf)[:size] // Resize to requested size
	return buf
}

// Put returns a buffer to the appropriate pool
func (p *AdaptiveBufferPool) Put(buf *[]byte) {
	if buf == nil {
		return
	}
	
	size := cap(*buf)
	
	// Find appropriate tier
	p.mu.RLock()
	tier := p.findTierExact(size)
	p.mu.RUnlock()
	
	if tier == nil {
		// Don't pool buffers that don't match our tiers
		return
	}
	
	// Reset buffer to full capacity and zero contents
	*buf = (*buf)[:cap(*buf)]
	clear(*buf)
	
	atomic.AddInt64(&tier.puts, 1)
	bufferPoolPuts.WithLabelValues(tier.name).Inc()
	tier.pool.Put(buf)
}

// findTier finds the smallest tier that can accommodate the requested size
func (p *AdaptiveBufferPool) findTier(size int) *BufferTier {
	for _, tier := range p.tiers {
		if tier.size >= size {
			return tier
		}
	}
	return nil
}

// findTierExact finds the tier that exactly matches the capacity
func (p *AdaptiveBufferPool) findTierExact(capacity int) *BufferTier {
	for _, tier := range p.tiers {
		if tier.size == capacity {
			return tier
		}
	}
	return nil
}

// recordSize records a requested size for future analysis.
// Only samples every 16th call to reduce contention, using atomic operations
// instead of a mutex for lock-free writes to the ring buffer.
func (p *AdaptiveBufferPool) recordSize(size int) {
	// Sample 1 in 16 calls to reduce overhead
	if p.sampleCount.Add(1)%16 != 0 {
		return
	}
	idx := p.historyIdx.Add(1) - 1
	p.sizeHistory[idx%int64(p.historySize)].Store(int64(size))
}

// adjustSizesPeriodically runs periodic size adjustment
func (p *AdaptiveBufferPool) adjustSizesPeriodically() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(p.adjustInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.AdjustSizes()
		}
	}
}

// AdjustSizes analyzes usage patterns and adjusts buffer tier sizes
func (p *AdaptiveBufferPool) AdjustSizes() {
	// Snapshot atomic ring buffer (no lock needed)
	var sizes []int
	for i := 0; i < p.historySize; i++ {
		v := p.sizeHistory[i].Load()
		if v > 0 {
			sizes = append(sizes, int(v))
		}
	}
	
	if len(sizes) < 100 {
		// Not enough data for adjustment
		return
	}
	
	// Sort sizes for percentile calculation
	sort.Ints(sizes)
	
	// Calculate percentiles
	p50 := percentile(sizes, 0.50)
	p75 := percentile(sizes, 0.75)
	p90 := percentile(sizes, 0.90)
	p95 := percentile(sizes, 0.95)
	p99 := percentile(sizes, 0.99)
	
	// Determine optimal tier sizes based on percentiles
	newSizes := []int{}
	
	// Always include key percentiles
	if p50 > 0 {
		newSizes = append(newSizes, p50)
	}
	if p75 > p50*2 { // Only add if significantly different
		newSizes = append(newSizes, p75)
	}
	if p90 > p75*2 {
		newSizes = append(newSizes, p90)
	}
	if p95 > p90*2 {
		newSizes = append(newSizes, p95)
	}
	if p99 > p95*2 {
		newSizes = append(newSizes, p99)
	}
	
	// Ensure we have minimum tiers
	if len(newSizes) < p.minTiers {
		// Keep existing sizes if not enough distinct percentiles
		return
	}
	
	// Cap at maximum tiers
	if len(newSizes) > p.maxTiers {
		newSizes = newSizes[:p.maxTiers]
	}
	
	// Check if sizes changed significantly (>10%)
	p.mu.RLock()
	currentSizes := make([]int, len(p.tiers))
	for i, tier := range p.tiers {
		currentSizes[i] = tier.size
	}
	p.mu.RUnlock()
	
	if !sizesChangedSignificantly(currentSizes, newSizes, 0.10) {
		// No significant change, keep current tiers
		return
	}
	
	// Update tiers with write lock
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Create new tiers
	newTiers := make([]*BufferTier, 0, len(newSizes))
	for i, size := range newSizes {
		// Try to reuse existing tier if size matches
		var tier *BufferTier
		for _, existingTier := range p.tiers {
			if existingTier.size == size {
				tier = existingTier
				break
			}
		}
		
		if tier == nil {
			// Create new tier
			tier = p.createTier(size, getTierName(i))
		} else {
			// Update tier name
			tier.name = getTierName(i)
		}
		
		newTiers = append(newTiers, tier)
		
		// Update metrics
		bufferPoolTierSize.WithLabelValues(tier.name).Set(float64(size))
	}
	
	p.tiers = newTiers
}

// Stats returns statistics about the buffer pool
func (p *AdaptiveBufferPool) Stats() AdaptiveBufferPoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	stats := AdaptiveBufferPoolStats{
		TierCount: len(p.tiers),
		Tiers:     make([]TierStats, 0, len(p.tiers)),
	}
	
	for _, tier := range p.tiers {
		gets := atomic.LoadInt64(&tier.gets)
		puts := atomic.LoadInt64(&tier.puts)
		allocs := atomic.LoadInt64(&tier.allocates)
		
		var utilization float64
		if gets > 0 {
			utilization = float64(puts) / float64(gets) * 100
		}
		
		tierStats := TierStats{
			Name:         tier.name,
			Size:         tier.size,
			Gets:         gets,
			Puts:         puts,
			Allocations:  allocs,
			Utilization:  utilization,
		}
		
		stats.Tiers = append(stats.Tiers, tierStats)
		stats.TotalGets += gets
		stats.TotalPuts += puts
		stats.TotalAllocations += allocs
		
		// Update utilization metric
		bufferPoolTierUtilization.WithLabelValues(tier.name).Set(utilization)
	}
	
	return stats
}

// Shutdown stops the adaptive buffer pool
func (p *AdaptiveBufferPool) Shutdown() {
	p.cancel()
	p.wg.Wait()
}

// AdaptiveBufferPoolStats contains statistics about the adaptive buffer pool
type AdaptiveBufferPoolStats struct {
	TierCount         int
	Tiers             []TierStats
	TotalGets         int64
	TotalPuts         int64
	TotalAllocations  int64
}

// TierStats contains statistics for a single tier
type TierStats struct {
	Name         string
	Size         int
	Gets         int64
	Puts         int64
	Allocations  int64
	Utilization  float64 // Percentage
}

// Helper functions

// percentile calculates the percentile value from sorted data
func percentile(sortedData []int, p float64) int {
	if len(sortedData) == 0 {
		return 0
	}
	
	index := int(float64(len(sortedData)-1) * p)
	if index < 0 {
		index = 0
	}
	if index >= len(sortedData) {
		index = len(sortedData) - 1
	}
	
	return sortedData[index]
}

// sizesChangedSignificantly checks if new sizes differ significantly from old sizes
func sizesChangedSignificantly(oldSizes, newSizes []int, threshold float64) bool {
	if len(oldSizes) != len(newSizes) {
		return true
	}
	
	for i := range oldSizes {
		diff := float64(abs(newSizes[i]-oldSizes[i])) / float64(oldSizes[i])
		if diff > threshold {
			return true
		}
	}
	
	return false
}

// abs returns absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// getTierName returns a name for a tier based on its index
func getTierName(index int) string {
	names := []string{"tier_0", "tier_1", "tier_2", "tier_3", "tier_4", "tier_5", "tier_6", "tier_7"}
	if index < len(names) {
		return names[index]
	}
	return "tier_unknown"
}

// PreWarm pre-allocates buffers for each tier to avoid cold-start allocation costs.
func (p *TieredBufferPool) PreWarm(count int) {
	for i := 0; i < count; i++ {
		buf := make([]byte, SmallSize)
		p.small.Put(&buf)
	}
	for i := 0; i < count; i++ {
		buf := make([]byte, MediumSize)
		p.medium.Put(&buf)
	}
	for i := 0; i < count; i++ {
		buf := make([]byte, LargeSize)
		p.large.Put(&buf)
	}
}

func init() {
	DefaultPool.PreWarm(16)
}

// Global adaptive pool (optional, for easy migration)
var DefaultAdaptivePool *AdaptiveBufferPool

// InitDefaultAdaptivePool initializes the global adaptive pool
func InitDefaultAdaptivePool(config AdaptiveBufferPoolConfig) {
	DefaultAdaptivePool = NewAdaptiveBufferPool(config)
}

// GetAdaptive returns a buffer from the default adaptive pool
func GetAdaptive(size int) *[]byte {
	if DefaultAdaptivePool == nil {
		// Fallback to regular pool
		return DefaultPool.Get(size)
	}
	return DefaultAdaptivePool.Get(size)
}

// PutAdaptive returns a buffer to the default adaptive pool
func PutAdaptive(buf *[]byte) {
	if DefaultAdaptivePool == nil {
		// Fallback to regular pool
		DefaultPool.Put(buf)
		return
	}
	DefaultAdaptivePool.Put(buf)
}

