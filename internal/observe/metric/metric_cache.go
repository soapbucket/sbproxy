// metric_cache.go registers Prometheus metrics for cache operations.
package metric

import "github.com/prometheus/client_golang/prometheus"

// Cacher Metrics

var (
	cacherOperationsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cacher_operations_total",
		Help: "Total number of cache operations",
	}, []string{"cacher_type", "operation", "result"}))

	cacherOperationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_cacher_operation_duration_seconds",
		Help:    "Duration of cache operations",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"cacher_type", "operation"}))

	cacherHits = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cacher_hits_total",
		Help: "Total number of cache hits",
	}, []string{"cacher_type"}))

	cacherMisses = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cacher_misses_total",
		Help: "Total number of cache misses",
	}, []string{"cacher_type"}))

	cacherOperationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cacher_operation_errors_total",
		Help: "Total number of cache operation errors",
	}, []string{"cacher_type", "operation", "error_type"}))

	cacherDataSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_cacher_data_size_bytes",
		Help:    "Size of data cached/retrieved",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824}, // 1KB to 1GB
	}, []string{"cacher_type", "operation"}))

	cacherSize = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_cacher_size",
		Help: "Current number of entries in cache",
	}, []string{"cacher_type"}))

	cacherEvictions = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cacher_evictions_total",
		Help: "Total number of cache evictions",
	}, []string{"cacher_type", "reason"}))

	// Performance Cache Metrics
	cacheHitRate = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_cache_hit_rate",
		Help: "Cache hit rate per layer (0-1). Alert when hit rate drops significantly.",
	}, []string{"origin", "cache_layer"}))

	cacheEvictionRate = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cache_evictions_total",
		Help: "Cache evictions by reason. Alert on high eviction rate.",
	}, []string{"origin", "cache_layer", "eviction_reason"}))

	cacheEfficiency = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_cache_efficiency",
		Help: "Overall cache efficiency score (0-1). Alert when efficiency drops.",
	}, []string{"origin", "cache_layer"}))

	cacheInvalidationDuration = mustRegisterHistogram(prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "sb_cache_invalidation_duration_seconds",
		Help:    "Duration of cache invalidation operations.",
		Buckets: prometheus.DefBuckets,
	}))

	// Fingerprint Cacher Metrics
	fingerprintCacheHitRate = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_fingerprint_cache_hit_rate",
		Help: "Fingerprint cache hit rate (prefix cache hits vs misses). Alert when hit rate drops significantly.",
	}, []string{"origin", "content_type"}))

	fingerprintCacheTTFBImprovement = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_fingerprint_cache_ttfb_improvement_seconds",
		Help:    "Time to first byte improvement from cached prefix (difference between cached and uncached).",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	}, []string{"origin", "content_type"}))

	fingerprintCacheOperations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_fingerprint_cache_operations_total",
		Help: "Fingerprint cache operations (get, put, delete). Alert on high error rate.",
	}, []string{"origin", "operation", "result"}))

	chunkCacheOperations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_chunk_cache_operations_total",
		Help: "Chunk cache operations by type (signature/url), operation (get/set/serve), and result (hit/miss/complete).",
	}, []string{"type", "operation", "result"}))

	fingerprintPrefixSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_fingerprint_prefix_size_bytes",
		Help:    "Distribution of cached prefix sizes. Alert on unusually large prefixes.",
		Buckets: []float64{1024, 2048, 4096, 8192, 16384, 32768, 65536},
	}, []string{"origin", "content_type"}))

	fingerprintSignatureMatches = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_fingerprint_signature_matches_total",
		Help: "Signature pattern matches (matched vs not matched). Alert when match rate drops significantly.",
	}, []string{"origin", "signature_type", "matched"}))

	fingerprintStreamMergeLatency = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_fingerprint_stream_merge_latency_seconds",
		Help:    "Time to merge cached prefix with live response stream. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
	}, []string{"origin"}))

	// DNS Cache Metrics
	dnsCacheHits = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_dns_cache_hits_total",
		Help: "Total number of DNS cache hits",
	}))

	dnsCacheMisses = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_dns_cache_misses_total",
		Help: "Total number of DNS cache misses",
	}))

	dnsCacheSize = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sb_dns_cache_size",
		Help: "Current number of entries in the DNS cache",
	}))
)

// Cacher Metric Functions

// CacherOperation records a cache operation with result and duration
func CacherOperation(cacherType, operation, result string, duration float64) {
	cacherOperationsTotal.WithLabelValues(cacherType, operation, result).Inc()
	cacherOperationDuration.WithLabelValues(cacherType, operation).Observe(duration)
}

// CacherHit records a cache hit
func CacherHit(cacherType string) {
	cacherHits.WithLabelValues(cacherType).Inc()
}

// CacherMiss records a cache miss
func CacherMiss(cacherType string) {
	cacherMisses.WithLabelValues(cacherType).Inc()
}

// CacherOperationError records a cache operation error
func CacherOperationError(cacherType, operation, errorType string) {
	cacherOperationErrors.WithLabelValues(cacherType, operation, errorType).Inc()
}

// CacherDataSize records the size of data in a cache operation
func CacherDataSize(cacherType, operation string, size int64) {
	cacherDataSize.WithLabelValues(cacherType, operation).Observe(float64(size))
}

// CacherSizeSet sets the current number of entries in cache
func CacherSizeSet(cacherType string, size int64) {
	cacherSize.WithLabelValues(cacherType).Set(float64(size))
}

// CacherEviction records a cache eviction
func CacherEviction(cacherType, reason string) {
	cacherEvictions.WithLabelValues(cacherType, reason).Inc()
}

// CacheHitRateSet sets the cache hit rate
func CacheHitRateSet(origin, cacheLayer string, rate float64) {
	cacheHitRate.WithLabelValues(origin, cacheLayer).Set(rate)
}

// CacheEviction records a cache eviction
func CacheEviction(origin, cacheLayer, evictionReason string) {
	cacheEvictionRate.WithLabelValues(origin, cacheLayer, evictionReason).Inc()
}

// CacheEfficiencySet sets cache efficiency score
func CacheEfficiencySet(origin, cacheLayer string, efficiency float64) {
	cacheEfficiency.WithLabelValues(origin, cacheLayer).Set(efficiency)
}

// CacheInvalidationDuration records cache invalidation latency.
func CacheInvalidationDuration(duration float64) {
	cacheInvalidationDuration.Observe(duration)
}

// Fingerprint Cacher Metric Functions

// FingerprintCacheHitRateSet sets the fingerprint cache hit rate
func FingerprintCacheHitRateSet(origin, contentType string, rate float64) {
	fingerprintCacheHitRate.WithLabelValues(origin, contentType).Set(rate)
}

// FingerprintCacheTTFBImprovement records TTFB improvement from cached prefix
func FingerprintCacheTTFBImprovement(origin, contentType string, improvement float64) {
	fingerprintCacheTTFBImprovement.WithLabelValues(origin, contentType).Observe(improvement)
}

// FingerprintCacheOperation records a fingerprint cache operation
func FingerprintCacheOperation(origin, operation, result string) {
	fingerprintCacheOperations.WithLabelValues(origin, operation, result).Inc()
}

// ChunkCacheOperation records a chunk cache operation.
// cacheType is "signature" or "url", operation is "get", "set", or "serve",
// and result is "hit", "miss", or "complete".
func ChunkCacheOperation(cacheType, operation, result string) {
	chunkCacheOperations.WithLabelValues(cacheType, operation, result).Inc()
}

// FingerprintPrefixSize records cached prefix size
func FingerprintPrefixSize(origin, contentType string, size int64) {
	fingerprintPrefixSize.WithLabelValues(origin, contentType).Observe(float64(size))
}

// FingerprintSignatureMatch records a signature match result
func FingerprintSignatureMatch(origin, signatureType string, matched bool) {
	matchedStr := "false"
	if matched {
		matchedStr = "true"
	}
	fingerprintSignatureMatches.WithLabelValues(origin, signatureType, matchedStr).Inc()
}

// FingerprintStreamMergeLatency records stream merge latency
func FingerprintStreamMergeLatency(origin string, duration float64) {
	fingerprintStreamMergeLatency.WithLabelValues(origin).Observe(duration)
}

// DNS Cache Metric Functions

// DNSCacheHit records a DNS cache hit
func DNSCacheHit() {
	dnsCacheHits.Inc()
}

// DNSCacheMiss records a DNS cache miss
func DNSCacheMiss() {
	dnsCacheMisses.Inc()
}

// DNSCacheSizeSet sets the current DNS cache size
func DNSCacheSizeSet(size int) {
	dnsCacheSize.Set(float64(size))
}
