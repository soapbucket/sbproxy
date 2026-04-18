// metric_origin.go registers per-origin Prometheus metrics for tracking
// request volume, latency, caching, authentication, policy enforcement,
// bandwidth, connections, and circuit breaker state per origin hostname.
package metric

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// --- Per-Origin Metrics (P1.1) ---

var (
	// 1.1.1 Request counters by origin
	OriginRequestsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_requests_total",
		Help: "Total requests per origin hostname, method, and status code",
	}, []string{"hostname", "method", "status_code"}))

	// 1.1.2 Latency histograms by origin
	OriginDurationSeconds = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sbproxy_origin_duration_seconds",
		Help:    "Request duration per origin hostname and method",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"hostname", "method"}))

	// 1.1.4 Cache hit/miss ratio by origin
	OriginCacheHits = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_cache_hits_total",
		Help: "Total cache hits per origin hostname",
	}, []string{"hostname"}))

	OriginCacheMisses = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_cache_misses_total",
		Help: "Total cache misses per origin hostname",
	}, []string{"hostname"}))

	// 1.1.5 Auth success/failure by origin and type
	OriginAuthTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_auth_total",
		Help: "Total auth attempts per origin hostname, auth type, and result",
	}, []string{"hostname", "auth_type", "result"}))

	// 1.1.6 Policy triggers by origin and type
	OriginPolicyTriggersTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_policy_triggers_total",
		Help: "Total policy triggers per origin hostname, policy type, and action",
	}, []string{"hostname", "policy_type", "action"}))

	// 1.1.7 Bytes in/out by origin
	OriginBytesIn = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_bytes_in_total",
		Help: "Total inbound bytes per origin hostname",
	}, []string{"hostname"}))

	OriginBytesOut = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_bytes_out_total",
		Help: "Total outbound bytes per origin hostname",
	}, []string{"hostname"}))

	// 1.1.8 Active connections by origin
	OriginActiveConnections = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sbproxy_origin_active_connections",
		Help: "Current active connections per origin hostname",
	}, []string{"hostname"}))

	// 1.1.10 Circuit breaker transitions by origin
	OriginCircuitBreakerTransitions = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_origin_circuit_breaker_transitions_total",
		Help: "Total circuit breaker state transitions per origin hostname",
	}, []string{"hostname", "from_state", "to_state"}))
)

// RecordOriginRequest records a completed request for an origin.
func RecordOriginRequest(hostname, method string, statusCode int, duration float64, bytesIn, bytesOut int64) {
	statusStr := strconv.Itoa(statusCode)
	OriginRequestsTotal.WithLabelValues(hostname, method, statusStr).Inc()
	OriginDurationSeconds.WithLabelValues(hostname, method).Observe(duration)
	if bytesIn > 0 {
		OriginBytesIn.WithLabelValues(hostname).Add(float64(bytesIn))
	}
	if bytesOut > 0 {
		OriginBytesOut.WithLabelValues(hostname).Add(float64(bytesOut))
	}
}

// RecordOriginCacheHit records a cache hit for an origin.
func RecordOriginCacheHit(hostname string) {
	OriginCacheHits.WithLabelValues(hostname).Inc()
}

// RecordOriginCacheMiss records a cache miss for an origin.
func RecordOriginCacheMiss(hostname string) {
	OriginCacheMisses.WithLabelValues(hostname).Inc()
}

// RecordOriginAuth records an auth attempt for an origin.
func RecordOriginAuth(hostname, authType string, success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	OriginAuthTotal.WithLabelValues(hostname, authType, result).Inc()
}

// RecordOriginPolicyTrigger records a policy trigger for an origin.
func RecordOriginPolicyTrigger(hostname, policyType, action string) {
	OriginPolicyTriggersTotal.WithLabelValues(hostname, policyType, action).Inc()
}

// RecordOriginCircuitBreaker records a circuit breaker state transition.
func RecordOriginCircuitBreaker(hostname, fromState, toState string) {
	OriginCircuitBreakerTransitions.WithLabelValues(hostname, fromState, toState).Inc()
}

// OriginActiveConnectionInc increments the active connection count for an origin.
func OriginActiveConnectionInc(hostname string) {
	OriginActiveConnections.WithLabelValues(hostname).Inc()
}

// OriginActiveConnectionDec decrements the active connection count for an origin.
func OriginActiveConnectionDec(hostname string) {
	OriginActiveConnections.WithLabelValues(hostname).Dec()
}
