// Package metric collects and exposes Prometheus metrics for proxy performance monitoring.
package metric

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Billing metrics for request/bytes tracking per origin
var (
	// BillingRequestsTotal - total requests by origin, workspace, status
	BillingRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_requests_total",
			Help: "Total requests processed by origin for billing",
		},
		[]string{"workspace_id", "origin_id", "origin_hostname", "status"},
	)

	// BillingBytesInTotal - total bytes received from clients
	BillingBytesInTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_bytes_in_total",
			Help: "Total bytes received from clients (request size)",
		},
		[]string{"workspace_id", "origin_id", "origin_hostname"},
	)

	// BillingBytesOutTotal - total bytes sent to clients
	BillingBytesOutTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_bytes_out_total",
			Help: "Total bytes sent to clients (response size)",
		},
		[]string{"workspace_id", "origin_id", "origin_hostname"},
	)

	// BillingBytesBackendTotal - total bytes to/from backends
	BillingBytesBackendTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_bytes_backend_total",
			Help: "Total bytes exchanged with backends",
		},
		[]string{"workspace_id", "origin_id", "origin_hostname"},
	)

	// BillingErrorsTotal - total errors by origin
	BillingErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_errors_total",
			Help: "Total errors by origin for billing audit",
		},
		[]string{"workspace_id", "origin_id", "origin_hostname", "error_type"},
	)

	// BillingLatencyHistogram - request latency by origin
	BillingLatencyHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "sb_billing_request_duration_seconds",
			Help: "Request duration for billing audit",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0},
		},
		[]string{"workspace_id", "origin_id", "origin_hostname"},
	)

	// TokensTotal - total tokens for AI providers
	BillingTokensTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_tokens_total",
			Help: "Total tokens used for AI provider billing",
		},
		[]string{"workspace_id", "origin_id", "provider_name"},
	)

	// CacheBytesTotal - total bytes served from cache (no backend cost)
	BillingCacheBytesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sb_billing_cache_bytes_total",
			Help: "Total bytes served from cache (no backend billing)",
		},
		[]string{"workspace_id", "origin_id", "origin_hostname"},
	)
)

// RecordBillingMetrics records a request for billing purposes
func RecordBillingMetrics(workspaceID, originID, originHostname string, status string,
	bytesIn, bytesOut, bytesBackend int64, fromCache bool) {

	BillingRequestsTotal.WithLabelValues(workspaceID, originID, originHostname, status).Inc()
	BillingBytesInTotal.WithLabelValues(workspaceID, originID, originHostname).Add(float64(bytesIn))
	BillingBytesOutTotal.WithLabelValues(workspaceID, originID, originHostname).Add(float64(bytesOut))

	if !fromCache {
		BillingBytesBackendTotal.WithLabelValues(workspaceID, originID, originHostname).Add(float64(bytesBackend))
	} else {
		BillingCacheBytesTotal.WithLabelValues(workspaceID, originID, originHostname).Add(float64(bytesOut))
	}
}

// RecordBillingError records an error for billing audit
func RecordBillingError(workspaceID, originID, originHostname, errorType string) {
	BillingErrorsTotal.WithLabelValues(workspaceID, originID, originHostname, errorType).Inc()
}

// RecordBillingLatency records request latency
func RecordBillingLatency(workspaceID, originID, originHostname string, latencySeconds float64) {
	BillingLatencyHistogram.WithLabelValues(workspaceID, originID, originHostname).Observe(latencySeconds)
}

// RecordTokenUsage records AI provider token usage
func RecordTokenUsage(workspaceID, originID, providerName string, tokens int64) {
	BillingTokensTotal.WithLabelValues(workspaceID, originID, providerName).Add(float64(tokens))
}
