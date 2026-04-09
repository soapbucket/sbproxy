// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsCollector collects metrics for HTTPS proxy activity
type MetricsCollector struct {
	// Counter metrics
	tunnelEstablishedTotal  prometheus.Counter
	tunnelFailedTotal       prometheus.Counter
	aiProviderDetectedTotal prometheus.Counter
	aiProviderBypassedTotal prometheus.Counter
	authSuccessTotal        prometheus.Counter
	authFailureTotal        prometheus.Counter
	targetManagedTotal      prometheus.Counter
	targetUnmanagedTotal    prometheus.Counter
	destinationBlockedTotal prometheus.Counter
	privateDeniedTotal      prometheus.Counter
	certCacheHitTotal       prometheus.Counter
	certCacheMissTotal      prometheus.Counter

	// Histogram metrics
	tunnelDurationSeconds prometheus.Histogram
	dataTransferredBytes  prometheus.Histogram

	// Gauge metrics
	activeTunnels prometheus.Gauge

	// Tunnel-type-labeled metrics for connect-tcp, connect-udp, connect-ip
	tunnelTypeEstablished *prometheus.CounterVec
	tunnelTypeFailed      *prometheus.CounterVec
	tunnelTypeDuration    *prometheus.HistogramVec
	tunnelTypeBytes       *prometheus.HistogramVec
	tunnelTypeActive      *prometheus.GaugeVec

	// ACL enforcement metrics
	aclAllowedTotal *prometheus.CounterVec
	aclDeniedTotal  *prometheus.CounterVec

	// Managed tunnel pipeline metrics (hostname-labeled)
	managedTunnelEstablished *prometheus.CounterVec
	managedTunnelDuration    *prometheus.HistogramVec
	managedTunnelBytesSent   *prometheus.CounterVec
	managedTunnelBytesRecv   *prometheus.CounterVec
	managedTunnelRequests    *prometheus.CounterVec

	// Per-provider metrics
	providerMetrics map[string]*ProviderMetrics
	providerMutex   sync.RWMutex
	registerOnce    sync.Once
}

// ProviderMetrics tracks metrics for a specific AI provider
type ProviderMetrics struct {
	RequestsTotal    prometheus.Counter
	ErrorsTotal      prometheus.Counter
	BytesSent        prometheus.Counter
	BytesReceived    prometheus.Counter
	CostEstimated    prometheus.Counter
	LatencyHistogram prometheus.Histogram
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(subsystem string) *MetricsCollector {
	if subsystem == "" {
		subsystem = "https_proxy"
	}

	mc := &MetricsCollector{
		tunnelEstablishedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "tunnel_established_total",
			Help:      "Total number of successfully established HTTPS tunnels",
		}),
		tunnelFailedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "tunnel_failed_total",
			Help:      "Total number of failed HTTPS tunnel attempts",
		}),
		aiProviderDetectedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "ai_provider_detected_total",
			Help:      "Total number of detected AI provider connections",
		}),
		aiProviderBypassedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "ai_provider_bypassed_total",
			Help:      "Total number of AI providers routed through proxy origin",
		}),
		authSuccessTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "auth_success_total",
			Help:      "Total number of successful proxy authentications",
		}),
		authFailureTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "auth_failure_total",
			Help:      "Total number of failed proxy authentications",
		}),
		targetManagedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "target_managed_total",
			Help:      "Total number of CONNECT targets resolved to managed SoapBucket configs",
		}),
		targetUnmanagedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "target_unmanaged_total",
			Help:      "Total number of CONNECT targets routed as unmanaged passthrough",
		}),
		destinationBlockedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "destination_blocked_total",
			Help:      "Total number of blocked CONNECT destinations",
		}),
		privateDeniedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "destination_private_denied_total",
			Help:      "Total number of private or unsafe CONNECT destinations denied",
		}),
		certCacheHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "certificate_cache_hit_total",
			Help:      "Total number of MITM certificate cache hits",
		}),
		certCacheMissTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "certificate_cache_miss_total",
			Help:      "Total number of MITM certificate cache misses",
		}),
		tunnelDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "tunnel_duration_seconds",
			Help:      "Tunnel connection duration in seconds",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 300},
		}),
		dataTransferredBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "data_transferred_bytes",
			Help:      "Amount of data transferred through tunnel in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1e6, 10e6, 100e6},
		}),
		activeTunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "active_tunnels",
			Help:      "Current number of active HTTPS tunnels",
		}),
		tunnelTypeEstablished: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "tunnel_type_established_total",
			Help:      "Total tunnels established by tunnel type (connect-tcp, connect-udp, connect-ip)",
		}, []string{"tunnel_type"}),
		tunnelTypeFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "tunnel_type_failed_total",
			Help:      "Total tunnels failed by tunnel type",
		}, []string{"tunnel_type", "reason"}),
		tunnelTypeDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "tunnel_type_duration_seconds",
			Help:      "Tunnel duration in seconds by tunnel type",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 300},
		}, []string{"tunnel_type"}),
		tunnelTypeBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "tunnel_type_bytes",
			Help:      "Data transferred in bytes by tunnel type",
			Buckets:   []float64{100, 1000, 10000, 100000, 1e6, 10e6, 100e6},
		}, []string{"tunnel_type"}),
		tunnelTypeActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "tunnel_type_active",
			Help:      "Current active tunnels by tunnel type",
		}, []string{"tunnel_type"}),
		aclAllowedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "acl_allowed_total",
			Help:      "Total ACL checks that allowed the target",
		}, []string{"tunnel_type"}),
		aclDeniedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "acl_denied_total",
			Help:      "Total ACL checks that denied the target",
		}, []string{"tunnel_type", "reason"}),
		managedTunnelEstablished: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "managed_tunnel_established_total",
			Help:      "Total managed CONNECT tunnels established, labeled by hostname",
		}, []string{"hostname"}),
		managedTunnelDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "managed_tunnel_duration_seconds",
			Help:      "Duration of managed tunnel sessions in seconds",
			Buckets:   []float64{0.1, 0.5, 1, 5, 10, 30, 60, 300, 600},
		}, []string{"hostname"}),
		managedTunnelBytesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "managed_tunnel_bytes_sent_total",
			Help:      "Total bytes sent to upstream through managed tunnel",
		}, []string{"hostname"}),
		managedTunnelBytesRecv: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "managed_tunnel_bytes_received_total",
			Help:      "Total bytes received from upstream through managed tunnel",
		}, []string{"hostname"}),
		managedTunnelRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "managed_tunnel_requests_total",
			Help:      "Total HTTP requests processed through managed tunnel pipeline",
		}, []string{"hostname", "status_class"}),
		providerMetrics: make(map[string]*ProviderMetrics),
	}

	return mc
}

// Register registers the collector metrics with the default prometheus registry once.
func (mc *MetricsCollector) Register() {
	if mc == nil {
		return
	}
	mc.registerOnce.Do(func() {
		registerCollector(mc.tunnelEstablishedTotal)
		registerCollector(mc.tunnelFailedTotal)
		registerCollector(mc.aiProviderDetectedTotal)
		registerCollector(mc.aiProviderBypassedTotal)
		registerCollector(mc.authSuccessTotal)
		registerCollector(mc.authFailureTotal)
		registerCollector(mc.targetManagedTotal)
		registerCollector(mc.targetUnmanagedTotal)
		registerCollector(mc.destinationBlockedTotal)
		registerCollector(mc.privateDeniedTotal)
		registerCollector(mc.certCacheHitTotal)
		registerCollector(mc.certCacheMissTotal)
		registerCollector(mc.tunnelDurationSeconds)
		registerCollector(mc.dataTransferredBytes)
		registerCollector(mc.activeTunnels)
		registerCollector(mc.tunnelTypeEstablished)
		registerCollector(mc.tunnelTypeFailed)
		registerCollector(mc.tunnelTypeDuration)
		registerCollector(mc.tunnelTypeBytes)
		registerCollector(mc.tunnelTypeActive)
		registerCollector(mc.aclAllowedTotal)
		registerCollector(mc.aclDeniedTotal)
		registerCollector(mc.managedTunnelEstablished)
		registerCollector(mc.managedTunnelDuration)
		registerCollector(mc.managedTunnelBytesSent)
		registerCollector(mc.managedTunnelBytesRecv)
		registerCollector(mc.managedTunnelRequests)
	})
}

// RecordTunnelEstablished records a successful tunnel establishment
func (mc *MetricsCollector) RecordTunnelEstablished() {
	mc.tunnelEstablishedTotal.Inc()
	mc.activeTunnels.Inc()
	slog.Debug("HTTPS tunnel established")
}

// RecordTunnelFailed records a failed tunnel attempt
func (mc *MetricsCollector) RecordTunnelFailed(reason string) {
	mc.tunnelFailedTotal.Inc()
	slog.Warn("HTTPS tunnel failed", "reason", reason)
}

// RecordAuthSuccess performs the record auth success operation on the MetricsCollector.
func (mc *MetricsCollector) RecordAuthSuccess() {
	mc.authSuccessTotal.Inc()
}

// RecordAuthFailure performs the record auth failure operation on the MetricsCollector.
func (mc *MetricsCollector) RecordAuthFailure() {
	mc.authFailureTotal.Inc()
}

// RecordManagedTarget performs the record managed target operation on the MetricsCollector.
func (mc *MetricsCollector) RecordManagedTarget() {
	mc.targetManagedTotal.Inc()
}

// RecordUnmanagedTarget performs the record unmanaged target operation on the MetricsCollector.
func (mc *MetricsCollector) RecordUnmanagedTarget() {
	mc.targetUnmanagedTotal.Inc()
}

// RecordDestinationBlocked performs the record destination blocked operation on the MetricsCollector.
func (mc *MetricsCollector) RecordDestinationBlocked() {
	mc.destinationBlockedTotal.Inc()
}

// RecordPrivateDenied performs the record private denied operation on the MetricsCollector.
func (mc *MetricsCollector) RecordPrivateDenied() {
	mc.privateDeniedTotal.Inc()
}

// RecordCertCacheHit performs the record cert cache hit operation on the MetricsCollector.
func (mc *MetricsCollector) RecordCertCacheHit() {
	mc.certCacheHitTotal.Inc()
}

// RecordCertCacheMiss performs the record cert cache miss operation on the MetricsCollector.
func (mc *MetricsCollector) RecordCertCacheMiss() {
	mc.certCacheMissTotal.Inc()
}

// RecordTunnelClosed records tunnel closure and duration
func (mc *MetricsCollector) RecordTunnelClosed(duration time.Duration, bytesTransferred int64) {
	mc.activeTunnels.Dec()
	mc.tunnelDurationSeconds.Observe(duration.Seconds())
	if bytesTransferred > 0 {
		mc.dataTransferredBytes.Observe(float64(bytesTransferred))
	}
	slog.Debug("HTTPS tunnel closed", "duration_ms", duration.Milliseconds(), "bytes", bytesTransferred)
}

// RecordTypedTunnelEstablished records a tunnel established with its type label.
func (mc *MetricsCollector) RecordTypedTunnelEstablished(tunnelType string) {
	mc.tunnelTypeEstablished.WithLabelValues(tunnelType).Inc()
	mc.tunnelTypeActive.WithLabelValues(tunnelType).Inc()
	slog.Debug("typed tunnel established", "tunnel_type", tunnelType)
}

// RecordTypedTunnelFailed records a tunnel failure with its type label and reason.
func (mc *MetricsCollector) RecordTypedTunnelFailed(tunnelType string, reason string) {
	mc.tunnelTypeFailed.WithLabelValues(tunnelType, reason).Inc()
	slog.Warn("typed tunnel failed", "tunnel_type", tunnelType, "reason", reason)
}

// RecordTypedTunnelClosed records tunnel closure for a specific tunnel type.
func (mc *MetricsCollector) RecordTypedTunnelClosed(tunnelType string, duration time.Duration, bytesTransferred int64) {
	mc.tunnelTypeActive.WithLabelValues(tunnelType).Dec()
	mc.tunnelTypeDuration.WithLabelValues(tunnelType).Observe(duration.Seconds())
	if bytesTransferred > 0 {
		mc.tunnelTypeBytes.WithLabelValues(tunnelType).Observe(float64(bytesTransferred))
	}
	slog.Debug("typed tunnel closed", "tunnel_type", tunnelType, "duration_ms", duration.Milliseconds(), "bytes", bytesTransferred)
}

// RecordACLAllowed records an ACL check that allowed the target.
func (mc *MetricsCollector) RecordACLAllowed(tunnelType string) {
	mc.aclAllowedTotal.WithLabelValues(tunnelType).Inc()
}

// RecordACLDenied records an ACL check that denied the target.
func (mc *MetricsCollector) RecordACLDenied(tunnelType string, reason string) {
	mc.aclDeniedTotal.WithLabelValues(tunnelType, reason).Inc()
}

// RecordManagedTunnelEstablished records that a managed CONNECT tunnel was
// established for the given hostname.
func (mc *MetricsCollector) RecordManagedTunnelEstablished(hostname string) {
	mc.managedTunnelEstablished.WithLabelValues(hostname).Inc()
}

// RecordManagedTunnelClosed records the duration and bytes transferred when a
// managed tunnel session ends.
func (mc *MetricsCollector) RecordManagedTunnelClosed(hostname string, duration time.Duration, bytesSent, bytesRecv int64) {
	mc.managedTunnelDuration.WithLabelValues(hostname).Observe(duration.Seconds())
	if bytesSent > 0 {
		mc.managedTunnelBytesSent.WithLabelValues(hostname).Add(float64(bytesSent))
	}
	if bytesRecv > 0 {
		mc.managedTunnelBytesRecv.WithLabelValues(hostname).Add(float64(bytesRecv))
	}
}

// RecordManagedTunnelRequest records a single HTTP request processed inside a
// managed tunnel pipeline. The status code is bucketed into classes (2xx, 3xx, etc.).
func (mc *MetricsCollector) RecordManagedTunnelRequest(hostname string, statusCode int, duration time.Duration, bytesWritten int64) {
	statusClass := statusCodeClass(statusCode)
	mc.managedTunnelRequests.WithLabelValues(hostname, statusClass).Inc()
	mc.managedTunnelDuration.WithLabelValues(hostname).Observe(duration.Seconds())
	if bytesWritten > 0 {
		mc.managedTunnelBytesRecv.WithLabelValues(hostname).Add(float64(bytesWritten))
	}
}

func statusCodeClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}

// RecordAIProviderDetected records detection of known AI provider
func (mc *MetricsCollector) RecordAIProviderDetected(provider string) {
	mc.aiProviderDetectedTotal.Inc()
	pm := mc.getOrCreateProviderMetrics(provider)
	pm.RequestsTotal.Inc()
	slog.Debug("AI provider detected", "provider", provider)
}

// RecordAIProviderBypassed records routing to proxy origin
func (mc *MetricsCollector) RecordAIProviderBypassed(provider string) {
	mc.aiProviderBypassedTotal.Inc()
	slog.Debug("AI provider routed to proxy origin", "provider", provider)
}

// RecordProviderError records an error for a specific provider
func (mc *MetricsCollector) RecordProviderError(provider string) {
	pm := mc.getOrCreateProviderMetrics(provider)
	pm.ErrorsTotal.Inc()
}

// RecordDataTransfer records data transfer for a provider
func (mc *MetricsCollector) RecordDataTransfer(provider string, bytesSent, bytesReceived int64) {
	pm := mc.getOrCreateProviderMetrics(provider)
	if bytesSent > 0 {
		pm.BytesSent.Add(float64(bytesSent))
	}
	if bytesReceived > 0 {
		pm.BytesReceived.Add(float64(bytesReceived))
	}
}

// RecordRequestLatency records latency for a provider request
func (mc *MetricsCollector) RecordRequestLatency(provider string, duration time.Duration) {
	pm := mc.getOrCreateProviderMetrics(provider)
	pm.LatencyHistogram.Observe(duration.Seconds())
}

// RecordEstimatedCost records estimated cost for a request
func (mc *MetricsCollector) RecordEstimatedCost(provider string, cost float64) {
	pm := mc.getOrCreateProviderMetrics(provider)
	pm.CostEstimated.Add(cost)
}

// getOrCreateProviderMetrics gets or creates metrics for a provider
func (mc *MetricsCollector) getOrCreateProviderMetrics(provider string) *ProviderMetrics {
	mc.providerMutex.RLock()
	if pm, exists := mc.providerMetrics[provider]; exists {
		mc.providerMutex.RUnlock()
		return pm
	}
	mc.providerMutex.RUnlock()

	mc.providerMutex.Lock()
	defer mc.providerMutex.Unlock()

	// Double-check after acquiring write lock
	if pm, exists := mc.providerMetrics[provider]; exists {
		return pm
	}

	// Create new provider metrics
	pm := &ProviderMetrics{
		RequestsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "https_proxy_provider_requests_total",
			Help:        "Total requests for provider",
			ConstLabels: prometheus.Labels{"provider": provider},
		}),
		ErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "https_proxy_provider_errors_total",
			Help:        "Total errors for provider",
			ConstLabels: prometheus.Labels{"provider": provider},
		}),
		BytesSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "https_proxy_provider_bytes_sent_total",
			Help:        "Total bytes sent to provider",
			ConstLabels: prometheus.Labels{"provider": provider},
		}),
		BytesReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "https_proxy_provider_bytes_received_total",
			Help:        "Total bytes received from provider",
			ConstLabels: prometheus.Labels{"provider": provider},
		}),
		CostEstimated: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "https_proxy_provider_cost_estimated_total",
			Help:        "Total estimated cost for provider in USD",
			ConstLabels: prometheus.Labels{"provider": provider},
		}),
		LatencyHistogram: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "https_proxy_provider_latency_seconds",
			Help:        "Request latency for provider in seconds",
			ConstLabels: prometheus.Labels{"provider": provider},
			Buckets:     []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10},
		}),
	}

	registerCollector(pm.RequestsTotal)
	registerCollector(pm.ErrorsTotal)
	registerCollector(pm.BytesSent)
	registerCollector(pm.BytesReceived)
	registerCollector(pm.CostEstimated)
	registerCollector(pm.LatencyHistogram)

	mc.providerMetrics[provider] = pm
	return pm
}

// GetProviderMetrics returns metrics for a specific provider
func (mc *MetricsCollector) GetProviderMetrics(provider string) *ProviderMetrics {
	mc.providerMutex.RLock()
	defer mc.providerMutex.RUnlock()
	return mc.providerMetrics[provider]
}

// GetAllProviderMetrics returns metrics for all providers
func (mc *MetricsCollector) GetAllProviderMetrics() map[string]*ProviderMetrics {
	mc.providerMutex.RLock()
	defer mc.providerMutex.RUnlock()

	result := make(map[string]*ProviderMetrics)
	for provider, metrics := range mc.providerMetrics {
		result[provider] = metrics
	}
	return result
}

// TunnelMetrics holds metrics for a tunnel session
type TunnelMetrics struct {
	StartTime        time.Time
	BytesTransferred int64
	Provider         string
	IsAIProvider     bool
	EstimatedCost    float64
	mu               sync.RWMutex
}

// NewTunnelMetrics creates a new tunnel metrics tracker
func NewTunnelMetrics(provider string, isAI bool) *TunnelMetrics {
	return &TunnelMetrics{
		StartTime:        time.Now(),
		BytesTransferred: 0,
		Provider:         provider,
		IsAIProvider:     isAI,
		EstimatedCost:    0,
	}
}

// AddBytes adds bytes transferred
func (tm *TunnelMetrics) AddBytes(bytes int64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.BytesTransferred += bytes
}

// SetEstimatedCost sets the estimated cost
func (tm *TunnelMetrics) SetEstimatedCost(cost float64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.EstimatedCost = cost
}

// GetDuration returns time elapsed since start
func (tm *TunnelMetrics) GetDuration() time.Duration {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return time.Since(tm.StartTime)
}

// GetStats returns a snapshot of current metrics
func (tm *TunnelMetrics) GetStats() (duration time.Duration, bytes int64, cost float64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return time.Since(tm.StartTime), tm.BytesTransferred, tm.EstimatedCost
}

func registerCollector(collector prometheus.Collector) {
	if collector == nil {
		return
	}
	if err := prometheus.Register(collector); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			slog.Debug("failed to register https_proxy metric", "error", err)
		}
	}
}
