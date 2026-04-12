// Package metric collects and exposes Prometheus metrics for proxy performance monitoring.
package metric

import (
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// mustRegisterCounter registers a Counter, returning the existing one if already registered.
func mustRegisterCounter(c prometheus.Counter) prometheus.Counter {
	if err := prometheus.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

// mustRegisterCounterVec registers a CounterVec, returning the existing one if already registered.
func mustRegisterCounterVec(c *prometheus.CounterVec) *prometheus.CounterVec {
	if err := prometheus.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

// mustRegisterGauge registers a Gauge, returning the existing one if already registered.
func mustRegisterGauge(g prometheus.Gauge) prometheus.Gauge {
	if err := prometheus.Register(g); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(prometheus.Gauge); ok {
				return existing
			}
		}
		panic(err)
	}
	return g
}

// mustRegisterGaugeVec registers a GaugeVec, returning the existing one if already registered.
func mustRegisterGaugeVec(g *prometheus.GaugeVec) *prometheus.GaugeVec {
	if err := prometheus.Register(g); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.GaugeVec); ok {
				return existing
			}
		}
		panic(err)
	}
	return g
}

// mustRegisterHistogram registers a Histogram, returning the existing one if already registered.
func mustRegisterHistogram(h prometheus.Histogram) prometheus.Histogram {
	if err := prometheus.Register(h); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(prometheus.Histogram); ok {
				return existing
			}
		}
		panic(err)
	}
	return h
}

// mustRegisterHistogramVec registers a HistogramVec, returning the existing one if already registered.
func mustRegisterHistogramVec(h *prometheus.HistogramVec) *prometheus.HistogramVec {
	if err := prometheus.Register(h); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := are.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
		}
		panic(err)
	}
	return h
}


var (
	totalHTTPRequests = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "http_req_total",
		Help: "The total number of HTTP requests served",
	}))

	totalHTTPOK = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "http_req_ok_total",
		Help: "The total number of HTTP requests served with 2xx status code",
	}))

	totalHTTPClientErrors = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "http_client_errors_total",
		Help: "The total number of HTTP requests served with 4xx status code",
	}))

	totalHTTPServerErrors = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "http_server_errors_total",
		Help: "The total number of HTTP requests served with 5xx status code",
	}))

	httpDuration = mustRegisterHistogram(prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "http_response_time_seconds",
		Help: "Duration of HTTP requests.",
	}))

	// Load Balancer metrics are in metric_lb.go
	// Circuit Breaker metrics are in metric_lb.go

	// Origin Config Metrics
	configCacheHits = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_cache_hits_total",
		Help: "Total number of configuration cache hits",
	}, []string{"hostname"}))

	configCacheMisses = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_cache_misses_total",
		Help: "Total number of configuration cache misses",
	}, []string{"hostname"}))

	configCacheSize = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sb_config_cache_size",
		Help: "Current number of entries in the configuration cache",
	}))

	activeOrigins = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_origins_active",
		Help: "Currently active origins by hostname, workspace, and origin ID",
	}, []string{"hostname", "workspace_id", "origin_id"}))

	configLoadsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_loads_total",
		Help: "Total number of configuration loads from storage",
	}, []string{"hostname", "type", "result"}))

	configLoadDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_config_load_duration_seconds",
		Help:    "Duration of configuration loads",
		Buckets: prometheus.DefBuckets,
	}, []string{"hostname", "type"}))

	configLoadErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_load_errors_total",
		Help: "Total number of configuration load errors",
	}, []string{"hostname", "error_type"}))

	configTypeLoaded = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_type_loaded_total",
		Help: "Total number of configurations loaded by type",
	}, []string{"type"}))

	configHostnameFallback = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_hostname_fallback_total",
		Help: "Total number of hostname fallback attempts",
	}, []string{"original_hostname", "fallback_hostname", "result"}))

	configForwardDepth = mustRegisterHistogram(prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "sb_config_forward_depth",
		Help:    "Distribution of configuration forward depths",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 10},
	}))

	configCacheEvictions = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_config_cache_evictions_total",
		Help: "Total number of configuration cache evictions (manual clears)",
	}))

	configCompilationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_config_compilation_duration_seconds",
		Help:    "Duration of configuration compilation steps",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
	}, []string{"hostname", "compilation_type"}))

	// Storage Metrics
	storageOperationsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_storage_operations_total",
		Help: "Total number of storage operations",
	}, []string{"storage_type", "operation", "result"}))

	storageOperationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_storage_operation_duration_seconds",
		Help:    "Duration of storage operations",
		Buckets: prometheus.DefBuckets,
	}, []string{"storage_type", "operation"}))

	storageOperationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_storage_operation_errors_total",
		Help: "Total number of storage operation errors",
	}, []string{"storage_type", "operation", "error_type"}))

	storageDataSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_storage_data_size_bytes",
		Help:    "Size of data stored/retrieved",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824}, // 1KB to 1GB
	}, []string{"storage_type", "operation"}))

	storageConnectionsActive = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_storage_connections_active",
		Help: "Current number of active storage connections",
	}, []string{"storage_type"}))

	// Cacher metrics are in metric_cache.go

	// Messenger Metrics
	messengerOperationsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_messenger_operations_total",
		Help: "Total number of messenger operations",
	}, []string{"messenger_type", "operation", "result"}))

	messengerOperationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_messenger_operation_duration_seconds",
		Help:    "Duration of messenger operations",
		Buckets: prometheus.DefBuckets,
	}, []string{"messenger_type", "operation"}))

	messengerOperationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_messenger_operation_errors_total",
		Help: "Total number of messenger operation errors",
	}, []string{"messenger_type", "operation", "error_type"}))

	messengerDataSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_messenger_data_size_bytes",
		Help:    "Size of data sent/received",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824}, // 1KB to 1GB
	}, []string{"messenger_type", "operation"}))

	// Crypto Metrics
	cryptoOperationsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_crypto_operations_total",
		Help: "Total number of crypto operations",
	}, []string{"crypto_type", "operation", "result"}))

	cryptoOperationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_crypto_operation_duration_seconds",
		Help:    "Duration of crypto operations",
		Buckets: prometheus.DefBuckets,
	}, []string{"crypto_type", "operation"}))

	cryptoOperationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_crypto_operation_errors_total",
		Help: "Total number of crypto operation errors",
	}, []string{"crypto_type", "operation", "error_type"}))

	cryptoDataSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_crypto_data_size_bytes",
		Help:    "Size of data encrypted/decrypted/signed/verified",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824}, // 1KB to 1GB
	}, []string{"crypto_type", "operation"}))

	// GeoIP Metrics
	geoipOperationsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_geoip_operations_total",
		Help: "Total number of GeoIP operations",
	}, []string{"geoip_type", "operation", "result"}))

	geoipOperationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_geoip_operation_duration_seconds",
		Help:    "Duration of GeoIP operations",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"geoip_type", "operation"}))

	geoipOperationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_geoip_operation_errors_total",
		Help: "Total number of GeoIP operation errors",
	}, []string{"geoip_type", "operation", "error_type"}))

	geoipLookupsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_geoip_lookups_total",
		Help: "Total number of IP lookups",
	}, []string{"geoip_type", "ip_version", "country_code"}))

	geoipLookupDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_geoip_lookup_duration_seconds",
		Help:    "Duration of IP lookups",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"geoip_type", "ip_version"}))

	// UAParser Metrics
	uaparserOperationsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_uaparser_operations_total",
		Help: "Total number of UAParser operations",
	}, []string{"uaparser_type", "operation", "result"}))

	uaparserOperationDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_uaparser_operation_duration_seconds",
		Help:    "Duration of UAParser operations",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"uaparser_type", "operation"}))

	uaparserOperationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_uaparser_operation_errors_total",
		Help: "Total number of UAParser operation errors",
	}, []string{"uaparser_type", "operation", "error_type"}))

	uaparserParsesTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_uaparser_parses_total",
		Help: "Total number of user agent parses",
	}, []string{"uaparser_type", "browser_family", "os_family", "device_family"}))

	uaparserParseDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_uaparser_parse_duration_seconds",
		Help:    "Duration of user agent parses",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"uaparser_type"}))

	// Certificate Pinning, TLS, Auth, and Security metrics are in metric_security.go

	// Reliability Metrics
	requestTimeouts = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_request_timeouts_total",
		Help: "Requests that timed out. Alert when rate > 1% of requests.",
	}, []string{"origin", "timeout_type", "upstream"}))

	connectionPoolExhaustions = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_connection_pool_exhaustions_total",
		Help: "Times connection pool was exhausted. Immediate alert (indicates capacity issues).",
	}, []string{"origin", "pool_type"}))

	// WebSocket Pool Metrics
	websocketPoolConnectionsCreated = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_pool_connections_created_total",
		Help: "Total number of WebSocket connections created in the pool",
	}, []string{"origin", "target"}))

	websocketPoolConnectionsClosed = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_pool_connections_closed_total",
		Help: "Total number of WebSocket connections closed in the pool",
	}, []string{"origin", "target"}))

	websocketPoolConnectionsAcquired = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_pool_connections_acquired_total",
		Help: "Total number of WebSocket connections acquired from the pool",
	}, []string{"origin", "target"}))

	websocketPoolConnectionsReleased = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_pool_connections_released_total",
		Help: "Total number of WebSocket connections released back to the pool",
	}, []string{"origin", "target"}))

	websocketPoolReconnects = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_pool_reconnects_total",
		Help: "Total number of WebSocket connection reconnects",
	}, []string{"origin", "target"}))

	websocketPoolSize = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_websocket_pool_size",
		Help: "Current number of connections in the WebSocket pool",
	}, []string{"origin", "target"}))

	websocketPoolIdleSize = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_websocket_pool_idle_size",
		Help: "Current number of idle connections in the WebSocket pool",
	}, []string{"origin", "target"}))

	websocketPoolActiveSize = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_websocket_pool_active_size",
		Help: "Current number of active (in-use) connections in the WebSocket pool",
	}, []string{"origin", "target"}))

	upstreamAvailability = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_upstream_availability",
		Help: "Current availability of upstream targets (0=down, 1=up). Alert when value = 0.",
	}, []string{"origin", "target"}))

	// Performance Metrics
	requestLatencyPercentiles = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_request_latency_seconds",
		Help:    "Request latency distribution. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	}, []string{"origin", "method", "status_code"}))

	upstreamResponseTime = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_upstream_response_time_seconds",
		Help:    "Time to receive response from upstream. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	}, []string{"origin", "target", "status_code"}))

	dnsResolutionTime = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_dns_resolution_time_seconds",
		Help:    "DNS lookup duration. Alert when p95 > 1s.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"hostname", "result"}))

	// Cache hit rate, fingerprint cache, and chunk cache metrics are in metric_cache.go

	requestBodySize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_request_body_size_bytes",
		Help:    "Request body size distribution. Alert on unusually large requests.",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824},
	}, []string{"origin", "method"}))

	responseBodySize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_response_body_size_bytes",
		Help:    "Response body size distribution. Alert on unusually large responses.",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824},
	}, []string{"origin", "status_code"}))

	activeConnections = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "active_connections",
		Help: "Current active connections. Alert when approaching limits.",
	}, []string{"origin", "connection_type"}))

	websocketConnectionDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_websocket_connection_duration_seconds",
		Help:    "WebSocket connection lifetime. Alert on unusually short connections (potential issues).",
		Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
	}, []string{"origin"}))

	websocketFramesRelayed = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_frames_relayed_total",
		Help: "Total websocket frames relayed by direction and provider.",
	}, []string{"origin", "direction", "provider"}))

	websocketBytesTransferred = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_bytes_transferred_total",
		Help: "Total websocket payload bytes transferred by direction and provider.",
	}, []string{"origin", "direction", "provider"}))

	websocketPolicyViolations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_policy_violations_total",
		Help: "Total websocket message policy or transport violations.",
	}, []string{"origin", "reason"}))

	websocketToolCallEvents = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_websocket_tool_call_events_total",
		Help: "Total observed websocket tool call lifecycle events.",
	}, []string{"origin", "direction", "provider"}))

	httpVersionUsage = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_http_version_usage_total",
		Help: "HTTP version usage (1.1, 2, 3). Informational.",
	}, []string{"origin", "http_version"}))

	quicConnections = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_quic_connections_total",
		Help: "QUIC connection attempts and results. Alert on high failure rate.",
	}, []string{"origin", "result"}))

	// Operational Metrics
	configReloads = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_reloads_total",
		Help: "Configuration reload attempts. Alert on failures.",
	}, []string{"hostname", "result"}))

	configReloadDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_config_reload_duration_seconds",
		Help:    "Configuration reload duration. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	}, []string{"result"}))

	configChanges = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_changes_total",
		Help: "Configuration parameter changes detected during reload.",
	}, []string{"parameter", "old_value", "new_value"}))

	configErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_config_errors_total",
		Help: "Configuration parsing/validation errors. Alert on any errors.",
	}, []string{"hostname", "error_type"}))

	storageQuotaUsage = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_storage_quota_usage_bytes",
		Help: "Storage quota usage. Alert when > 80%.",
	}, []string{"storage_type"}))

	messengerQueueDepth = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_messenger_queue_depth",
		Help: "Current message queue depth. Alert when depth > threshold.",
	}, []string{"messenger_type", "channel"}))

	messageProcessingLatency = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_message_processing_latency_seconds",
		Help:    "Message processing duration. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"messenger_type", "channel"}))

	celExecutionTime = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_cel_execution_time_seconds",
		Help:    "CEL expression evaluation duration. Alert when p95 > threshold.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	}, []string{"origin", "expression_type"}))

	luaExecutionTime = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_lua_execution_time_seconds",
		Help:    "Lua script execution duration. Alert when p95 > threshold.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	}, []string{"origin", "script_name"}))

	luaScriptErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_lua_script_errors_total",
		Help: "Total number of Lua script execution errors. Can be used for circuit breaker.",
	}, []string{"origin", "script_name", "error_type"}))

	// WAF and Host Filter metrics are in metric_security.go

	transformLatency = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_transform_latency_seconds",
		Help:    "Content transformation duration. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	}, []string{"origin", "transform_type"}))

	// Business Metrics
	requestsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_requests_total",
		Help: "Total requests per origin. Alert on unusual spikes/drops.",
	}, []string{"workspace_id", "origin", "method", "status_code"}))

	uniqueUsers = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_unique_users_total",
		Help: "Unique active users/API keys. Informational.",
	}, []string{"origin", "user_type"}))

	bandwidthBytes = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_bandwidth_bytes_total",
		Help: "Total bandwidth usage. Alert on unusual spikes.",
	}, []string{"origin", "direction"}))

	// Cache efficiency metrics are in metric_cache.go
	// LB target distribution metrics are in metric_lb.go

	graphqlQueryComplexity = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_graphql_query_complexity",
		Help:    "GraphQL query complexity scores. Alert on high complexity queries.",
		Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
	}, []string{"origin", "operation_name"}))

	graphqlExecutionTime = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_graphql_execution_time_seconds",
		Help:    "GraphQL query execution duration. Alert when p95 > threshold.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
	}, []string{"origin", "operation_name"}))

	graphqlBatchSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_graphql_batch_size",
		Help:    "GraphQL batch size (original and deduplicated)",
		Buckets: []float64{1, 2, 5, 10, 20, 50, 100},
	}, []string{"origin_id"}))

	graphqlCacheHits = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_graphql_cache_hits_total",
		Help: "Total number of GraphQL result cache hits",
	}, []string{"origin_id"}))

	// Observability Metrics
	errorsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_errors_total",
		Help: "Errors categorized by type. Alert on spike in specific error types.",
	}, []string{"origin", "error_type", "error_category"}))

	retryAttempts = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_retry_attempts_total",
		Help: "Retry attempts and outcomes. Alert on high retry rate.",
	}, []string{"origin", "retry_reason", "success"}))

	requestCancellations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_request_cancellations_total",
		Help: "Client-side request cancellations. Alert on high cancellation rate.",
	}, []string{"origin", "cancellation_reason"}))

	upstreamConnectionReuseRate = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_upstream_connection_reuse_rate",
		Help: "Percentage of requests reusing connections (0-1). Alert when rate drops (indicates connection issues).",
	}, []string{"origin", "target"}))

	http2Streams = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_http2_streams_total",
		Help: "HTTP/2 stream creation and results. Alert on high failure rate.",
	}, []string{"origin", "result"}))

	requestHeaderSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_request_header_size_bytes",
		Help:    "Request header size distribution. Alert on unusually large headers.",
		Buckets: []float64{256, 512, 1024, 2048, 4096, 8192, 16384},
	}, []string{"origin"}))

	responseHeaderSize = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_response_header_size_bytes",
		Help:    "Response header size distribution. Alert on unusually large headers.",
		Buckets: []float64{256, 512, 1024, 2048, 4096, 8192, 16384},
	}, []string{"origin"}))

	// Low Priority Observability Metrics
	traceCoverage = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_trace_coverage",
		Help: "Percentage of requests with traces (0-1). Informational.",
	}, []string{"origin", "trace_sampled"}))

	traceSpanDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_trace_span_duration_seconds",
		Help:    "Trace span duration distribution. Use for analysis.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"span_name", "operation"}))

	logVolume = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_log_volume_total",
		Help: "Log entries by level. Alert on spike in ERROR/WARN logs.",
	}, []string{"log_level", "workspace_id", "origin"}))

	clickhouseDropped = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_clickhouse_dropped_total",
		Help: "Log entries dropped due to ClickHouse write failures. Alert if non-zero.",
	}))

	clickhouseFlushed = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_clickhouse_flushed_total",
		Help: "Log entries successfully flushed to ClickHouse.",
	}))

	clickhouseFlushErrors = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_clickhouse_flush_errors_total",
		Help: "Errors during ClickHouse flush operations.",
	}))

	clickhouseCircuitOpen = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sb_clickhouse_circuit_open_total",
		Help: "Times ClickHouse circuit breaker transitioned to open.",
	}))

	eventBusDropped = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_event_bus_dropped_total",
		Help: "Events dropped due to event bus pressure.",
	}, []string{"event_type"}))

	// Cache invalidation metrics are in metric_cache.go

	featureFlagUsage = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_feature_flag_usage_total",
		Help: "Feature flag usage. Informational.",
	}, []string{"feature_name", "enabled"}))

	abtestVariantDistribution = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_abtest_variant_distribution",
		Help: "A/B test variant selection. Alert on uneven distribution.",
	}, []string{"origin", "test_name", "variant"}))

	requestFingerprintUniqueness = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_request_fingerprint_uniqueness",
		Help: "Unique fingerprint ratio. Alert on low uniqueness (potential bot traffic).",
	}, []string{"origin"}))

	sessionDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_session_duration_seconds",
		Help:    "User session duration. Informational.",
		Buckets: []float64{60, 300, 600, 1800, 3600, 7200, 14400, 28800, 86400},
	}, []string{"origin", "session_type"}))

	apiVersionUsage = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_api_version_usage_total",
		Help: "API version usage. Alert on deprecated version usage.",
	}, []string{"origin", "api_version"}))

	requestPathDistribution = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_request_path_distribution",
		Help: "Request distribution by path pattern. Informational.",
	}, []string{"origin", "path_pattern"}))

	geoRequestDistribution = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_geo_request_distribution",
		Help: "Request distribution by geography. Informational.",
	}, []string{"origin", "country_code", "region"}))

	deviceTypeDistribution = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_device_type_distribution",
		Help: "Request distribution by device type. Informational.",
	}, []string{"origin", "device_type"}))

	browserDistribution = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_browser_distribution",
		Help: "Request distribution by browser. Informational.",
	}, []string{"origin", "browser_family"}))

	osDistribution = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_os_distribution",
		Help: "Request distribution by OS. Informational.",
	}, []string{"origin", "os_family"}))

	// Fallback Origin Metrics
	fallbackTriggeredTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_fallback_origin_triggered_total",
		Help: "Total fallback origin activations",
	}, []string{"origin_id", "fallback_hostname", "trigger"}))

	fallbackSuccessTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_fallback_origin_success_total",
		Help: "Successful fallback origin responses",
	}, []string{"origin_id", "fallback_hostname"}))

	fallbackFailureTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_fallback_origin_failure_total",
		Help: "Failed fallback origin attempts",
	}, []string{"origin_id", "fallback_hostname", "reason"}))

	fallbackLatency = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_fallback_origin_latency_seconds",
		Help:    "Total latency including primary attempt and fallback",
		Buckets: prometheus.DefBuckets,
	}, []string{"origin_id", "fallback_hostname"}))
)

// AddMetricsEndpoint exposes metrics to the specified endpoint
func AddMetricsEndpoint(metricsPath string, handler chi.Router) {
	handler.Handle(metricsPath, promhttp.Handler())
}

// HTTPRequestServed performs the http request served operation.
func HTTPRequestServed(status int) {
	totalHTTPRequests.Inc()
	if status >= 200 && status < 300 {
		totalHTTPOK.Inc()
	} else if status >= 400 && status < 500 {
		totalHTTPClientErrors.Inc()
	} else if status >= 500 {
		totalHTTPServerErrors.Inc()
	}
}

// HTTPDuration performs the http duration operation.
func HTTPDuration(fn func()) {
	timer := prometheus.NewTimer(httpDuration)
	fn()
	timer.ObserveDuration()
}

// Load Balancer Metric Functions are in metric_lb.go

// Origin Config Metric Functions

// ConfigCacheHit records a cache hit for a configuration
func ConfigCacheHit(hostname string) {
	configCacheHits.WithLabelValues(hostname).Inc()
}

// ConfigCacheMiss records a cache miss for a configuration
func ConfigCacheMiss(hostname string) {
	configCacheMisses.WithLabelValues(hostname).Inc()
}

// ConfigCacheSizeSet sets the current size of the configuration cache
func ConfigCacheSizeSet(size int) {
	configCacheSize.Set(float64(size))
}

// OriginActive marks an origin as active with its metadata
func OriginActive(hostname, workspaceID, originID string) {
	activeOrigins.WithLabelValues(hostname, workspaceID, originID).Set(1)
}

// OriginInactive removes an origin from the active set
func OriginInactive(hostname, workspaceID, originID string) {
	activeOrigins.DeleteLabelValues(hostname, workspaceID, originID)
}

// OriginsReset clears all active origin metrics (used on full config reload)
func OriginsReset() {
	activeOrigins.Reset()
}

// ConfigLoaded records a completed configuration load
func ConfigLoaded(hostname, configType, result string, duration float64) {
	configLoadsTotal.WithLabelValues(hostname, configType, result).Inc()
	if configType != "" {
		configLoadDuration.WithLabelValues(hostname, configType).Observe(duration)
	}
}

// ConfigLoadError records a configuration load error
func ConfigLoadError(hostname, errorType string) {
	configLoadErrors.WithLabelValues(hostname, errorType).Inc()
}

// ConfigTypeLoaded records when a specific configuration type is loaded
func ConfigTypeLoaded(configType string) {
	if configType != "" {
		configTypeLoaded.WithLabelValues(configType).Inc()
	}
}

// ConfigHostnameFallback records a hostname fallback attempt
func ConfigHostnameFallback(originalHostname, fallbackHostname, result string) {
	configHostnameFallback.WithLabelValues(originalHostname, fallbackHostname, result).Inc()
}

// ConfigForwardDepth records the depth of configuration forwarding
func ConfigForwardDepth(depth int) {
	configForwardDepth.Observe(float64(depth))
}

// ConfigCacheEviction records a cache eviction event
func ConfigCacheEviction() {
	configCacheEvictions.Inc()
}

// ConfigCompilationDuration records the duration of a configuration compilation step
func ConfigCompilationDuration(hostname, compilationType string, duration float64) {
	configCompilationDuration.WithLabelValues(hostname, compilationType).Observe(duration)
}

// Storage Metric Functions

// StorageOperation records a storage operation with result and duration
func StorageOperation(storageType, operation, result string, duration float64) {
	storageOperationsTotal.WithLabelValues(storageType, operation, result).Inc()
	storageOperationDuration.WithLabelValues(storageType, operation).Observe(duration)
}

// StorageOperationError records a storage operation error
func StorageOperationError(storageType, operation, errorType string) {
	storageOperationErrors.WithLabelValues(storageType, operation, errorType).Inc()
}

// StorageDataSize records the size of data in a storage operation
func StorageDataSize(storageType, operation string, size int64) {
	storageDataSize.WithLabelValues(storageType, operation).Observe(float64(size))
}

// StorageConnectionsActive sets the current number of active storage connections
func StorageConnectionsActive(storageType string, count int64) {
	storageConnectionsActive.WithLabelValues(storageType).Set(float64(count))
}

// Cacher Metric Functions are in metric_cache.go

// Messenger Metric Functions

// MessengerOperation records a messenger operation with result and duration
func MessengerOperation(messengerType, operation, result string, duration float64) {
	messengerOperationsTotal.WithLabelValues(messengerType, operation, result).Inc()
	messengerOperationDuration.WithLabelValues(messengerType, operation).Observe(duration)
}

// MessengerOperationError records a messenger operation error
func MessengerOperationError(messengerType, operation, errorType string) {
	messengerOperationErrors.WithLabelValues(messengerType, operation, errorType).Inc()
}

// MessengerDataSize records the size of data in a messenger operation
func MessengerDataSize(messengerType, operation string, size int64) {
	messengerDataSize.WithLabelValues(messengerType, operation).Observe(float64(size))
}

// Crypto Metric Functions

// CryptoOperation records a crypto operation with result and duration
func CryptoOperation(cryptoType, operation, result string, duration float64) {
	cryptoOperationsTotal.WithLabelValues(cryptoType, operation, result).Inc()
	cryptoOperationDuration.WithLabelValues(cryptoType, operation).Observe(duration)
}

// CryptoOperationError records a crypto operation error
func CryptoOperationError(cryptoType, operation, errorType string) {
	cryptoOperationErrors.WithLabelValues(cryptoType, operation, errorType).Inc()
}

// CryptoDataSize records the size of data in a crypto operation
func CryptoDataSize(cryptoType, operation string, size int64) {
	cryptoDataSize.WithLabelValues(cryptoType, operation).Observe(float64(size))
}

// GeoIP Metric Functions

// GeoIPOperation records a GeoIP operation with result and duration
func GeoIPOperation(geoipType, operation, result string, duration float64) {
	geoipOperationsTotal.WithLabelValues(geoipType, operation, result).Inc()
	geoipOperationDuration.WithLabelValues(geoipType, operation).Observe(duration)
}

// GeoIPOperationError records a GeoIP operation error
func GeoIPOperationError(geoipType, operation, errorType string) {
	geoipOperationErrors.WithLabelValues(geoipType, operation, errorType).Inc()
}

// GeoIPLookup records an IP lookup with country and IP version
func GeoIPLookup(geoipType, ipVersion, countryCode string, duration float64) {
	geoipLookupsTotal.WithLabelValues(geoipType, ipVersion, countryCode).Inc()
	geoipLookupDuration.WithLabelValues(geoipType, ipVersion).Observe(duration)
}

// UAParser Metric Functions

// UAParserOperation records a UAParser operation with result and duration
func UAParserOperation(uaparserType, operation, result string, duration float64) {
	uaparserOperationsTotal.WithLabelValues(uaparserType, operation, result).Inc()
	uaparserOperationDuration.WithLabelValues(uaparserType, operation).Observe(duration)
}

// UAParserOperationError records a UAParser operation error
func UAParserOperationError(uaparserType, operation, errorType string) {
	uaparserOperationErrors.WithLabelValues(uaparserType, operation, errorType).Inc()
}

// UAParserParse records a user agent parse with browser, OS, and device info
func UAParserParse(uaparserType, browserFamily, osFamily, deviceFamily string, duration float64) {
	uaparserParsesTotal.WithLabelValues(uaparserType, browserFamily, osFamily, deviceFamily).Inc()
	uaparserParseDuration.WithLabelValues(uaparserType).Observe(duration)
}

// Security Metric Functions (CertPin, TLS, Auth, DDoS, CSRF, GeoBlock) are in metric_security.go

// Reliability Metric Functions

// RequestTimeout records a request timeout
func RequestTimeout(origin, timeoutType, upstream string) {
	requestTimeouts.WithLabelValues(origin, timeoutType, upstream).Inc()
}

// ConnectionPoolExhaustion records a connection pool exhaustion
func ConnectionPoolExhaustion(origin, poolType string) {
	connectionPoolExhaustions.WithLabelValues(origin, poolType).Inc()
}

// WebSocket Pool Metric Functions

// WebSocketPoolConnectionCreated records a WebSocket connection created in the pool
func WebSocketPoolConnectionCreated(origin, target string) {
	websocketPoolConnectionsCreated.WithLabelValues(origin, target).Inc()
}

// WebSocketPoolConnectionClosed records a WebSocket connection closed in the pool
func WebSocketPoolConnectionClosed(origin, target string) {
	websocketPoolConnectionsClosed.WithLabelValues(origin, target).Inc()
}

// WebSocketPoolConnectionAcquired records a WebSocket connection acquired from the pool
func WebSocketPoolConnectionAcquired(origin, target string) {
	websocketPoolConnectionsAcquired.WithLabelValues(origin, target).Inc()
}

// WebSocketPoolConnectionReleased records a WebSocket connection released back to the pool
func WebSocketPoolConnectionReleased(origin, target string) {
	websocketPoolConnectionsReleased.WithLabelValues(origin, target).Inc()
}

// WebSocketPoolReconnect records a WebSocket connection reconnect
func WebSocketPoolReconnect(origin, target string) {
	websocketPoolReconnects.WithLabelValues(origin, target).Inc()
}

// WebSocketPoolSizeSet sets the current pool size
func WebSocketPoolSizeSet(origin, target string, size int64) {
	websocketPoolSize.WithLabelValues(origin, target).Set(float64(size))
}

// WebSocketPoolIdleSizeSet sets the current idle pool size
func WebSocketPoolIdleSizeSet(origin, target string, size int64) {
	websocketPoolIdleSize.WithLabelValues(origin, target).Set(float64(size))
}

// WebSocketPoolActiveSizeSet sets the current active (in-use) pool size
func WebSocketPoolActiveSizeSet(origin, target string, size int64) {
	websocketPoolActiveSize.WithLabelValues(origin, target).Set(float64(size))
}

// UpstreamAvailabilitySet sets the availability of an upstream target
func UpstreamAvailabilitySet(origin, target string, available bool) {
	value := 0.0
	if available {
		value = 1.0
	}
	upstreamAvailability.WithLabelValues(origin, target).Set(value)
}

// Performance Metric Functions

// RequestLatency records request latency
func RequestLatency(origin, method string, statusCode int, duration float64) {
	statusStr := strconv.Itoa(statusCode)
	requestLatencyPercentiles.WithLabelValues(origin, method, statusStr).Observe(duration)
}

// UpstreamResponseTime records upstream response time
func UpstreamResponseTime(origin, target string, statusCode int, duration float64) {
	statusStr := strconv.Itoa(statusCode)
	upstreamResponseTime.WithLabelValues(origin, target, statusStr).Observe(duration)
}

// DNSResolutionTime records DNS resolution time
func DNSResolutionTime(hostname, result string, duration float64) {
	dnsResolutionTime.WithLabelValues(hostname, result).Observe(duration)
}

// CacheHitRateSet and CacheEviction are in metric_cache.go

// Fingerprint Cacher Metric Functions are in metric_cache.go

// RequestBodySize records request body size
func RequestBodySize(origin, method string, size int64) {
	requestBodySize.WithLabelValues(origin, method).Observe(float64(size))
}

// ResponseBodySize records response body size
func ResponseBodySize(origin string, statusCode int, size int64) {
	statusStr := strconv.Itoa(statusCode)
	responseBodySize.WithLabelValues(origin, statusStr).Observe(float64(size))
}

// ActiveConnectionsSet sets the number of active connections
func ActiveConnectionsSet(origin, connectionType string, count int64) {
	activeConnections.WithLabelValues(origin, connectionType).Set(float64(count))
}

// WebSocketConnectionDuration records WebSocket connection duration
func WebSocketConnectionDuration(origin string, duration float64) {
	websocketConnectionDuration.WithLabelValues(origin).Observe(duration)
}

// WebSocketFrameRelayed records a relayed websocket frame.
func WebSocketFrameRelayed(origin, direction, provider string) {
	websocketFramesRelayed.WithLabelValues(origin, direction, provider).Inc()
}

// WebSocketBytesTransferred records websocket payload bytes.
func WebSocketBytesTransferred(origin, direction, provider string, size int) {
	websocketBytesTransferred.WithLabelValues(origin, direction, provider).Add(float64(size))
}

// WebSocketPolicyViolation records a websocket policy or transport rejection.
func WebSocketPolicyViolation(origin, reason string) {
	websocketPolicyViolations.WithLabelValues(origin, reason).Inc()
}

// WebSocketToolCallEvent records an observed websocket tool-call lifecycle event.
func WebSocketToolCallEvent(origin, direction, provider string) {
	websocketToolCallEvents.WithLabelValues(origin, direction, provider).Inc()
}

// HTTPVersionUsage records HTTP version usage
func HTTPVersionUsage(origin, httpVersion string) {
	httpVersionUsage.WithLabelValues(origin, httpVersion).Inc()
}

// QUICConnection records a QUIC connection attempt
func QUICConnection(origin, result string) {
	quicConnections.WithLabelValues(origin, result).Inc()
}

// Operational Metric Functions

// ConfigReload records a configuration reload attempt (for origin configs)
func ConfigReload(hostname, result string) {
	configReloads.WithLabelValues(hostname, result).Inc()
}

// ConfigReloadWithDuration records a configuration reload attempt with duration (for global hot reload)
func ConfigReloadWithDuration(result string, duration time.Duration) {
	configReloads.WithLabelValues("global", result).Inc()
	configReloadDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// ConfigChange records a configuration parameter change
func ConfigChange(parameter, oldValue, newValue string) {
	configChanges.WithLabelValues(parameter, oldValue, newValue).Inc()
}

// ConfigError records a configuration error
func ConfigError(hostname, errorType string) {
	configErrors.WithLabelValues(hostname, errorType).Inc()
}

// StorageQuotaUsageSet sets storage quota usage
func StorageQuotaUsageSet(storageType string, usageBytes int64) {
	storageQuotaUsage.WithLabelValues(storageType).Set(float64(usageBytes))
}

// MessengerQueueDepthSet sets message queue depth
func MessengerQueueDepthSet(messengerType, channel string, depth int64) {
	messengerQueueDepth.WithLabelValues(messengerType, channel).Set(float64(depth))
}

// MessageProcessingLatency records message processing duration
func MessageProcessingLatency(messengerType, channel string, duration float64) {
	messageProcessingLatency.WithLabelValues(messengerType, channel).Observe(duration)
}

// CELExecutionTime records CEL expression execution time
func CELExecutionTime(origin, expressionType string, duration float64) {
	celExecutionTime.WithLabelValues(origin, expressionType).Observe(duration)
}

// LuaExecutionTime records Lua script execution time
func LuaExecutionTime(origin, scriptName string, duration float64) {
	luaExecutionTime.WithLabelValues(origin, scriptName).Observe(duration)
}

// LuaScriptError records Lua script execution errors for monitoring and circuit breaker use
func LuaScriptError(origin, scriptName, errorType string) {
	luaScriptErrors.WithLabelValues(origin, scriptName, errorType).Inc()
}

// WAF and Host Filter Metric Functions are in metric_security.go

// TransformLatency records transform operation latency
func TransformLatency(origin, transformType string, duration float64) {
	transformLatency.WithLabelValues(origin, transformType).Observe(duration)
}

// Business Metric Functions

// RequestTotal records a request
func RequestTotal(workspaceID, origin, method string, statusCode int) {
	statusStr := strconv.Itoa(statusCode)
	if workspaceID == "" {
		workspaceID = "unknown"
	}
	requestsTotal.WithLabelValues(workspaceID, origin, method, statusStr).Inc()
}

// UniqueUsersSet sets the number of unique users
func UniqueUsersSet(origin, userType string, count int64) {
	uniqueUsers.WithLabelValues(origin, userType).Set(float64(count))
}

// BandwidthBytes records bandwidth usage
func BandwidthBytes(origin, direction string, bytes int64) {
	bandwidthBytes.WithLabelValues(origin, direction).Add(float64(bytes))
}

// CacheEfficiencySet is in metric_cache.go
// LBTargetDistribution is in metric_lb.go

// GraphQLQueryComplexity records GraphQL query complexity
func GraphQLQueryComplexity(origin, operationName string, complexity float64) {
	graphqlQueryComplexity.WithLabelValues(origin, operationName).Observe(complexity)
}

// GraphQLExecutionTime records GraphQL query execution time
func GraphQLExecutionTime(origin, operationName string, duration float64) {
	graphqlExecutionTime.WithLabelValues(origin, operationName).Observe(duration)
}

// GraphQLBatchSize records GraphQL batch size metrics
func GraphQLBatchSize(origin string, originalSize, deduplicatedSize int) {
	graphqlBatchSize.WithLabelValues(origin).Observe(float64(originalSize))
	graphqlBatchSize.WithLabelValues(origin).Observe(float64(deduplicatedSize))
}

// GraphQLCacheHit records a GraphQL result cache hit
func GraphQLCacheHit(origin string, hits int) {
	graphqlCacheHits.WithLabelValues(origin).Add(float64(hits))
}

// Observability Metric Functions

// ErrorTotal records an error
func ErrorTotal(origin, errorType, errorCategory string) {
	errorsTotal.WithLabelValues(origin, errorType, errorCategory).Inc()
}

// RetryAttempt records a retry attempt
func RetryAttempt(origin, retryReason string, success bool) {
	successStr := "false"
	if success {
		successStr = "true"
	}
	retryAttempts.WithLabelValues(origin, retryReason, successStr).Inc()
}

// RequestCancellation records a request cancellation
func RequestCancellation(origin, cancellationReason string) {
	requestCancellations.WithLabelValues(origin, cancellationReason).Inc()
}

// UpstreamConnectionReuseRateSet sets upstream connection reuse rate
func UpstreamConnectionReuseRateSet(origin, target string, rate float64) {
	upstreamConnectionReuseRate.WithLabelValues(origin, target).Set(rate)
}

// HTTP2Stream records an HTTP/2 stream operation
func HTTP2Stream(origin, result string) {
	http2Streams.WithLabelValues(origin, result).Inc()
}

// RequestHeaderSize records request header size
func RequestHeaderSize(origin string, size int64) {
	requestHeaderSize.WithLabelValues(origin).Observe(float64(size))
}

// ResponseHeaderSize records response header size
func ResponseHeaderSize(origin string, size int64) {
	responseHeaderSize.WithLabelValues(origin).Observe(float64(size))
}

// Low Priority Observability Metric Functions

// TraceCoverageSet sets trace coverage percentage
func TraceCoverageSet(origin, traceSampled string, coverage float64) {
	traceCoverage.WithLabelValues(origin, traceSampled).Set(coverage)
}

// TraceSpanDuration records trace span duration
func TraceSpanDuration(spanName, operation string, duration float64) {
	traceSpanDuration.WithLabelValues(spanName, operation).Observe(duration)
}

// LogVolume records log volume
func LogVolume(logLevel, workspaceID, origin string) {
	if workspaceID == "" {
		workspaceID = "unknown"
	}
	logVolume.WithLabelValues(logLevel, workspaceID, origin).Inc()
}

// ClickHouseDropped records log entries dropped due to ClickHouse write failures
func ClickHouseDropped(count int64) {
	clickhouseDropped.Add(float64(count))
}

// ClickHouseFlushed records log entries successfully flushed to ClickHouse
func ClickHouseFlushed(count int64) {
	clickhouseFlushed.Add(float64(count))
}

// ClickHouseFlushError records errors during ClickHouse flush operations
func ClickHouseFlushError(err error) {
	clickhouseFlushErrors.Inc()
}

// ClickHouseCircuitOpen records when ClickHouse circuit breaker opens
func ClickHouseCircuitOpen() {
	clickhouseCircuitOpen.Inc()
}

// EventBusDropped records a dropped in-process event.
func EventBusDropped(eventType string) {
	eventBusDropped.WithLabelValues(eventType).Inc()
}

// CacheInvalidationDuration is in metric_cache.go

// FeatureFlagUsage records feature flag usage
func FeatureFlagUsage(featureName string, enabled bool) {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	featureFlagUsage.WithLabelValues(featureName, enabledStr).Inc()
}

// ABTestVariantDistribution records A/B test variant selection
func ABTestVariantDistribution(origin, testName, variant string) {
	abtestVariantDistribution.WithLabelValues(origin, testName, variant).Inc()
}

// RequestFingerprintUniquenessSet sets request fingerprint uniqueness ratio
func RequestFingerprintUniquenessSet(origin string, uniqueness float64) {
	requestFingerprintUniqueness.WithLabelValues(origin).Set(uniqueness)
}

// SessionDuration records session duration
func SessionDuration(origin, sessionType string, duration float64) {
	sessionDuration.WithLabelValues(origin, sessionType).Observe(duration)
}

// APIVersionUsage records API version usage
func APIVersionUsage(origin, apiVersion string) {
	apiVersionUsage.WithLabelValues(origin, apiVersion).Inc()
}

// RequestPathDistribution records request path distribution
func RequestPathDistribution(origin, pathPattern string) {
	requestPathDistribution.WithLabelValues(origin, pathPattern).Inc()
}

// GeoRequestDistribution records geographic request distribution
func GeoRequestDistribution(origin, countryCode, region string) {
	geoRequestDistribution.WithLabelValues(origin, countryCode, region).Inc()
}

// DeviceTypeDistribution records device type distribution
func DeviceTypeDistribution(origin, deviceType string) {
	deviceTypeDistribution.WithLabelValues(origin, deviceType).Inc()
}

// BrowserDistribution records browser distribution
func BrowserDistribution(origin, browserFamily string) {
	browserDistribution.WithLabelValues(origin, browserFamily).Inc()
}

// OSDistribution records OS distribution
func OSDistribution(origin, osFamily string) {
	osDistribution.WithLabelValues(origin, osFamily).Inc()
}

// DNS Cache Metrics and Functions are in metric_cache.go

// Streaming proxy metrics

var (
	streamingRequestsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_streaming_requests_total",
		Help: "Total number of streaming requests (SSE, gRPC, etc.)",
	}, []string{"origin", "method"}))

	protocolDetectionTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_protocol_detection_total",
		Help: "Total number of requests by detected protocol",
	}, []string{"protocol"}))

	flushStrategyTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_flush_strategy_total",
		Help: "Total number of requests by flush strategy",
	}, []string{"origin", "strategy", "reason"}))

	headerCompressionRatio = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_header_compression_ratio",
		Help:    "Header compression ratio (HTTP/2 HPACK, HTTP/3 QPACK)",
		Buckets: prometheus.LinearBuckets(0, 0.1, 11), // 0.0 to 1.0
	}, []string{"origin", "protocol"}))

	headerSizeBytes = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_header_size_bytes",
		Help:    "Distribution of header sizes",
		Buckets: prometheus.ExponentialBuckets(256, 2, 10), // 256B to 128KB
	}, []string{"origin", "direction", "protocol"}))

	// Trusted proxy metrics are in metric_security.go
)

// StreamingRequest records a streaming request
func StreamingRequest(origin, method string) {
	streamingRequestsTotal.WithLabelValues(origin, method).Inc()
}

// ProtocolDetection records protocol detection
func ProtocolDetection(protocol string) {
	protocolDetectionTotal.WithLabelValues(protocol).Inc()
}

// FlushStrategyUsage records flush strategy usage
func FlushStrategyUsage(origin, strategy, reason string) {
	flushStrategyTotal.WithLabelValues(origin, strategy, reason).Inc()
}

// HeaderCompressionRatio records header compression efficiency
func HeaderCompressionRatio(origin, protocol string, ratio float64) {
	headerCompressionRatio.WithLabelValues(origin, protocol).Observe(ratio)
}

// HeaderSize records header sizes
func HeaderSize(origin, direction, protocol string, size int64) {
	headerSizeBytes.WithLabelValues(origin, direction, protocol).Observe(float64(size))
}

// TrustedProxyValidation is in metric_security.go

// contractValidationErrors tracks contract validation errors
var contractValidationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "contract_validation_errors_total",
		Help: "Total contract validation errors by direction, path, and method",
	},
	[]string{"direction", "path", "method"},
))

// ContractValidationError records a contract validation error
func ContractValidationError(direction, path, method string) {
	contractValidationErrors.WithLabelValues(direction, path, method).Inc()
}

// FallbackTriggered records a fallback origin activation
func FallbackTriggered(originID, fallbackHostname, trigger string) {
	fallbackTriggeredTotal.WithLabelValues(originID, fallbackHostname, trigger).Inc()
}

// FallbackSuccess records a successful fallback origin response
func FallbackSuccess(originID, fallbackHostname string) {
	fallbackSuccessTotal.WithLabelValues(originID, fallbackHostname).Inc()
}

// FallbackFailure records a failed fallback origin attempt
func FallbackFailure(originID, fallbackHostname, reason string) {
	fallbackFailureTotal.WithLabelValues(originID, fallbackHostname, reason).Inc()
}

// FallbackLatency records fallback origin latency
func FallbackLatency(originID, fallbackHostname string, duration float64) {
	fallbackLatency.WithLabelValues(originID, fallbackHostname).Observe(duration)
}

// Per-workspace metrics for K8s operator promotion/demotion decisions
var (
	workspaceRequestsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_workspace_requests_total",
		Help: "Total requests per workspace",
	}, []string{"workspace_id", "status_code"}))

	workspaceRequestDuration = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_workspace_request_duration_seconds",
		Help:    "Request duration per workspace",
		Buckets: prometheus.DefBuckets,
	}, []string{"workspace_id"}))

	workspaceActiveConnections = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_workspace_active_connections",
		Help: "Current active connections per workspace",
	}, []string{"workspace_id"}))

	workspaceMode = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_workspace_mode",
		Help: "Proxy workspace mode info (1 = active)",
	}, []string{"mode", "workspace_id"}))
)

// WorkspaceRequest records a request for a workspace with status code
func WorkspaceRequest(workspaceID, statusCode string) {
	if workspaceID == "" {
		return
	}
	workspaceRequestsTotal.WithLabelValues(workspaceID, statusCode).Inc()
}

// WorkspaceRequestDuration records request duration for a workspace
func WorkspaceRequestDuration(workspaceID string, duration float64) {
	if workspaceID == "" {
		return
	}
	workspaceRequestDuration.WithLabelValues(workspaceID).Observe(duration)
}

// WorkspaceActiveConnectionInc increments active connections for a workspace
func WorkspaceActiveConnectionInc(workspaceID string) {
	if workspaceID == "" {
		return
	}
	workspaceActiveConnections.WithLabelValues(workspaceID).Inc()
}

// WorkspaceActiveConnectionDec decrements active connections for a workspace
func WorkspaceActiveConnectionDec(workspaceID string) {
	if workspaceID == "" {
		return
	}
	workspaceActiveConnections.WithLabelValues(workspaceID).Dec()
}

// SetWorkspaceMode sets the workspace mode info metric
func SetWorkspaceMode(mode, workspaceID string) {
	workspaceMode.WithLabelValues(mode, workspaceID).Set(1)
}

// Bot detection metrics are in metric_security.go

// Connection and pool metrics

var maxConnectionsRejectedTotal = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
	Name: "proxy_max_connections_rejected_total",
	Help: "Total requests rejected because the max connections semaphore was full and context was cancelled",
}))

var poolOversizedDiscardsTotal = mustRegisterCounter(prometheus.NewCounter(prometheus.CounterOpts{
	Name: "proxy_pool_oversized_discards_total",
	Help: "Total buffers discarded instead of returned to the pool because they exceeded MaxPoolBufferSize",
}))

// BotDetection is in metric_security.go

// MaxConnectionsRejected increments the counter when a request is rejected
// because the max connections semaphore was full and the context was cancelled.
func MaxConnectionsRejected() {
	maxConnectionsRejectedTotal.Inc()
}

// PoolOversizedDiscard increments the counter when a buffer is discarded
// instead of returned to the pool because it exceeds MaxPoolBufferSize.
func PoolOversizedDiscard() {
	poolOversizedDiscardsTotal.Inc()
}
