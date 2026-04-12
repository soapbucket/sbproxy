// config.go defines the configuration struct for the GraphQL action.
package graphql

import (
	pkgconfig "github.com/soapbucket/sbproxy/pkg/config"
	pkgtransport "github.com/soapbucket/sbproxy/pkg/transport"
)

// Config holds the full configuration for the graphql action.
// Duration fields accept JSON strings like "30s", "5m", "1h".
type Config struct {
	// Connection settings (mirrors BaseConnection).
	SkipTLSVerifyHost      bool   `json:"skip_tls_verify_host,omitempty"`
	MinTLSVersion          string `json:"min_tls_version,omitempty"`
	HTTP11Only             bool   `json:"http11_only,omitempty"`
	EnableHTTP3            bool   `json:"enable_http3,omitempty"`
	DisableCompression     bool   `json:"disable_compression,omitempty"`
	DisableFollowRedirects bool   `json:"disable_follow_redirects,omitempty"`
	MaxRedirects           int    `json:"max_redirects,omitempty"`

	Timeout             pkgconfig.Duration `json:"timeout,omitempty"`
	Delay               pkgconfig.Duration `json:"delay,omitempty"`
	DialTimeout         pkgconfig.Duration `json:"dial_timeout,omitempty"`
	TLSHandshakeTimeout pkgconfig.Duration `json:"tls_handshake_timeout,omitempty"`
	IdleConnTimeout     pkgconfig.Duration `json:"idle_conn_timeout,omitempty"`
	KeepAlive           pkgconfig.Duration `json:"keep_alive,omitempty"`
	FlushInterval       pkgconfig.Duration `json:"flush_interval,omitempty"`

	ResponseHeaderTimeout pkgconfig.Duration `json:"response_header_timeout,omitempty"`
	ExpectContinueTimeout pkgconfig.Duration `json:"expect_continue_timeout,omitempty"`

	MaxConnections      int `json:"max_connections,omitempty"`
	MaxIdleConns        int `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost     int `json:"max_conns_per_host,omitempty"`

	WriteBufferSize int `json:"write_buffer_size,omitempty"`
	ReadBufferSize  int `json:"read_buffer_size,omitempty"`

	RateLimit  int `json:"rate_limit,omitempty"`
	BurstLimit int `json:"burst_limit,omitempty"`

	MTLSClientCertFile string `json:"mtls_client_cert_file,omitempty"`
	MTLSClientKeyFile  string `json:"mtls_client_key_file,omitempty"`
	MTLSCACertFile     string `json:"mtls_ca_cert_file,omitempty"`
	MTLSClientCertData string `json:"mtls_client_cert_data,omitempty"`
	MTLSClientKeyData  string `json:"mtls_client_key_data,omitempty"`
	MTLSCACertData     string `json:"mtls_ca_cert_data,omitempty"`

	// GraphQL-specific fields.
	URL                       string                     `json:"url"`
	MaxDepth                  int                        `json:"max_depth,omitempty"`
	MaxComplexity             int                        `json:"max_complexity,omitempty"`
	MaxCost                   int                        `json:"max_cost,omitempty"`
	MaxAliases                int                        `json:"max_aliases,omitempty"`
	EnableIntrospection       bool                       `json:"enable_introspection,omitempty"`
	PersistentQueriesMap      map[string]string          `json:"persistent_queries_map,omitempty"`
	AutomaticPersistedQueries bool                       `json:"automatic_persisted_queries,omitempty"`
	APQCacheSize              int                        `json:"apq_cache_size,omitempty"`
	QueryCacheSize            int                        `json:"query_cache_size,omitempty"`
	FieldCosts                map[string]int             `json:"field_costs,omitempty"`
	TypeCosts                 map[string]int             `json:"type_costs,omitempty"`
	FieldRateLimits           map[string]*FieldRateLimit `json:"field_rate_limits,omitempty"`

	// Query optimization.
	EnableQueryBatching      bool               `json:"enable_query_batching,omitempty"`
	EnableQueryDeduplication bool               `json:"enable_query_deduplication,omitempty"`
	EnableResultCaching      bool               `json:"enable_result_caching,omitempty"`
	ResultCacheSize          int                `json:"result_cache_size,omitempty"`
	ResultCacheTTL           pkgconfig.Duration `json:"result_cache_ttl,omitempty"`
	MaxBatchSize             int                `json:"max_batch_size,omitempty"`
	EnableOptimizationHints  bool               `json:"enable_optimization_hints,omitempty"`

	// Per-operation rate limiting.
	QueryRateLimit        *OperationRateLimit `json:"query_rate_limit,omitempty"`
	MutationRateLimit     *OperationRateLimit `json:"mutation_rate_limit,omitempty"`
	SubscriptionRateLimit *OperationRateLimit `json:"subscription_rate_limit,omitempty"`
}

// FieldRateLimit defines rate limiting for specific GraphQL fields.
type FieldRateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int `json:"requests_per_hour,omitempty"`
}

// OperationRateLimit defines per-operation-type rate limiting.
type OperationRateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int `json:"requests_per_hour,omitempty"`
}

// Request represents an inbound GraphQL request.
type Request struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	Extensions    map[string]interface{} `json:"extensions,omitempty"`
}

// Response represents a GraphQL response.
type Response struct {
	Data       interface{}            `json:"data,omitempty"`
	Errors     []interface{}          `json:"errors,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// connectionConfig converts Config into pkgtransport.ConnectionConfig.
func (c *Config) connectionConfig() pkgtransport.ConnectionConfig {
	timeout := c.Timeout.Duration
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return pkgtransport.ConnectionConfig{
		SkipTLSVerifyHost:      c.SkipTLSVerifyHost,
		MinTLSVersion:          c.MinTLSVersion,
		HTTP11Only:             c.HTTP11Only,
		EnableHTTP3:            c.EnableHTTP3,
		DisableCompression:     c.DisableCompression,
		DisableFollowRedirects: c.DisableFollowRedirects,
		MaxRedirects:           c.MaxRedirects,
		Timeout:                timeout,
		Delay:                  c.Delay.Duration,
		DialTimeout:            c.DialTimeout.Duration,
		TLSHandshakeTimeout:    c.TLSHandshakeTimeout.Duration,
		IdleConnTimeout:        c.IdleConnTimeout.Duration,
		KeepAlive:              c.KeepAlive.Duration,
		FlushInterval:          c.FlushInterval.Duration,
		ResponseHeaderTimeout:  c.ResponseHeaderTimeout.Duration,
		ExpectContinueTimeout:  c.ExpectContinueTimeout.Duration,
		MaxConnections:         c.MaxConnections,
		MaxIdleConns:           c.MaxIdleConns,
		MaxIdleConnsPerHost:    c.MaxIdleConnsPerHost,
		MaxConnsPerHost:        c.MaxConnsPerHost,
		WriteBufferSize:        c.WriteBufferSize,
		ReadBufferSize:         c.ReadBufferSize,
		RateLimit:              c.RateLimit,
		BurstLimit:             c.BurstLimit,
		MTLSClientCertFile:     c.MTLSClientCertFile,
		MTLSClientKeyFile:      c.MTLSClientKeyFile,
		MTLSCACertFile:         c.MTLSCACertFile,
		MTLSClientCertData:     c.MTLSClientCertData,
		MTLSClientKeyData:      c.MTLSClientKeyData,
		MTLSCACertData:         c.MTLSCACertData,
	}
}
