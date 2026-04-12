// Package loadbalancer defines config types for the load_balancer action module.
//
// All struct and JSON field names match the canonical definitions in
// internal/config/types.go so that existing YAML/JSON configurations parse
// identically. When the old code is eventually removed, these become the
// sole source of truth.
package loadbalancer

// Config is the top-level load balancer action configuration.
// JSON tags must stay in sync with internal/config.LoadBalancerConfig.
type Config struct {
	Type string `json:"type"` // always "load_balancer"

	Targets []Target `json:"targets"`

	// Discovery enables dynamic upstream resolution. When set, Targets may be
	// empty and backends are discovered at runtime.
	Discovery *DiscoveryConfig `json:"discovery,omitempty"`

	// Algorithm selects the load balancing strategy: "weighted_random" (default),
	// "round_robin", "weighted_round_robin", "least_connections", "ip_hash",
	// "uri_hash", "header_hash", "cookie_hash", "random", or "first".
	Algorithm string `json:"algorithm,omitempty"`

	// HashKey is the header name or cookie name used by header_hash and cookie_hash.
	HashKey string `json:"hash_key,omitempty"`

	RoundRobin       bool `json:"round_robin,omitempty"`
	LeastConnections bool `json:"least_connections,omitempty"`
	DisableSticky    bool `json:"disable_sticky,omitempty"`

	StickyCookieName string `json:"sticky_cookie_name,omitempty"`

	StripBasePath bool `json:"strip_base_path,omitempty"`
	PreserveQuery bool `json:"preserve_query,omitempty"`
}

// Target represents a single backend in the load balancer pool.
type Target struct {
	URL    string `json:"url"`
	Weight int    `json:"weight,omitempty"`

	HealthCheck    *HealthCheckConfig    `json:"health_check,omitempty"`
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty"`

	// Connection-level fields (subset - extend as needed).
	SkipTLSVerifyHost bool `json:"skip_tls_verify_host,omitempty"`
}

// HealthCheckConfig defines health check parameters for a target.
type HealthCheckConfig struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Path     string `json:"path,omitempty"`
	Method   string `json:"method,omitempty"`

	ExpectedStatus []int `json:"expected_status,omitempty"`

	HealthyThreshold   int `json:"healthy_threshold,omitempty"`
	UnhealthyThreshold int `json:"unhealthy_threshold,omitempty"`
}

// CircuitBreakerConfig defines circuit breaker parameters for a target.
type CircuitBreakerConfig struct {
	Enabled bool `json:"enabled"`

	FailureThreshold       int `json:"failure_threshold,omitempty"`
	SuccessThreshold       int `json:"success_threshold,omitempty"`
	RequestVolumeThreshold int `json:"request_volume_threshold,omitempty"`

	Timeout     string `json:"timeout,omitempty"`
	SleepWindow string `json:"sleep_window,omitempty"`

	ErrorRateThreshold float64 `json:"error_rate_threshold,omitempty"`
	HalfOpenRequests   int     `json:"half_open_requests,omitempty"`
}

// DiscoveryConfig configures dynamic upstream resolution.
type DiscoveryConfig struct {
	Type            string `json:"type"`
	Service         string `json:"service,omitempty"`
	RefreshInterval string `json:"refresh_interval,omitempty"`
	Resolver        string `json:"resolver,omitempty"`
}
