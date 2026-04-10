// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/modifier"
	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	httputil "github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

var ()

func init() {
	loaderFns[TypeLoadBalancer] = LoadLoadBalancerConfig
}

// LoadBalancerTypedConfig represents the load balancer configuration
type LoadBalancerTypedConfig struct {
	LoadBalancerConfig

	tr http.RoundTripper `json:"-"`

	compiledTargets []*compiledTarget `json:"-"`
}

// setTransport sets the transport for the load balancer
func (l *LoadBalancerTypedConfig) setTransport(tr http.RoundTripper) {
	l.tr = tr
}

// Init performs the init operation on the LoadBalancerTypedConfig.
func (l *LoadBalancerTypedConfig) Init(cfg *Config) error {
	// we may want to pass in the manager here...
	// 1. handle all healthchecks with a work queue
	// 2. provide default values

	// Resolve sticky cookie configuration
	// Priority: LoadBalancer config > OriginConfig (from ServerConfig) > Default
	stickyCookieName := l.StickyCookieName
	if stickyCookieName == "" {
		stickyCookieName = DefaultStickyCookieName
	}

	// Create context for health checking
	healthCtx, healthCancel := context.WithCancel(context.Background())

	// Resolve the load balancing algorithm.
	// The Algorithm field takes precedence over legacy boolean flags.
	resolvedAlgorithm := l.Algorithm
	if resolvedAlgorithm == "" {
		// Fall back to legacy boolean flags
		if l.LeastConnections {
			resolvedAlgorithm = AlgorithmLeastConnections
		} else if l.RoundRobin {
			resolvedAlgorithm = AlgorithmRoundRobin
		} else {
			resolvedAlgorithm = AlgorithmWeightedRandom
		}
	}

	// Create load balancer transport
	// Fix 1.4: Use sync.Mutex-protected rand for thread-safety (rand.Rand is not thread-safe under RLock)
	lb := &loadBalancerTransport{
		targets:           l.compiledTargets,
		originID:          cfg.ID,
		originCfg:         cfg,
		random:            rand.New(rand.NewSource(time.Now().UnixNano())),
		stickyCookieName:  stickyCookieName,
		healthCheckCtx:    healthCtx,
		healthCheckCancel: healthCancel,
		algorithm:         resolvedAlgorithm,
		hashKey:           l.HashKey,
		leastConnections:  l.LeastConnections,
		disableSticky:     l.DisableSticky,
		useRoundRobin:     l.RoundRobin,
		stripBasePath:     l.StripBasePath,
		preserveQuery:     l.PreserveQuery,
	}

	// Set originID on all circuit breakers
	for _, target := range l.compiledTargets {
		if target.circuitBreaker != nil {
			target.circuitBreaker.originID = cfg.ID
			target.circuitBreaker.cfg = cfg
		}
	}

	// Set transport before starting health checkers (removed circular dependency)
	l.setTransport(lb)

	// Start health checkers for each target
	for i, target := range l.compiledTargets {
		if target.Config.HealthCheck != nil && target.Config.HealthCheck.Enabled {
			target.startHealthChecker(healthCtx, cfg.ID, i, target.Config.HealthCheck, cfg)
		}
	}

	return nil
}

// Close stops all health check goroutines for this load balancer.
// This should be called when the configuration is reloaded or the proxy shuts down
// to ensure background goroutines are properly cleaned up.
func (l *LoadBalancerTypedConfig) Close() {
	if l.tr == nil {
		return
	}
	if lb, ok := l.tr.(*loadBalancerTransport); ok && lb.healthCheckCancel != nil {
		lb.healthCheckCancel()
	}
}

// Transport performs the transport operation on the LoadBalancerTypedConfig.
func (l *LoadBalancerTypedConfig) Transport() TransportFn {
	return func(req *http.Request) (*http.Response, error) {
		return l.tr.RoundTrip(req)
	}
}

// IsProxy reports whether the LoadBalancerTypedConfig is proxy.
func (l *LoadBalancerTypedConfig) IsProxy() bool {
	result := l.tr != nil
	if !result {
		slog.Debug("LoadBalancerTypedConfig.IsProxy() returning false",
			"tr_is_nil", l.tr == nil,
			"compiled_targets_count", len(l.compiledTargets))
	}
	return result
}

// Handler performs the handler operation on the LoadBalancerTypedConfig.
func (l *LoadBalancerTypedConfig) Handler() http.Handler {
	// Load balancer uses proxy mode, not handler mode
	// Return nil to ensure Config.Handler() creates the default handler
	// which will check IsProxy() and use proxy mode instead
	return nil
}

// ApplyHTTPSProxyProfile performs the apply https proxy profile operation on the LoadBalancerTypedConfig.
func (l *LoadBalancerTypedConfig) ApplyHTTPSProxyProfile(profile *HTTPSProxyAction) {
	if l == nil || profile == nil {
		return
	}
	for i := range l.Targets {
		target := &l.Targets[i]
		target.SkipTLSVerifyHost = !profile.TLS.VerifyCertificate
		target.MinTLSVersion = profile.TLS.MinVersion
		target.CertificatePinning = profile.CertificatePinning
		if profile.MTLSClientCertFile != "" {
			target.MTLSClientCertFile = profile.MTLSClientCertFile
			target.MTLSClientKeyFile = profile.MTLSClientKeyFile
			target.MTLSCACertFile = profile.MTLSCACertFile
		}
		if profile.MTLSClientCertData != "" {
			target.MTLSClientCertData = profile.MTLSClientCertData
			target.MTLSClientKeyData = profile.MTLSClientKeyData
			target.MTLSCACertData = profile.MTLSCACertData
		}
		if i < len(l.compiledTargets) && l.compiledTargets[i] != nil {
			l.compiledTargets[i].Config.BaseConnection = target.BaseConnection
			l.compiledTargets[i].Transport = ClientConnectionTransportFn(&target.BaseConnection)
		}
	}
}

// signTargetIndex creates an HMAC-signed cookie value for target index
// Format: "index.signature" (e.g., "2.a3f5b9c1d2e4f678")
func signTargetIndex(targetIndex int, secret string) string {
	if secret == "" {
		// If no secret, just return the index (insecure but functional)
		return strconv.Itoa(targetIndex)
	}

	data := strconv.Itoa(targetIndex)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	signature := hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for brevity
	return fmt.Sprintf("%d.%s", targetIndex, signature)
}

// verifyAndExtractTargetIndex verifies HMAC signature and extracts target index
// Returns target index and whether verification succeeded
func verifyAndExtractTargetIndex(cookieValue string, secret string, maxTargets int) (int, bool) {
	if cookieValue == "" {
		return -1, false
	}

	// Handle case with no secret (backward compatibility)
	if secret == "" {
		if idx, err := strconv.Atoi(cookieValue); err == nil && idx >= 0 && idx < maxTargets {
			return idx, true
		}
		return -1, false
	}

	// Parse format: "index.signature"
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 2 {
		return -1, false
	}

	targetIndex, err := strconv.Atoi(parts[0])
	if err != nil || targetIndex < 0 || targetIndex >= maxTargets {
		return -1, false
	}

	// Verify signature
	expectedSigned := signTargetIndex(targetIndex, secret)
	if !hmac.Equal([]byte(cookieValue), []byte(expectedSigned)) {
		slog.Warn("sticky cookie signature mismatch",
			logging.FieldCaller, "config:verifyAndExtractTargetIndex",
			"cookie_value", cookieValue)
		return -1, false
	}

	return targetIndex, true
}

// healthStatus tracks the health state of a target
type healthStatus struct {
	healthy              atomic.Bool
	consecutiveSuccesses int64 // atomic counter
	consecutiveFailures  int64 // atomic counter
	lastCheckTime        time.Time
	lastError            string
	mu                   sync.RWMutex
}

// circuitBreaker tracks circuit breaker state for a target
type circuitBreaker struct {
	state           atomic.Value // string: closed, open, half_open
	failures        atomic.Int64 // failure count
	successes       atomic.Int64 // success count
	requests        atomic.Int64 // total request count
	lastStateChange time.Time
	mu              sync.RWMutex

	// Configuration
	config           *CircuitBreakerConfig
	targetURL        string
	targetIndex      string
	originID         string // origin ID for metrics
	cfg              *Config
	halfOpenAttempts atomic.Int32 // counter for half-open test requests
}

// newCircuitBreaker creates a new circuit breaker
func newCircuitBreaker(config *CircuitBreakerConfig, targetURL, targetIndex string) *circuitBreaker {
	if config == nil || !config.Enabled {
		return nil
	}

	cb := &circuitBreaker{
		config:          config,
		targetURL:       targetURL,
		targetIndex:     targetIndex,
		originID:        "", // Will be set when circuit breaker is associated with origin
		lastStateChange: time.Now(),
	}
	cb.state.Store(CircuitBreakerStateClosed)

	return cb
}

// getState returns the current circuit breaker state
func (cb *circuitBreaker) getState() string {
	if cb == nil {
		return CircuitBreakerStateClosed // No circuit breaker = always closed
	}
	return cb.state.Load().(string)
}

// isOpen returns true if the circuit is open
func (cb *circuitBreaker) isOpen() bool {
	if cb == nil {
		return false
	}

	state := cb.getState()

	// If open, check if timeout has elapsed to transition to half-open
	if state == CircuitBreakerStateOpen {
		cb.mu.RLock()
		elapsed := time.Since(cb.lastStateChange)
		cb.mu.RUnlock()

		timeout := cb.config.Timeout.Duration
		if timeout == 0 {
			timeout = cb.config.SleepWindow.Duration
		}
		if timeout == 0 {
			timeout = DefaultCircuitBreakerTimeout
		}

		if elapsed >= timeout {
			// Transition to half-open
			cb.transitionTo(CircuitBreakerStateHalfOpen)
			return false
		}
		return true
	}

	return false
}

// recordSuccess records a successful request
func (cb *circuitBreaker) recordSuccess() {
	if cb == nil {
		return
	}

	cb.requests.Add(1)
	cb.successes.Add(1)

	state := cb.getState()

	if state == CircuitBreakerStateHalfOpen {
		// In half-open, track successes for transition back to closed
		successThreshold := cb.config.SuccessThreshold
		if successThreshold == 0 {
			successThreshold = DefaultCircuitBreakerSuccessThreshold
		}

		halfOpenAttempts := cb.halfOpenAttempts.Add(1)

		if halfOpenAttempts >= int32(successThreshold) {
			// Enough successes, close the circuit
			cb.transitionTo(CircuitBreakerStateClosed)
		}
	}
}

// recordFailure records a failed request
func (cb *circuitBreaker) recordFailure() {
	if cb == nil {
		return
	}

	cb.requests.Add(1)
	cb.failures.Add(1)

	state := cb.getState()

	if state == CircuitBreakerStateHalfOpen {
		// In half-open, any failure opens the circuit again
		cb.transitionTo(CircuitBreakerStateOpen)
		return
	}

	if state == CircuitBreakerStateClosed {
		// Check if we should open the circuit
		cb.checkThresholds()
	}
}

// checkThresholds evaluates whether to open the circuit
func (cb *circuitBreaker) checkThresholds() {
	requests := cb.requests.Load()
	failures := cb.failures.Load()

	// Check minimum request volume
	requestVolumeThreshold := int64(cb.config.RequestVolumeThreshold)
	if requestVolumeThreshold == 0 {
		requestVolumeThreshold = DefaultCircuitBreakerRequestVolumeThreshold
	}

	if requests < requestVolumeThreshold {
		return // Not enough requests to make a decision
	}

	// Check failure threshold
	failureThreshold := int64(cb.config.FailureThreshold)
	if failureThreshold == 0 {
		failureThreshold = DefaultCircuitBreakerFailureThreshold
	}

	if failures >= failureThreshold {
		cb.transitionTo(CircuitBreakerStateOpen)
		return
	}

	// Check error rate threshold
	errorRateThreshold := cb.config.ErrorRateThreshold
	if errorRateThreshold == 0 {
		errorRateThreshold = DefaultCircuitBreakerErrorRateThreshold
	}

	errorRate := float64(failures) / float64(requests)
	if errorRate >= errorRateThreshold {
		cb.transitionTo(CircuitBreakerStateOpen)
	}
}

// transitionTo transitions the circuit breaker to a new state
func (cb *circuitBreaker) transitionTo(newState string) {
	oldState := cb.getState()

	if oldState == newState {
		return
	}

	cb.mu.Lock()
	cb.state.Store(newState)
	cb.lastStateChange = time.Now()
	cb.mu.Unlock()

	// Reset counters on state change
	if newState == CircuitBreakerStateClosed {
		cb.failures.Store(0)
		cb.successes.Store(0)
		cb.requests.Store(0)
		cb.halfOpenAttempts.Store(0)
	} else if newState == CircuitBreakerStateHalfOpen {
		cb.halfOpenAttempts.Store(0)
	}

	slog.Info("circuit breaker state changed",
		"target_url", cb.targetURL,
		"target_index", cb.targetIndex,
		"old_state", oldState,
		"new_state", newState,
		"failures", cb.failures.Load(),
		"requests", cb.requests.Load())

	// Record circuit breaker state change metric
	origin := "unknown"
	if cb.originID != "" {
		origin = cb.originID
	}
	metric.LBCircuitBreakerStateChanged(origin, cb.targetURL, cb.targetIndex, newState)
	switch newState {
	case CircuitBreakerStateOpen:
		emitTypedCircuitEvent(cb.cfg, "upstream.circuit_opened", events.SeverityWarning, cb.targetURL, int(cb.failures.Load()), int(DefaultCircuitBreakerTimeout.Seconds()), 0)
	case CircuitBreakerStateClosed:
		emitTypedCircuitEvent(cb.cfg, "upstream.circuit_closed", events.SeverityInfo, cb.targetURL, 0, 0, 0)
	}
}

// isHealthy returns whether the target is currently healthy
func (h *healthStatus) isHealthy() bool {
	return h.healthy.Load()
}

// markHealthy marks the target as healthy
func (h *healthStatus) markHealthy(originID, targetURL, targetIndex string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.healthy.Load() {
		h.healthy.Store(true)
		atomic.StoreInt64(&h.consecutiveFailures, 0)
		// Record upstream availability metric
		metric.UpstreamAvailabilitySet(originID, targetURL, true)
	}
	atomic.AddInt64(&h.consecutiveSuccesses, 1)
	h.lastCheckTime = time.Now()
	h.lastError = ""

	// Record health check status gauge
	metric.LBTargetHealthSet(originID, targetURL, targetIndex, true)
}

// markUnhealthy marks the target as unhealthy with an error message
func (h *healthStatus) markUnhealthy(originID, targetURL, targetIndex string, err string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.healthy.Load() {
		h.healthy.Store(false)
		atomic.StoreInt64(&h.consecutiveSuccesses, 0)
		// Record upstream availability metric
		metric.UpstreamAvailabilitySet(originID, targetURL, false)
	}
	atomic.AddInt64(&h.consecutiveFailures, 1)
	h.lastCheckTime = time.Now()
	h.lastError = err

	// Record health check failure metric
	metric.LBHealthCheckPerformed(originID, targetURL, targetIndex, "failure")

	// Record health check status gauge
	metric.LBTargetHealthSet(originID, targetURL, targetIndex, false)
}

// getStatus returns the current health status for logging/debugging
func (h *healthStatus) getStatus() (bool, int64, int64, time.Time, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.healthy.Load(),
		atomic.LoadInt64(&h.consecutiveSuccesses),
		atomic.LoadInt64(&h.consecutiveFailures),
		h.lastCheckTime,
		h.lastError
}

// compiledTarget represents a compiled load balancer target
type compiledTarget struct {
	Config    *Target
	URL       *url.URL
	Transport http.RoundTripper

	RequestModifiers  modifier.RequestModifiers
	ResponseModifiers modifier.ResponseModifiers

	RequestMatchers rule.RequestRules

	// Connection tracking for least connections algorithm
	activeConnections int64 // atomic counter

	// Health checking
	health *healthStatus

	// Circuit breaker
	circuitBreaker *circuitBreaker
}

// performHealthCheck performs a single health check on the target
func (t *compiledTarget) performHealthCheck(ctx context.Context, config *HealthCheckConfig) error {
	// Build health check URL
	healthURL := *t.URL
	if config.Path != "" {
		healthURL.Path = config.Path
	} else {
		healthURL.Path = DefaultHealthCheckPath
	}

	method := config.Method
	if method == "" {
		method = DefaultHealthCheckMethod
	}

	// Create health check request
	req, err := http.NewRequestWithContext(ctx, method, healthURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	// Set timeout
	timeout := config.Timeout.Duration
	if timeout == 0 {
		timeout = DefaultHealthCheckTimeout
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(timeoutCtx)

	// Perform health check
	client := &http.Client{
		Transport: t.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check if status code is expected
	expectedStatus := config.ExpectedStatus
	if len(expectedStatus) == 0 {
		// Default: accept 200-299
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Check against expected status codes
	for _, expected := range expectedStatus {
		if resp.StatusCode == expected {
			return nil
		}
	}

	return fmt.Errorf("status code %d not in expected list", resp.StatusCode)
}

// startHealthChecker starts the health checking loop for this target
func (t *compiledTarget) startHealthChecker(ctx context.Context, originID string, targetIndex int, config *HealthCheckConfig, originCfg *Config) {
	if config == nil || !config.Enabled {
		return
	}

	interval := config.Interval.Duration
	if interval == 0 {
		interval = DefaultHealthCheckInterval
	}

	healthyThreshold := config.HealthyThreshold
	if healthyThreshold == 0 {
		healthyThreshold = DefaultHealthyThreshold
	}

	unhealthyThreshold := config.UnhealthyThreshold
	if unhealthyThreshold == 0 {
		unhealthyThreshold = DefaultUnhealthyThreshold
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		targetURL := t.URL.String()
		targetIndexStr := strconv.Itoa(targetIndex)

		slog.Info("starting health checker", "origin_id", originID, "target_index", targetIndex, "url", targetURL, "interval", interval)

		// Perform initial health check immediately
		if err := t.performHealthCheck(ctx, config); err != nil {
			slog.Warn("initial health check failed", "origin_id", originID, "target_index", targetIndex, "error", err)
			t.health.markUnhealthy(originID, targetURL, targetIndexStr, err.Error())
		} else {
			slog.Debug("initial health check passed", "origin_id", originID, "target_index", targetIndex)
			t.health.markHealthy(originID, targetURL, targetIndexStr)
			// Record successful health check
			metric.LBHealthCheckPerformed(originID, targetURL, targetIndexStr, "success")
		}

		for {
			select {
			case <-ctx.Done():
				slog.Info("stopping health checker", "origin_id", originID, "target_index", targetIndex)
				return
			case <-ticker.C:
				err := t.performHealthCheck(ctx, config)

				wasHealthy := t.health.isHealthy()

				if err != nil {
					t.health.markUnhealthy(originID, targetURL, targetIndexStr, err.Error())
					failures := atomic.LoadInt64(&t.health.consecutiveFailures)

					if wasHealthy && failures >= int64(unhealthyThreshold) {
						slog.Warn("target marked unhealthy", "origin_id", originID, "target_index", targetIndex, "url", targetURL, "consecutive_failures", failures, "error", err)
						emitHealthChange(originCfg, targetURL, "unhealthy")
					} else {
						slog.Debug("health check failed", "origin_id", originID, "target_index", targetIndex, "consecutive_failures", failures, "error", err)
					}
				} else {
					t.health.markHealthy(originID, targetURL, targetIndexStr)
					successes := atomic.LoadInt64(&t.health.consecutiveSuccesses)

					if !wasHealthy && successes >= int64(healthyThreshold) {
						slog.Info("target marked healthy", "origin_id", originID, "target_index", targetIndex, "url", targetURL, "consecutive_successes", successes)
						emitHealthChange(originCfg, targetURL, "healthy")
					} else {
						slog.Debug("health check passed", "origin_id", originID, "target_index", targetIndex, "consecutive_successes", successes)
					}
				}
			}
		}
	}()
}

// LoadLoadBalancerConfig performs the load load balancer config operation.
func LoadLoadBalancerConfig(data []byte) (ActionConfig, error) {
	var lbCfg LoadBalancerConfig
	if err := json.Unmarshal(data, &lbCfg); err != nil {
		return nil, err
	}

	// Validate algorithm if specified
	if lbCfg.Algorithm != "" {
		switch lbCfg.Algorithm {
		case AlgorithmWeightedRandom, AlgorithmRoundRobin, AlgorithmWeightedRoundRobin, AlgorithmLeastConnections,
			AlgorithmIPHash, AlgorithmURIHash, AlgorithmRandom, AlgorithmFirst:
			// valid
		case AlgorithmHeaderHash, AlgorithmCookieHash:
			if lbCfg.HashKey == "" {
				return nil, fmt.Errorf("load balancer algorithm %q requires a non-empty hash_key", lbCfg.Algorithm)
			}
		default:
			return nil, fmt.Errorf("invalid load balancer algorithm %q: must be one of weighted_random, round_robin, weighted_round_robin, least_connections, ip_hash, uri_hash, header_hash, cookie_hash, random, first", lbCfg.Algorithm)
		}
	}

	// Validate targets
	if len(lbCfg.Targets) == 0 {
		return nil, ErrNoTargets
	}

	compiledTargets := make([]*compiledTarget, len(lbCfg.Targets))
	for i, target := range lbCfg.Targets {
		compiled, err := compileTarget(&target, i)
		if err != nil {
			slog.Error("failed to compile target", "target_index", i, "error", err)
			return nil, err
		}
		compiledTargets[i] = compiled
	}

	typedCfg := &LoadBalancerTypedConfig{
		LoadBalancerConfig: lbCfg,

		compiledTargets: compiledTargets,
	}

	return typedCfg, nil
}

// compileTarget compiles a single target configuration
func compileTarget(target *Target, index int) (*compiledTarget, error) {
	// Validate and parse URL
	if target.URL == "" {
		return nil, ErrInvalidTargetURL
	}

	targetURL, err := url.Parse(target.URL)
	if err != nil || targetURL.Scheme == "" {
		slog.Error("invalid target URL", "target_index", index, "url", target.URL, "error", err)
		return nil, ErrInvalidTargetURL
	}

	tr := ClientConnectionTransportFn(&target.BaseConnection)

	// Initialize health status (starts as healthy)
	health := &healthStatus{}
	health.healthy.Store(true) // Assume healthy until first check

	// Initialize circuit breaker
	targetIndexStr := strconv.Itoa(index)
	circuitBreaker := newCircuitBreaker(target.CircuitBreaker, targetURL.String(), targetIndexStr)
	// Note: originID will be set when load balancer transport is created

	return &compiledTarget{
		Config:            target,
		URL:               targetURL,
		Transport:         tr,
		RequestModifiers:  target.RequestModifiers,
		ResponseModifiers: target.ResponseModifiers,
		RequestMatchers:   target.RequestMatchers,
		health:            health,
		activeConnections: 0,
		circuitBreaker:    circuitBreaker,
	}, nil
}

// loadBalancerTransport implements load balancing logic
type loadBalancerTransport struct {
	targets            []*compiledTarget
	roundRobin         int64 // atomic counter for round robin
	originID           string
	originCfg          *Config
	random             *rand.Rand
	mu                 sync.RWMutex
	stickyCookieName   string // Resolved sticky cookie name
	stickyCookieSecret string // Resolved sticky cookie secret
	healthCheckCtx     context.Context
	healthCheckCancel  context.CancelFunc

	// Config flags (copied from LoadBalancerTypedConfig to avoid circular reference)
	algorithm        string // resolved algorithm: one of the Algorithm* constants
	leastConnections bool   // legacy flag, used when algorithm is empty
	disableSticky    bool
	useRoundRobin    bool // legacy flag, used when algorithm is empty
	stripBasePath    bool // If true, use request path; if false, use target URL path
	preserveQuery    bool // If true, use only request query; if false, merge target URL query with request query

	// hashKey is the header/cookie name used by header_hash and cookie_hash algorithms
	hashKey string

	// Weighted round-robin state
	wrrIndex   int64 // atomic: current target index for weighted round-robin
	wrrCounter int64 // atomic: remaining count for current target
}

// RoundTrip performs the round trip operation on the loadBalancerTransport.
func (lb *loadBalancerTransport) RoundTrip(req *http.Request) (*http.Response, error) {

	// Select target
	targetIndex := lb.selectTarget(req)
	if targetIndex < 0 {
		// All targets are unhealthy or no valid target found
		slog.Error("all targets unhealthy, returning 503", "origin_id", lb.originID)
		return nil, ErrAllTargetsUnhealthy
	}
	if targetIndex >= len(lb.targets) {
		slog.Error("invalid target index", "origin_id", lb.originID, "index", targetIndex)
		return nil, ErrLoadBalancerTargetNotFound
	}
	target := lb.targets[targetIndex]

	// Record load balancer target distribution
	targetURLStr := target.URL.String()
	metric.LBTargetDistribution(lb.originID, targetURLStr, 1.0)

	// Track connection for least connections algorithm
	if lb.algorithm == AlgorithmLeastConnections || lb.leastConnections {
		atomic.AddInt64(&target.activeConnections, 1)
		// Fix 1.5: Decrement activeConnections when request completes (defer ensures it runs even on error)
		defer atomic.AddInt64(&target.activeConnections, -1)
	}

	// Clone request for this target
	reqCopy := req.Clone(req.Context())

	// Build target URL based on StripBasePath and PreserveQuery settings
	targetURL := &url.URL{
		Scheme: target.URL.Scheme,
		Host:   target.URL.Host,
	}

	// Handle path based on StripBasePath setting
	if lb.stripBasePath {
		// Use request path (default behavior for load balancers)
		targetURL.Path = req.URL.Path
	} else {
		// Use target URL path, or append request path to it
		// If incoming path is "/" and target URL has a path, use target path only (don't append "/")
		if req.URL.Path == "/" && target.URL.Path != "" && target.URL.Path != "/" {
			targetURL.Path = target.URL.Path
		} else {
			targetURL.Path = target.URL.Path + req.URL.Path
		}
	}

	// Handle query parameters based on PreserveQuery setting
	if lb.preserveQuery {
		// Use only the incoming query parameters
		targetURL.RawQuery = req.URL.RawQuery
	} else {
		// Merge query parameters from both target URL and incoming request
		// Target URL params take precedence (e.g., backend=1 from config)
		if req.URL.RawQuery != "" || target.URL.RawQuery != "" {
			query := target.URL.Query()
			for k, vs := range req.URL.Query() {
				for _, v := range vs {
					query.Add(k, v)
				}
			}
			targetURL.RawQuery = query.Encode()
		}
	}

	targetURL.Fragment = req.URL.Fragment

	reqCopy.URL = targetURL
	reqCopy.Host = target.URL.Host
	reqCopy.Header.Set(httputil.HeaderHost, target.URL.Host)

	// Apply target-specific request modifiers

	if err := target.RequestModifiers.Apply(reqCopy); err != nil {
		slog.Error("failed to apply target request modifiers", "origin_id", lb.originID, "target_index", targetIndex, "error", err)
		return nil, err
	}

	// Measure upstream response time
	startTime := time.Now()

	// Execute request
	resp, err := target.Transport.RoundTrip(reqCopy)

	// Calculate upstream response time
	upstreamDuration := time.Since(startTime).Seconds()

	if err != nil {
		slog.Error("target request failed", "origin_id", lb.originID, "target_index", targetIndex, "error", err)

		// Record upstream response time with error status
		targetHost := target.URL.Host
		if targetHost == "" {
			targetHost = "unknown"
		}
		metric.UpstreamResponseTime(lb.originID, targetHost, 0, upstreamDuration)

		// Check if error is a timeout
		ctxErr := reqCopy.Context().Err()
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") || ctxErr == context.DeadlineExceeded {
			timeoutType := "request_timeout"
			upstream := target.URL.Host
			if upstream == "" {
				upstream = "unknown"
			}
			metric.RequestTimeout(lb.originID, timeoutType, upstream)
			emitUpstreamTimeout(reqCopy.Context(), lb.originCfg, reqCopy, targetURL.String(), 0)
		}

		// Record circuit breaker failure
		if target.circuitBreaker != nil {
			target.circuitBreaker.recordFailure()
		}
		return nil, err
	}

	if err := target.ResponseModifiers.Apply(resp); err != nil {
		slog.Error("failed to apply target response modifiers", "origin_id", lb.originID, "target_index", targetIndex, "error", err)
		return nil, err
	}

	// Record upstream response time metric
	targetHost := target.URL.Host
	if targetHost == "" {
		targetHost = "unknown"
	}
	metric.UpstreamResponseTime(lb.originID, targetHost, resp.StatusCode, upstreamDuration)
	if resp.StatusCode >= 500 {
		emitUpstream5xx(reqCopy.Context(), lb.originCfg, reqCopy, targetURL.String(), resp.StatusCode, int64(upstreamDuration*1000))
	}

	// Record circuit breaker success/failure based on status code
	if target.circuitBreaker != nil {
		// Consider 5xx errors as failures, everything else as success
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			target.circuitBreaker.recordFailure()
		} else {
			target.circuitBreaker.recordSuccess()
		}
	}

	// Set sticky session cookie (if enabled and not already present)
	if !lb.disableSticky && lb.stickyCookieName != "" {
		// Check if cookie already exists and is valid
		if cookie, err := req.Cookie(lb.stickyCookieName); err != nil || cookie.Value == "" {
			// No cookie or invalid cookie - set a new one
			signedValue := signTargetIndex(targetIndex, lb.stickyCookieSecret)

			// Create sticky cookie with appropriate security settings
			stickyCookie := &http.Cookie{
				Name:     lb.stickyCookieName,
				Value:    signedValue,
				Path:     "/",
				HttpOnly: true,
				Secure:   req.TLS != nil, // Only secure for HTTPS
				SameSite: http.SameSiteLaxMode,
				MaxAge:   DefaultStickyCookieMaxAge,
			}

			// Add the cookie to the response
			if resp.Header == nil {
				resp.Header = make(http.Header)
			}
			resp.Header.Add(httputil.HeaderSetCookie, stickyCookie.String())

			slog.Debug("set sticky cookie", "origin_id", lb.originID, "target_index", targetIndex, "cookie_name", lb.stickyCookieName)
		}
	}

	return resp, nil
}

// selectTarget selects a target based on the load balancing strategy
func (lb *loadBalancerTransport) selectTarget(req *http.Request) int {
	// Single target optimization
	if len(lb.targets) == 1 {
		// Even with single target, check if it's healthy and circuit breaker is not open
		target := lb.targets[0]
		if target.health != nil && !target.health.isHealthy() {
			slog.Warn("only target is unhealthy, using anyway", "origin_id", lb.originID)
		}
		if target.circuitBreaker != nil && target.circuitBreaker.isOpen() {
			slog.Warn("only target circuit breaker is open, using anyway", "origin_id", lb.originID)
		}
		targetIndex := 0
		return targetIndex
	}

	// 1. Check for sticky session cookie (if enabled)
	if !lb.disableSticky && lb.stickyCookieName != "" {
		if cookie, err := req.Cookie(lb.stickyCookieName); err == nil {
			if targetIndex, valid := verifyAndExtractTargetIndex(cookie.Value, lb.stickyCookieSecret, len(lb.targets)); valid {
				target := lb.targets[targetIndex]
				// Check if sticky target is healthy and circuit breaker is not open
				isHealthy := target.health == nil || target.health.isHealthy()
				circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()

				if isHealthy && circuitBreakerOk {
					slog.Debug("using sticky session", "origin_id", lb.originID, "target_index", targetIndex)
					return targetIndex
				} else {
					if !isHealthy {
						slog.Debug("sticky target unhealthy, selecting new target", "origin_id", lb.originID, "target_index", targetIndex)
					}
					if !circuitBreakerOk {
						slog.Debug("sticky target circuit breaker open, selecting new target", "origin_id", lb.originID, "target_index", targetIndex)
					}
				}
			} else {
				slog.Debug("invalid sticky cookie, selecting new target", "origin_id", lb.originID)
			}
		}
	}

	// 2. Try matcher-based routing (only healthy targets with circuit breaker ok)
	for i, target := range lb.targets {
		// Check if this target's matcher matches the request, target is healthy, and circuit breaker is ok
		isHealthy := target.health == nil || target.health.isHealthy()
		circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()

		if lb.matchesTarget(req, target) && isHealthy && circuitBreakerOk {
			slog.Debug("target selected by matcher", "origin_id", lb.originID, "target_index", i)
			return i
		}
	}

	// 3. Use configured load balancing algorithm (with health checking)
	var targetIndex int

	switch lb.algorithm {
	case AlgorithmLeastConnections:
		targetIndex = lb.selectLeastConnectionsHealthy()
	case AlgorithmRoundRobin:
		targetIndex = lb.selectRoundRobinHealthy()
	case AlgorithmWeightedRoundRobin:
		targetIndex = lb.selectWeightedRoundRobinHealthy()
	case AlgorithmIPHash:
		targetIndex = lb.selectIPHashHealthy(req)
	case AlgorithmURIHash:
		targetIndex = lb.selectURIHashHealthy(req)
	case AlgorithmHeaderHash:
		targetIndex = lb.selectHeaderHashHealthy(req)
	case AlgorithmCookieHash:
		targetIndex = lb.selectCookieHashHealthy(req)
	case AlgorithmRandom:
		targetIndex = lb.selectRandomHealthy()
	case AlgorithmFirst:
		targetIndex = lb.selectFirstHealthy()
	default:
		// Weighted random (default)
		// Note: selectWeightedRandomHealthy() manages its own locks internally,
		// so we don't need to hold a lock here. This avoids deadlock with RLock->Lock upgrade.
		targetIndex = lb.selectWeightedRandomHealthy()
	}

	return targetIndex
}

// matchesTarget checks if a request matches a target's matcher
// Note: Target.Matcher currently uses HostnameForwarder which contains RequestMatcher rules
// Returns false if the target has no matchers (to allow falling through to load balancing)
func (lb *loadBalancerTransport) matchesTarget(req *http.Request, target *compiledTarget) bool {
	// If no matchers are defined, don't match (fall through to load balancing)
	if len(target.RequestMatchers) == 0 {
		return false
	}
	return target.RequestMatchers.Match(req)
}

// selectLeastConnectionsHealthy selects the target with least connections, preferring healthy targets
func (lb *loadBalancerTransport) selectLeastConnectionsHealthy() int {
	if len(lb.targets) == 0 {
		return -1
	}

	// First pass: find healthy target with circuit breaker ok and least connections
	minConnections := int64(-1)
	minIndex := -1

	for i, target := range lb.targets {
		// Skip unhealthy targets
		if target.health != nil && !target.health.isHealthy() {
			continue
		}

		// Skip targets with open circuit breaker
		if target.circuitBreaker != nil && target.circuitBreaker.isOpen() {
			continue
		}

		connections := atomic.LoadInt64(&target.activeConnections)
		if minIndex == -1 || connections < minConnections {
			minConnections = connections
			minIndex = i
		}
	}

	// If we found a healthy target, use it
	if minIndex >= 0 {
		slog.Debug("selected healthy target by least connections", "target_index", minIndex, "connections", minConnections)
		return minIndex
	}

	// All targets unhealthy or circuit breakers open - return -1 to signal 503
	slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
	return -1
}

// selectRoundRobinHealthy selects the next target in round robin, skipping unhealthy ones and open circuit breakers
func (lb *loadBalancerTransport) selectRoundRobinHealthy() int {
	if len(lb.targets) == 0 {
		return -1
	}

	// Try up to len(targets) times to find a healthy target with circuit breaker ok
	for attempts := 0; attempts < len(lb.targets); attempts++ {
		index := atomic.AddInt64(&lb.roundRobin, 1) - 1
		targetIndex := int(index % int64(len(lb.targets)))

		target := lb.targets[targetIndex]
		isHealthy := target.health == nil || target.health.isHealthy()
		circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()

		if isHealthy && circuitBreakerOk {
			return targetIndex
		}
	}

	// All targets unhealthy or circuit breakers open - return -1 to signal 503
	slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
	return -1
}

// selectWeightedRandomHealthy selects a target using weighted random, preferring healthy targets with circuit breaker ok
func (lb *loadBalancerTransport) selectWeightedRandomHealthy() int {
	if len(lb.targets) == 0 {
		return -1
	}

	// Calculate total weight of healthy targets with circuit breaker ok
	healthyWeight := 0
	for _, target := range lb.targets {
		// Skip unhealthy targets
		if target.health != nil && !target.health.isHealthy() {
			continue
		}

		// Skip targets with open circuit breaker
		if target.circuitBreaker != nil && target.circuitBreaker.isOpen() {
			continue
		}

		weight := target.Config.Weight
		if weight <= 0 {
			weight = 1
		}
		healthyWeight += weight
	}

	// If we have healthy targets with weight, select from them
	if healthyWeight > 0 {
		// Fix 1.4: Protect rand access with mutex (rand.Rand is not thread-safe)
		lb.mu.Lock()
		randomValue := lb.random.Intn(healthyWeight)
		lb.mu.Unlock()
		currentWeight := 0

		for i, target := range lb.targets {
			// Skip unhealthy targets
			if target.health != nil && !target.health.isHealthy() {
				continue
			}

			// Skip targets with open circuit breaker
			if target.circuitBreaker != nil && target.circuitBreaker.isOpen() {
				continue
			}

			weight := target.Config.Weight
			if weight <= 0 {
				weight = 1
			}
			currentWeight += weight
			if randomValue < currentWeight {
				slog.Debug("selected healthy target by weighted random", "target_index", i)
				return i
			}
		}
	}

	// All targets unhealthy or circuit breakers open - return -1 to signal 503
	slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
	return -1
}


// selectWeightedRoundRobinHealthy selects targets using weighted round-robin,
// skipping unhealthy targets and those with open circuit breakers.
func (lb *loadBalancerTransport) selectWeightedRoundRobinHealthy() int {
	if len(lb.targets) == 0 {
		return -1
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	numTargets := len(lb.targets)

	// Try each target at most once to find a healthy one
	for attempts := 0; attempts < numTargets; attempts++ {
		idx := lb.wrrIndex
		counter := lb.wrrCounter

		// If counter is exhausted, advance to next target
		if counter <= 0 {
			idx = (idx + 1) % int64(numTargets)
			weight := lb.targets[idx].Config.Weight
			if weight <= 0 {
				weight = 1
			}
			counter = int64(weight)
		}

		target := lb.targets[idx]
		isHealthy := target.health == nil || target.health.isHealthy()
		circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()

		if isHealthy && circuitBreakerOk {
			counter--
			lb.wrrIndex = idx
			lb.wrrCounter = counter
			return int(idx)
		}

		// Target is unhealthy - skip it entirely by exhausting its counter and moving on
		lb.wrrIndex = idx
		lb.wrrCounter = 0
	}

	// All targets unhealthy or circuit breakers open - return -1 to signal 503
	slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
	return -1
}

// fnvHashString hashes a string using FNV-1a and returns the index within n targets.
func fnvHashString(s string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32()) % n
}

// selectHashHealthy probes forward from baseIndex to find a healthy target.
func (lb *loadBalancerTransport) selectHashHealthy(baseIndex int) int {
	n := len(lb.targets)
	for i := 0; i < n; i++ {
		idx := (baseIndex + i) % n
		target := lb.targets[idx]
		isHealthy := target.health == nil || target.health.isHealthy()
		circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()
		if isHealthy && circuitBreakerOk {
			return idx
		}
	}
	slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
	return -1
}

// selectIPHashHealthy hashes the client IP (port stripped) for consistent routing.
// Same IP always routes to the same backend; falls back to the next healthy target.
func (lb *loadBalancerTransport) selectIPHashHealthy(req *http.Request) int {
	if len(lb.targets) == 0 {
		return -1
	}
	ip := req.RemoteAddr
	// Strip port if present
	if host, _, found := strings.Cut(ip, ":"); found {
		ip = host
	}
	baseIndex := fnvHashString(ip, len(lb.targets))
	return lb.selectHashHealthy(baseIndex)
}

// selectURIHashHealthy hashes the request URL path for consistent routing.
// Same path always routes to the same backend.
func (lb *loadBalancerTransport) selectURIHashHealthy(req *http.Request) int {
	if len(lb.targets) == 0 {
		return -1
	}
	path := req.URL.Path
	baseIndex := fnvHashString(path, len(lb.targets))
	return lb.selectHashHealthy(baseIndex)
}

// selectHeaderHashHealthy hashes a specified request header value (lb.hashKey).
// Falls back to hashing RemoteAddr if the header is absent.
func (lb *loadBalancerTransport) selectHeaderHashHealthy(req *http.Request) int {
	if len(lb.targets) == 0 {
		return -1
	}
	value := req.Header.Get(lb.hashKey)
	if value == "" {
		value = req.RemoteAddr
	}
	baseIndex := fnvHashString(value, len(lb.targets))
	return lb.selectHashHealthy(baseIndex)
}

// selectCookieHashHealthy hashes a specified cookie value (lb.hashKey).
// Falls back to hashing RemoteAddr if the cookie is absent.
func (lb *loadBalancerTransport) selectCookieHashHealthy(req *http.Request) int {
	if len(lb.targets) == 0 {
		return -1
	}
	value := req.RemoteAddr
	if cookie, err := req.Cookie(lb.hashKey); err == nil {
		value = cookie.Value
	}
	baseIndex := fnvHashString(value, len(lb.targets))
	return lb.selectHashHealthy(baseIndex)
}

// selectRandomHealthy selects a random healthy target with equal probability (ignores weights).
func (lb *loadBalancerTransport) selectRandomHealthy() int {
	if len(lb.targets) == 0 {
		return -1
	}

	// Collect indices of healthy targets
	healthy := make([]int, 0, len(lb.targets))
	for i, target := range lb.targets {
		isHealthy := target.health == nil || target.health.isHealthy()
		circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()
		if isHealthy && circuitBreakerOk {
			healthy = append(healthy, i)
		}
	}

	if len(healthy) == 0 {
		slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
		return -1
	}

	lb.mu.Lock()
	idx := lb.random.Intn(len(healthy))
	lb.mu.Unlock()
	return healthy[idx]
}

// selectFirstHealthy selects the first healthy target in list order (primary/failover pattern).
func (lb *loadBalancerTransport) selectFirstHealthy() int {
	if len(lb.targets) == 0 {
		return -1
	}

	for i, target := range lb.targets {
		isHealthy := target.health == nil || target.health.isHealthy()
		circuitBreakerOk := target.circuitBreaker == nil || !target.circuitBreaker.isOpen()
		if isHealthy && circuitBreakerOk {
			return i
		}
	}

	slog.Warn("all targets unhealthy or circuit breakers open", "origin_id", lb.originID)
	return -1
}

