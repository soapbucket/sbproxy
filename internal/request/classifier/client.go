package classifier

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/classifier/classifierpkg"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"golang.org/x/time/rate"
)

// ManagedClient wraps the prompt-classifier Go client with circuit breaker,
// per-workspace rate limiting, and an embedding cache.
type ManagedClient struct {
	client         *classifierpkg.Client
	breaker        *circuitbreaker.CircuitBreaker
	embedCache     *EmbeddingCache
	limiters       sync.Map       // workspaceID -> *rate.Limiter
	defaultLimiter *rate.Limiter
	settings       Settings
	available      atomic.Bool  // false if sidecar never connected
	embedSupported atomic.Bool  // false if sidecar has no embedding model
}

// NewManagedClient creates a ManagedClient by connecting to the sidecar.
//
// Startup flow:
//  1. Create the TCP client with pool_size and timeout from settings.
//  2. Create a circuit breaker named "prompt-classifier".
//  3. Wait for the sidecar to be ready (ready_timeout).
//  4. If unreachable and fail_open: log warning, set available=false, return (no error).
//  5. If unreachable and !fail_open: return error.
//  6. Probe EmbedOne to detect model availability; set embedSupported accordingly.
//  7. Create the embedding cache.
func NewManagedClient(ctx context.Context, settings Settings) (*ManagedClient, error) {
	settings = settings.withDefaults()

	client := classifierpkg.NewClient(
		settings.Address,
		classifierpkg.WithPoolSize(settings.PoolSize),
		classifierpkg.WithTimeout(settings.Timeout.Duration),
	)

	cb := circuitbreaker.New(circuitbreaker.Config{
		Name:             "prompt-classifier",
		FailureThreshold: 5,
		SuccessThreshold: 3,
		Timeout:          30 * time.Second,
	})

	mc := &ManagedClient{
		client:         client,
		breaker:        cb,
		settings:       settings,
		defaultLimiter: rate.NewLimiter(rate.Limit(settings.RateLimit.RequestsPerSecond), settings.RateLimit.Burst),
	}

	// Wait for sidecar readiness
	readyCtx, cancel := context.WithTimeout(ctx, settings.ReadyTimeout.Duration)
	defer cancel()

	if err := client.WaitReady(readyCtx); err != nil {
		if settings.FailOpen {
			slog.Warn("classifier sidecar unavailable, running in degraded mode",
				"address", settings.Address, "error", err)
			mc.available.Store(false)
			mc.embedSupported.Store(false)
			return mc, nil
		}
		client.Close()
		return nil, fmt.Errorf("classifier sidecar required but unavailable at %s: %w", settings.Address, err)
	}

	mc.available.Store(true)

	// Probe embedding support
	_, err := client.EmbedOne("test")
	if err != nil {
		slog.Info("classifier sidecar has no embedding model, embed calls will return errors",
			"address", settings.Address, "probe_error", err)
		mc.embedSupported.Store(false)
	} else {
		mc.embedSupported.Store(true)
		mc.embedCache = NewEmbeddingCache(
			settings.EmbeddingCache.MaxEntries,
			settings.EmbeddingCache.TTL.Duration,
		)
	}

	return mc, nil
}

// ClassifyForTenant classifies text using the tenant's registered config.
// When the circuit breaker is open and fail_open is true, returns an empty response.
func (mc *ManagedClient) ClassifyForTenant(text string, topK int, configID string) (*classifierpkg.Response, error) {
	if !mc.available.Load() {
		if mc.settings.FailOpen {
			return &classifierpkg.Response{}, nil
		}
		return nil, fmt.Errorf("classifier sidecar not available")
	}

	var resp *classifierpkg.Response
	err := mc.breaker.Call(func() error {
		var callErr error
		resp, callErr = mc.client.ClassifyForTenant(text, topK, configID)
		return callErr
	})

	if err != nil {
		if err == circuitbreaker.ErrCircuitOpen && mc.settings.FailOpen {
			return &classifierpkg.Response{}, nil
		}
		return nil, err
	}

	return resp, nil
}

// EmbedOne returns the embedding vector for a single text, using the cache when possible.
// When the circuit breaker is open, returns an error (callers should fall back to an external provider).
func (mc *ManagedClient) EmbedOne(text string) ([]float32, error) {
	if !mc.available.Load() || !mc.embedSupported.Load() {
		return nil, fmt.Errorf("embedding not available")
	}

	// Check cache
	if mc.embedCache != nil {
		if vec, ok := mc.embedCache.Get(text); ok {
			return vec, nil
		}
	}

	var vec []float32
	err := mc.breaker.Call(func() error {
		var callErr error
		vec, callErr = mc.client.EmbedOne(text)
		return callErr
	})
	if err != nil {
		return nil, err
	}

	// Store in cache
	if mc.embedCache != nil {
		mc.embedCache.Put(text, vec)
	}

	return vec, nil
}

// Embed returns embedding vectors for multiple texts.
// Results are not cached (batch calls are typically unique).
func (mc *ManagedClient) Embed(texts ...string) (*classifierpkg.EmbedResponse, error) {
	if !mc.available.Load() || !mc.embedSupported.Load() {
		return nil, fmt.Errorf("embedding not available")
	}

	var resp *classifierpkg.EmbedResponse
	err := mc.breaker.Call(func() error {
		var callErr error
		resp, callErr = mc.client.Embed(texts...)
		return callErr
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Register pushes a tenant config to the sidecar.
func (mc *ManagedClient) Register(configID string, config *classifierpkg.TenantConfig) error {
	if !mc.available.Load() {
		if mc.settings.FailOpen {
			return nil
		}
		return fmt.Errorf("classifier sidecar not available")
	}

	return mc.breaker.Call(func() error {
		return mc.client.Register(configID, config)
	})
}

// Delete removes a tenant config from the sidecar.
func (mc *ManagedClient) Delete(configID string) error {
	if !mc.available.Load() {
		if mc.settings.FailOpen {
			return nil
		}
		return fmt.Errorf("classifier sidecar not available")
	}

	return mc.breaker.Call(func() error {
		return mc.client.Delete(configID)
	})
}

// IsAvailable returns true when the sidecar was reachable at startup.
func (mc *ManagedClient) IsAvailable() bool {
	return mc.available.Load()
}

// IsEmbedSupported returns true when the sidecar has an embedding model loaded.
func (mc *ManagedClient) IsEmbedSupported() bool {
	return mc.embedSupported.Load()
}

// Version returns the sidecar's name, version, and capabilities.
func (mc *ManagedClient) Version() (*classifierpkg.VersionResponse, error) {
	return mc.client.Version()
}

// GetLimiter returns or creates a per-workspace rate limiter.
func (mc *ManagedClient) GetLimiter(workspaceID string) *rate.Limiter {
	if workspaceID == "" {
		return mc.defaultLimiter
	}
	if v, ok := mc.limiters.Load(workspaceID); ok {
		return v.(*rate.Limiter)
	}
	limiter := rate.NewLimiter(
		rate.Limit(mc.settings.RateLimit.RequestsPerSecond),
		mc.settings.RateLimit.Burst,
	)
	actual, _ := mc.limiters.LoadOrStore(workspaceID, limiter)
	return actual.(*rate.Limiter)
}

// Close drains the underlying client connection pool.
func (mc *ManagedClient) Close() {
	if mc.client != nil {
		mc.client.Close()
	}
}
