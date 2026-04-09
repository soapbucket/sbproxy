package ai

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeProviders(names ...string) []*ProviderConfig {
	var result []*ProviderConfig
	for _, name := range names {
		result = append(result, &ProviderConfig{Name: name})
	}
	return result
}

func TestRouterRoundRobin(t *testing.T) {
	providers := makeProviders("a", "b", "c")
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)

	counts := map[string]int{}
	for i := 0; i < 99; i++ {
		cfg, err := r.Route(context.Background(), "", nil)
		require.NoError(t, err)
		counts[cfg.Name]++
	}

	// Should be evenly distributed
	assert.Equal(t, 33, counts["a"])
	assert.Equal(t, 33, counts["b"])
	assert.Equal(t, 33, counts["c"])
}

func TestRouterWeighted(t *testing.T) {
	providers := []*ProviderConfig{
		{Name: "heavy", Weight: 70},
		{Name: "light", Weight: 30},
	}
	r := NewRouter(&RoutingConfig{Strategy: "weighted"}, providers)

	counts := map[string]int{}
	n := 10000
	for i := 0; i < n; i++ {
		cfg, err := r.Route(context.Background(), "", nil)
		require.NoError(t, err)
		counts[cfg.Name]++
	}

	// Check within 5% tolerance
	heavyPct := float64(counts["heavy"]) / float64(n) * 100
	assert.InDelta(t, 70, heavyPct, 5, "heavy should be ~70%%, got %.1f%%", heavyPct)
}

func TestRouterLowestLatency(t *testing.T) {
	providers := makeProviders("slow", "fast", "medium")
	r := NewRouter(&RoutingConfig{Strategy: "lowest_latency"}, providers)

	// Record latencies
	for i := 0; i < 10; i++ {
		r.tracker.RecordSuccess("slow", 500*time.Millisecond)
		r.tracker.RecordSuccess("fast", 50*time.Millisecond)
		r.tracker.RecordSuccess("medium", 200*time.Millisecond)
	}

	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "fast", cfg.Name)
}

func TestRouterCostOptimized(t *testing.T) {
	providers := []*ProviderConfig{
		{Name: "expensive", Priority: 10},
		{Name: "cheap", Priority: 1},
		{Name: "medium", Priority: 5},
	}
	r := NewRouter(&RoutingConfig{Strategy: "cost_optimized"}, providers)

	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "cheap", cfg.Name)
}

func TestRouterFallbackChain(t *testing.T) {
	providers := makeProviders("primary", "secondary", "tertiary")
	r := NewRouter(&RoutingConfig{
		Strategy:      "fallback_chain",
		FallbackOrder: []string{"primary", "secondary", "tertiary"},
	}, providers)

	// First call should use primary
	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "primary", cfg.Name)

	// Excluding primary should use secondary
	cfg, err = r.Route(context.Background(), "", map[string]bool{"primary": true})
	require.NoError(t, err)
	assert.Equal(t, "secondary", cfg.Name)

	// Excluding primary and secondary should use tertiary
	cfg, err = r.Route(context.Background(), "", map[string]bool{"primary": true, "secondary": true})
	require.NoError(t, err)
	assert.Equal(t, "tertiary", cfg.Name)
}

func TestRouterLeastConnections(t *testing.T) {
	providers := makeProviders("busy", "idle", "moderate")
	r := NewRouter(&RoutingConfig{Strategy: "least_connections"}, providers)

	// Simulate in-flight requests
	for i := 0; i < 10; i++ {
		r.tracker.IncrInFlight("busy")
	}
	for i := 0; i < 2; i++ {
		r.tracker.IncrInFlight("idle")
	}
	for i := 0; i < 5; i++ {
		r.tracker.IncrInFlight("moderate")
	}

	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "idle", cfg.Name)
}

func TestRouterTokenRate(t *testing.T) {
	providers := []*ProviderConfig{
		{Name: "limited", MaxTokensPerMin: 1000},
		{Name: "unlimited"},
	}
	r := NewRouter(&RoutingConfig{Strategy: "token_rate"}, providers)

	// Unlimited provider should always be preferred
	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "unlimited", cfg.Name)
}

func TestRouterTokenRate_PreferMoreCapacity(t *testing.T) {
	providers := []*ProviderConfig{
		{Name: "a", MaxTokensPerMin: 10000},
		{Name: "b", MaxTokensPerMin: 10000},
	}
	r := NewRouter(&RoutingConfig{Strategy: "token_rate"}, providers)

	// Consume tokens for "a"
	r.tracker.RecordTokens("a", 8000)

	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "b", cfg.Name) // b has more remaining capacity
}

func TestRouterCircuitBreaker(t *testing.T) {
	providers := makeProviders("failing", "healthy")
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)

	// Trigger circuit breaker on "failing"
	for i := 0; i < circuitFailThreshold; i++ {
		r.tracker.RecordError("failing")
	}

	// Circuit should be open
	assert.True(t, r.tracker.IsCircuitOpen("failing"))

	// Routing should skip "failing"
	for i := 0; i < 10; i++ {
		cfg, err := r.Route(context.Background(), "", nil)
		require.NoError(t, err)
		assert.Equal(t, "healthy", cfg.Name)
	}
}

func TestRouterAllProvidersDown(t *testing.T) {
	providers := makeProviders("a", "b")
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)

	// Open circuit breakers on all providers
	for i := 0; i < circuitFailThreshold; i++ {
		r.tracker.RecordError("a")
		r.tracker.RecordError("b")
	}

	_, err := r.Route(context.Background(), "", nil)
	require.Error(t, err)
}

func TestRouterModelFiltering(t *testing.T) {
	providers := []*ProviderConfig{
		{Name: "openai", Models: []string{"gpt-4", "gpt-3.5-turbo"}},
		{Name: "anthropic", Models: []string{"claude-3-5-sonnet-20241022"}},
	}
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)

	// Request for gpt-4 should only route to openai
	cfg, err := r.Route(context.Background(), "gpt-4", nil)
	require.NoError(t, err)
	assert.Equal(t, "openai", cfg.Name)

	// Request for claude should only route to anthropic
	cfg, err = r.Route(context.Background(), "claude-3-5-sonnet-20241022", nil)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", cfg.Name)

	// Unknown model should fail
	_, err = r.Route(context.Background(), "unknown-model", nil)
	require.Error(t, err)
}

func TestRouterExclude(t *testing.T) {
	providers := makeProviders("a", "b", "c")
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)

	exclude := map[string]bool{"a": true, "b": true}
	cfg, err := r.Route(context.Background(), "", exclude)
	require.NoError(t, err)
	assert.Equal(t, "c", cfg.Name)
}

func TestRouterConcurrency(t *testing.T) {
	providers := makeProviders("a", "b", "c")
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Route(context.Background(), "", nil)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent routing error: %v", err)
	}
}

func TestRouterShouldRetry(t *testing.T) {
	r := NewRouter(&RoutingConfig{
		Retry: &RetryConfig{
			RetryOnStatus: []int{429, 500, 502, 503, 504},
		},
	}, makeProviders("a"))

	assert.True(t, r.ShouldRetry(429))
	assert.True(t, r.ShouldRetry(500))
	assert.True(t, r.ShouldRetry(502))
	assert.False(t, r.ShouldRetry(400))
	assert.False(t, r.ShouldRetry(401))
	assert.False(t, r.ShouldRetry(404))
}

func TestRouterMaxAttempts(t *testing.T) {
	r := NewRouter(&RoutingConfig{
		Retry: &RetryConfig{MaxAttempts: 5},
	}, makeProviders("a"))
	assert.Equal(t, 5, r.MaxAttempts())

	r2 := NewRouter(nil, makeProviders("a"))
	assert.Equal(t, 3, r2.MaxAttempts()) // default
}

func TestRouterDefaultStrategy(t *testing.T) {
	r := NewRouter(nil, makeProviders("a", "b"))
	assert.Equal(t, 2, r.ProviderCount())

	cfg, err := r.Route(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Contains(t, []string{"a", "b"}, cfg.Name)
}

func TestRouterDisabledProvider(t *testing.T) {
	disabled := false
	providers := []*ProviderConfig{
		{Name: "enabled"},
		{Name: "disabled", Enabled: &disabled},
	}
	r := NewRouter(nil, providers)
	assert.Equal(t, 1, r.ProviderCount())
}

func BenchmarkRouterRoundRobin(b *testing.B) {
	providers := makeProviders("a", "b", "c", "d", "e")
	r := NewRouter(&RoutingConfig{Strategy: "round_robin"}, providers)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Route(ctx, "", nil)
	}
}

func BenchmarkRouterWeighted(b *testing.B) {
	providers := []*ProviderConfig{
		{Name: "a", Weight: 50},
		{Name: "b", Weight: 30},
		{Name: "c", Weight: 20},
	}
	r := NewRouter(&RoutingConfig{Strategy: "weighted"}, providers)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Route(ctx, "", nil)
	}
}

func BenchmarkRouterLowestLatency(b *testing.B) {
	providers := makeProviders("a", "b", "c")
	r := NewRouter(&RoutingConfig{Strategy: "lowest_latency"}, providers)
	for _, name := range []string{"a", "b", "c"} {
		for i := 0; i < 100; i++ {
			r.tracker.RecordSuccess(name, 100*time.Millisecond)
		}
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Route(ctx, "", nil)
	}
}

