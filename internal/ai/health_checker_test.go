package ai

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// mockCacher implements cacher.Cacher for testing distributed lock behavior.
type mockCacher struct {
	data map[string][]byte
}

func newMockCacher() *mockCacher {
	return &mockCacher{data: make(map[string][]byte)}
}

func (m *mockCacher) Driver() string { return "mock" }
func (m *mockCacher) Close() error   { return nil }

func (m *mockCacher) Get(_ context.Context, cType string, key string) (io.Reader, error) {
	k := cType + "/" + key
	v, ok := m.data[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return bytes.NewReader(v), nil
}

func (m *mockCacher) ListKeys(_ context.Context, _ string, _ string) ([]string, error) {
	return nil, nil
}

func (m *mockCacher) Put(_ context.Context, cType string, key string, data io.Reader) error {
	k := cType + "/" + key
	b, _ := io.ReadAll(data)
	m.data[k] = b
	return nil
}

func (m *mockCacher) PutWithExpires(_ context.Context, cType string, key string, data io.Reader, _ time.Duration) error {
	return m.Put(context.Background(), cType, key, data)
}

func (m *mockCacher) Delete(_ context.Context, cType string, key string) error {
	delete(m.data, cType+"/"+key)
	return nil
}

func (m *mockCacher) DeleteByPattern(_ context.Context, _ string, _ string) error {
	return nil
}

func (m *mockCacher) Increment(_ context.Context, _ string, _ string, _ int64) (int64, error) {
	return 0, nil
}

func (m *mockCacher) IncrementWithExpires(_ context.Context, _ string, _ string, _ int64, _ time.Duration) (int64, error) {
	return 0, nil
}

func makeProvider(name string, enabled bool, interval time.Duration, model string) *ProviderConfig {
	e := enabled
	return &ProviderConfig{
		Name:    name,
		Enabled: &e,
		HealthCheck: &HealthCheckConfig{
			Enabled:  true,
			Interval: reqctx.Duration{Duration: interval},
			Model:    model,
			Timeout:  reqctx.Duration{Duration: 5 * time.Second},
		},
	}
}

func TestHealthCheckHealthyProvider(t *testing.T) {
	tracker := NewProviderTracker()
	p := makeProvider("openai", true, 100*time.Millisecond, "gpt-4o-mini")
	router := NewRouter(&RoutingConfig{Strategy: "round_robin"}, []*ProviderConfig{p})

	var checkCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		checkCount.Add(1)
		return nil
	}

	hc := NewHealthChecker(tracker, router, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()

	// Allow goroutine to finish.
	time.Sleep(20 * time.Millisecond)

	if checkCount.Load() < 2 {
		t.Errorf("expected at least 2 health checks, got %d", checkCount.Load())
	}

	// Provider should remain healthy, no consecutive failures.
	if hc.ConsecutiveFailures("openai") != 0 {
		t.Errorf("expected 0 consecutive failures, got %d", hc.ConsecutiveFailures("openai"))
	}

	// Circuit should be closed.
	if tracker.IsCircuitOpen("openai") {
		t.Error("circuit should be closed for healthy provider")
	}
}

func TestHealthCheckFailedOpensCircuit(t *testing.T) {
	tracker := NewProviderTracker()
	p := makeProvider("anthropic", true, 50*time.Millisecond, "claude-3-haiku")
	router := NewRouter(&RoutingConfig{Strategy: "round_robin"}, []*ProviderConfig{p})

	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		return errors.New("connection refused")
	}

	hc := NewHealthChecker(tracker, router, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	// After multiple failures, circuit should open.
	if !tracker.IsCircuitOpen("anthropic") {
		t.Error("circuit should be open after repeated failures")
	}

	if hc.ConsecutiveFailures("anthropic") < 2 {
		t.Errorf("expected at least 2 consecutive failures, got %d", hc.ConsecutiveFailures("anthropic"))
	}
}

func TestHealthCheckRecovery(t *testing.T) {
	tracker := NewProviderTracker()
	p := makeProvider("openai", true, 50*time.Millisecond, "gpt-4o-mini")
	router := NewRouter(&RoutingConfig{Strategy: "round_robin"}, []*ProviderConfig{p})

	var callCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		n := callCount.Add(1)
		// Fail for the first 3 checks, then succeed.
		if n <= 3 {
			return errors.New("provider unavailable")
		}
		return nil
	}

	hc := NewHealthChecker(tracker, router, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	// After recovery, consecutive failures should be 0.
	if hc.ConsecutiveFailures("openai") != 0 {
		t.Errorf("expected 0 consecutive failures after recovery, got %d", hc.ConsecutiveFailures("openai"))
	}
}

func TestHealthCheckGracefulShutdown(t *testing.T) {
	tracker := NewProviderTracker()
	p := makeProvider("openai", true, 1*time.Second, "gpt-4o-mini")

	var checkCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		checkCount.Add(1)
		return nil
	}

	hc := NewHealthChecker(tracker, nil, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithCancel(context.Background())

	hc.Start(ctx)

	// Cancel immediately. The goroutine should stop before the first ticker fires.
	// It may have done one check after the initial jitter (or none if jitter > 0).
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	count := checkCount.Load()
	// At most 1 check should have happened (from the initial post-jitter check).
	if count > 1 {
		t.Errorf("expected at most 1 check after quick cancel, got %d", count)
	}
}

func TestHealthCheckNilCache(t *testing.T) {
	tracker := NewProviderTracker()
	p := makeProvider("gemini", true, 80*time.Millisecond, "gemini-1.5-flash")

	var checkCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		checkCount.Add(1)
		return nil
	}

	// Nil cache: should check independently.
	hc := NewHealthChecker(tracker, nil, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	if checkCount.Load() < 2 {
		t.Errorf("expected at least 2 checks with nil cache, got %d", checkCount.Load())
	}
}

func TestHealthCheckDisabledNoGoroutine(t *testing.T) {
	tracker := NewProviderTracker()

	enabled := true
	p := &ProviderConfig{
		Name:    "disabled-provider",
		Enabled: &enabled,
		HealthCheck: &HealthCheckConfig{
			Enabled: false, // Disabled.
		},
	}

	var checkCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		checkCount.Add(1)
		return nil
	}

	hc := NewHealthChecker(tracker, nil, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	if checkCount.Load() != 0 {
		t.Errorf("expected 0 checks for disabled provider, got %d", checkCount.Load())
	}
}

func TestHealthCheckWithMockCache(t *testing.T) {
	tracker := NewProviderTracker()
	p := makeProvider("openai", true, 80*time.Millisecond, "gpt-4o-mini")
	router := NewRouter(&RoutingConfig{Strategy: "round_robin"}, []*ProviderConfig{p})
	cache := newMockCacher()

	var checkCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		checkCount.Add(1)
		return nil
	}

	hc := NewHealthChecker(tracker, router, []*ProviderConfig{p}, cache, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	// With a mock cache, the first instance should acquire the lock and perform checks.
	if checkCount.Load() < 1 {
		t.Errorf("expected at least 1 check with mock cache, got %d", checkCount.Load())
	}
}

func TestHealthCheckNilHealthCheckConfig(t *testing.T) {
	tracker := NewProviderTracker()

	enabled := true
	p := &ProviderConfig{
		Name:        "no-hc-provider",
		Enabled:     &enabled,
		HealthCheck: nil, // No health check config at all.
	}

	var checkCount atomic.Int32
	checkFn := func(_ context.Context, _ *ProviderConfig, _ string) error {
		checkCount.Add(1)
		return nil
	}

	hc := NewHealthChecker(tracker, nil, []*ProviderConfig{p}, nil, "inst-1", checkFn)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	hc.Start(ctx)
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)

	if checkCount.Load() != 0 {
		t.Errorf("expected 0 checks for provider without health check config, got %d", checkCount.Load())
	}
}
