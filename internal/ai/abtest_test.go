package ai

import (
	"math"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestABTest_WeightDistribution(t *testing.T) {
	config := ABTestConfig{
		Enabled: true,
		Name:    "model-test",
		Variants: []ABVariant{
			{Name: "control", Weight: 0.7},
			{Name: "experiment", Weight: 0.3},
		},
	}
	ab := NewABTestRouter(config)

	counts := map[string]int{"control": 0, "experiment": 0}
	n := 10000
	for i := 0; i < n; i++ {
		v := ab.SelectVariant(nil)
		if v == nil {
			t.Fatal("SelectVariant returned nil")
		}
		counts[v.Name]++
	}

	// Check distribution is roughly correct (within 5% tolerance)
	controlRatio := float64(counts["control"]) / float64(n)
	if math.Abs(controlRatio-0.7) > 0.05 {
		t.Errorf("control ratio %.3f, expected ~0.7", controlRatio)
	}

	experimentRatio := float64(counts["experiment"]) / float64(n)
	if math.Abs(experimentRatio-0.3) > 0.05 {
		t.Errorf("experiment ratio %.3f, expected ~0.3", experimentRatio)
	}
}

func TestABTest_StickyAssignment(t *testing.T) {
	config := ABTestConfig{
		Enabled:   true,
		Name:      "sticky-test",
		StickyKey: "X-User-ID",
		Variants: []ABVariant{
			{Name: "A", Weight: 0.5},
			{Name: "B", Weight: 0.5},
		},
	}
	ab := NewABTestRouter(config)

	// Same user should always get the same variant
	var firstVariant string
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.Header.Set("X-User-ID", "user-42")
		v := ab.SelectVariant(req)
		if v == nil {
			t.Fatal("SelectVariant returned nil")
		}
		if firstVariant == "" {
			firstVariant = v.Name
		} else if v.Name != firstVariant {
			t.Errorf("sticky assignment failed: got %q, expected %q", v.Name, firstVariant)
		}
	}

	// Different user may get a different variant (but consistently)
	var otherVariant string
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.Header.Set("X-User-ID", "user-99")
		v := ab.SelectVariant(req)
		if v == nil {
			t.Fatal("SelectVariant returned nil")
		}
		if otherVariant == "" {
			otherVariant = v.Name
		} else if v.Name != otherVariant {
			t.Errorf("sticky assignment for user-99 inconsistent: got %q, expected %q", v.Name, otherVariant)
		}
	}
}

func TestABTest_RecordMetrics(t *testing.T) {
	config := ABTestConfig{
		Enabled: true,
		Name:    "metrics-test",
		Variants: []ABVariant{
			{Name: "v1", Weight: 1.0},
		},
	}
	ab := NewABTestRouter(config)

	ab.RecordResult("v1", 100, 50*time.Millisecond, nil)
	ab.RecordResult("v1", 200, 100*time.Millisecond, nil)

	m := ab.GetMetrics()
	v1 := m["v1"]
	if v1 == nil {
		t.Fatal("expected metrics for v1")
	}
	if v1.Requests.Load() != 2 {
		t.Errorf("expected 2 requests, got %d", v1.Requests.Load())
	}
	if v1.Tokens.Load() != 300 {
		t.Errorf("expected 300 tokens, got %d", v1.Tokens.Load())
	}
	if v1.Errors.Load() != 0 {
		t.Errorf("expected 0 errors, got %d", v1.Errors.Load())
	}
}

func TestABTest_GetMetrics(t *testing.T) {
	config := ABTestConfig{
		Enabled: true,
		Name:    "getmetrics-test",
		Variants: []ABVariant{
			{Name: "alpha", Weight: 0.5},
			{Name: "beta", Weight: 0.5},
		},
	}
	ab := NewABTestRouter(config)

	ab.RecordResult("alpha", 50, 10*time.Millisecond, nil)
	ab.RecordResult("beta", 75, 20*time.Millisecond, nil)
	ab.RecordResult("beta", 0, 5*time.Millisecond, errForTest)

	m := ab.GetMetrics()
	if len(m) != 2 {
		t.Errorf("expected 2 variants in metrics, got %d", len(m))
	}
	if m["alpha"].Requests.Load() != 1 {
		t.Errorf("alpha: expected 1 request, got %d", m["alpha"].Requests.Load())
	}
	if m["beta"].Requests.Load() != 2 {
		t.Errorf("beta: expected 2 requests, got %d", m["beta"].Requests.Load())
	}
	if m["beta"].Errors.Load() != 1 {
		t.Errorf("beta: expected 1 error, got %d", m["beta"].Errors.Load())
	}
}

var errForTest = func() error { return &testError{} }()

type testError struct{}

func (e *testError) Error() string { return "test error" }

func TestABTest_SingleVariant(t *testing.T) {
	config := ABTestConfig{
		Enabled: true,
		Name:    "single",
		Variants: []ABVariant{
			{Name: "only", Weight: 1.0, Provider: "openai", Model: "gpt-4o"},
		},
	}
	ab := NewABTestRouter(config)

	for i := 0; i < 100; i++ {
		v := ab.SelectVariant(nil)
		if v == nil {
			t.Fatal("SelectVariant returned nil")
		}
		if v.Name != "only" {
			t.Errorf("expected 'only', got %q", v.Name)
		}
	}
}

func TestABTest_Reset(t *testing.T) {
	config := ABTestConfig{
		Enabled:   true,
		Name:      "reset-test",
		StickyKey: "X-User-ID",
		Variants: []ABVariant{
			{Name: "A", Weight: 0.5},
			{Name: "B", Weight: 0.5},
		},
	}
	ab := NewABTestRouter(config)

	// Record some metrics
	ab.RecordResult("A", 100, 50*time.Millisecond, nil)
	ab.RecordResult("B", 200, 100*time.Millisecond, nil)

	// Create a sticky assignment
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("X-User-ID", "user-1")
	ab.SelectVariant(req)

	// Reset
	ab.Reset()

	m := ab.GetMetrics()
	for name, vm := range m {
		if vm.Requests.Load() != 0 {
			t.Errorf("%s: expected 0 requests after reset, got %d", name, vm.Requests.Load())
		}
		if vm.Tokens.Load() != 0 {
			t.Errorf("%s: expected 0 tokens after reset, got %d", name, vm.Tokens.Load())
		}
	}

	// Sticky assignments should be cleared (user-1 might get a different variant)
	// We can verify the sticky map is empty by checking that a new selection happens
	// (though it could randomly land on the same variant)
	ab.stickyMu.RLock()
	stickyLen := len(ab.sticky)
	ab.stickyMu.RUnlock()
	if stickyLen != 0 {
		t.Errorf("expected empty sticky map after reset, got %d entries", stickyLen)
	}
}

func TestABTest_ConcurrentSelect(t *testing.T) {
	config := ABTestConfig{
		Enabled:   true,
		Name:      "concurrent",
		StickyKey: "X-User-ID",
		Variants: []ABVariant{
			{Name: "A", Weight: 0.5},
			{Name: "B", Weight: 0.5},
		},
	}
	ab := NewABTestRouter(config)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/", nil)
			req.Header.Set("X-User-ID", "user-concurrent")
			v := ab.SelectVariant(req)
			if v == nil {
				t.Error("SelectVariant returned nil")
			}
			ab.RecordResult(v.Name, 50, 10*time.Millisecond, nil)
		}(i)
	}
	wg.Wait()

	m := ab.GetMetrics()
	total := m["A"].Requests.Load() + m["B"].Requests.Load()
	if total != 100 {
		t.Errorf("expected 100 total requests, got %d", total)
	}
}

func TestABTest_VariantOverrides(t *testing.T) {
	temp := 0.1
	config := ABTestConfig{
		Enabled: true,
		Name:    "overrides",
		Variants: []ABVariant{
			{
				Name:        "low-temp",
				Weight:      0.5,
				Provider:    "openai",
				Model:       "gpt-4o",
				Temperature: &temp,
				MaxTokens:   100,
			},
			{
				Name:      "high-tokens",
				Weight:    0.5,
				Provider:  "anthropic",
				Model:     "claude-3",
				MaxTokens: 4096,
			},
		},
	}
	ab := NewABTestRouter(config)

	// Verify variant fields are correctly accessible
	found := map[string]bool{}
	for i := 0; i < 200; i++ {
		v := ab.SelectVariant(nil)
		if v == nil {
			t.Fatal("SelectVariant returned nil")
		}
		found[v.Name] = true

		switch v.Name {
		case "low-temp":
			if v.Temperature == nil || *v.Temperature != 0.1 {
				t.Errorf("low-temp: expected temperature 0.1")
			}
			if v.MaxTokens != 100 {
				t.Errorf("low-temp: expected max_tokens 100, got %d", v.MaxTokens)
			}
			if v.Provider != "openai" {
				t.Errorf("low-temp: expected provider openai, got %q", v.Provider)
			}
		case "high-tokens":
			if v.Temperature != nil {
				t.Errorf("high-tokens: expected nil temperature")
			}
			if v.MaxTokens != 4096 {
				t.Errorf("high-tokens: expected max_tokens 4096, got %d", v.MaxTokens)
			}
			if v.Provider != "anthropic" {
				t.Errorf("high-tokens: expected provider anthropic, got %q", v.Provider)
			}
		}
	}

	if !found["low-temp"] || !found["high-tokens"] {
		t.Error("expected both variants to be selected at least once")
	}
}
