package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFaultInjection_AbortFullPercentage(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"abort": {
			"status_code": 503,
			"percentage": 100,
			"body": "service unavailable"
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler should not have been called when abort is at 100%")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
	if rec.Body.String() != "service unavailable" {
		t.Errorf("expected body %q, got %q", "service unavailable", rec.Body.String())
	}
}

func TestFaultInjection_DelayFullPercentage(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"delay": {
			"duration": "50ms",
			"percentage": 100
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if !nextCalled {
		t.Error("next handler should have been called after delay")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected delay of at least 40ms, got %v", elapsed)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestFaultInjection_ActivationHeaderMissing(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"activation_header": "X-Fault-Inject",
		"abort": {
			"status_code": 503,
			"percentage": 100
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler should have been called when activation header is missing")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestFaultInjection_ActivationHeaderPresent(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"activation_header": "X-Fault-Inject",
		"abort": {
			"status_code": 503,
			"percentage": 100
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Fault-Inject", "true")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler should not have been called when activation header is present and abort is 100%")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
}

func TestFaultInjection_Disabled(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"disabled": true,
		"abort": {
			"status_code": 503,
			"percentage": 100
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler should have been called when policy is disabled")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestFaultInjection_ZeroPercentageNeverTriggers(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"abort": {
			"status_code": 503,
			"percentage": 0
		},
		"delay": {
			"duration": "1s",
			"percentage": 0
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)

	// Run multiple times to verify 0% never triggers
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		start := time.Now()
		handler.ServeHTTP(rec, req)
		elapsed := time.Since(start)

		if rec.Code != http.StatusOK {
			t.Errorf("iteration %d: expected status %d, got %d", i, http.StatusOK, rec.Code)
		}
		if elapsed > 50*time.Millisecond {
			t.Errorf("iteration %d: request took %v, expected no delay", i, elapsed)
		}
	}
}

func TestFaultInjection_GetType(t *testing.T) {
	data := []byte(`{"type": "fault_injection"}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if policy.GetType() != PolicyTypeFaultInjection {
		t.Errorf("expected type %q, got %q", PolicyTypeFaultInjection, policy.GetType())
	}
}

func TestFaultInjection_AbortWithoutBody(t *testing.T) {
	data := []byte(`{
		"type": "fault_injection",
		"abort": {
			"status_code": 429,
			"percentage": 100
		}
	}`)

	policy, err := NewFaultInjectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	if err := policy.Init(&Config{}); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not have been called")
	})

	handler := policy.Apply(next)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
	if rec.Body.String() != "" {
		t.Errorf("expected empty body, got %q", rec.Body.String())
	}
}
