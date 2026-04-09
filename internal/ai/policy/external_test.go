package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestExternalGuardrail_Detect_Flagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %s", r.Header.Get("Authorization"))
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["text"] != "malicious content" {
			t.Errorf("expected 'malicious content', got %q", body["text"])
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"flagged": true, "details": "harmful content detected"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:     "ext-1",
		Name:   "test external",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"url":     server.URL,
			"api_key": "test-key",
		},
	}

	result, err := eg.Detect(context.Background(), config, "malicious content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered to be true")
	}
	if result.Details != "harmful content detected" {
		t.Errorf("expected 'harmful content detected', got %q", result.Details)
	}
	if result.Action != GuardrailActionBlock {
		t.Errorf("expected block action, got %s", result.Action)
	}
	if result.Latency <= 0 {
		t.Error("expected positive latency")
	}
}

func TestExternalGuardrail_Detect_NotFlagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"flagged": false})
	}))
	defer server.Close()

	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:   "ext-2",
		Name: "safe check",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	result, err := eg.Detect(context.Background(), config, "safe content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected triggered to be false")
	}
}

func TestExternalGuardrail_Detect_MissingURL(t *testing.T) {
	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:     "ext-3",
		Name:   "no url",
		Config: map[string]any{},
	}

	_, err := eg.Detect(context.Background(), config, "content")
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestExternalGuardrail_Detect_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:   "ext-4",
		Name: "error check",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	_, err := eg.Detect(context.Background(), config, "content")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestExternalGuardrail_Detect_CustomMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"flagged": false})
	}))
	defer server.Close()

	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:   "ext-5",
		Name: "custom method",
		Config: map[string]any{
			"url":    server.URL,
			"method": "PUT",
		},
	}

	result, err := eg.Detect(context.Background(), config, "content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered")
	}
}

func TestExternalGuardrail_Detect_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"flagged": false})
	}))
	defer server.Close()

	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:   "ext-6",
		Name: "timeout test",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := eg.Detect(ctx, config, "content")
	if err == nil {
		t.Fatal("expected error for context timeout")
	}
}

func TestCircuitBreaker_OpensAfterFailures(t *testing.T) {
	failCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		failCount++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("fail"))
	}))
	defer server.Close()

	eg := NewExternalGuardrail()
	config := &GuardrailConfig{
		ID:   "cb-1",
		Name: "circuit breaker test",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	// Trigger 5 failures to open the circuit.
	for i := 0; i < circuitBreakerThreshold; i++ {
		_, _ = eg.Detect(context.Background(), config, "content")
	}

	if eg.CircuitBreakerState() != circuitOpen {
		t.Errorf("expected circuit to be open, got %d", eg.CircuitBreakerState())
	}

	// Next call should be short-circuited (no error, not triggered).
	result, err := eg.Detect(context.Background(), config, "content")
	if err != nil {
		t.Fatalf("expected no error when circuit is open, got: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered when circuit is open")
	}
	if result.Details != "circuit breaker open, skipping external guardrail" {
		t.Errorf("unexpected details: %s", result.Details)
	}
}

func TestCircuitBreaker_ResetsOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker()

	// Record failures up to threshold.
	for i := 0; i < circuitBreakerThreshold; i++ {
		cb.RecordFailure()
	}
	if cb.State() != circuitOpen {
		t.Fatal("expected open state")
	}

	// Record success resets.
	cb.RecordSuccess()
	if cb.State() != circuitClosed {
		t.Fatal("expected closed state after success")
	}
	if !cb.Allow() {
		t.Fatal("expected allow after reset")
	}
}
