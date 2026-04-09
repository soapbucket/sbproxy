package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func TestWebhookConnector_Resolve_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var req webhookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode: %v", err)
		}
		if req.Timestamp == "" {
			t.Error("expected non-empty timestamp")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webhookResponse{
			Principal:   "webhook-user",
			Groups:      []string{"team-a"},
			Models:      []string{"gpt-4o"},
			Permissions: []string{"read"},
		})
	}))
	defer server.Close()

	c := NewWebhookConnector(server.URL, 5*time.Second, 3)
	perm, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil {
		t.Fatal("expected non-nil permission")
	}
	if perm.Principal != "webhook-user" {
		t.Errorf("expected principal webhook-user, got %s", perm.Principal)
	}
}

func TestWebhookConnector_Resolve_Retry(t *testing.T) {
	var attempts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := attempts.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webhookResponse{
			Principal: "retry-user",
		})
	}))
	defer server.Close()

	c := NewWebhookConnector(server.URL, 5*time.Second, 3)
	perm, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm == nil || perm.Principal != "retry-user" {
		t.Error("expected successful result after retries")
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestWebhookConnector_Resolve_CircuitBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewWebhookConnector(server.URL, 5*time.Second, 1)
	// Set threshold low for testing.
	c.threshold = 3

	// Trigger failures to open the circuit.
	for i := 0; i < 3; i++ {
		_, _ = c.Resolve(context.Background(), "api_key", "sk-test")
	}

	// Circuit should now be open.
	_, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err == nil {
		t.Fatal("expected circuit breaker error")
	}
}

func TestWebhookConnector_Resolve_CircuitBreaker_Recovery(t *testing.T) {
	var failMode atomic.Bool
	failMode.Store(true)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webhookResponse{
			Principal: "recovered-user",
		})
	}))
	defer server.Close()

	c := NewWebhookConnector(server.URL, 5*time.Second, 1)
	c.threshold = 3
	c.cooldown = 100 * time.Millisecond

	// Trigger failures to open the circuit.
	for i := 0; i < 3; i++ {
		_, _ = c.Resolve(context.Background(), "api_key", "sk-test")
	}

	// Circuit is open.
	_, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err == nil {
		t.Fatal("expected circuit breaker error while open")
	}

	// Wait for cooldown and fix the server.
	time.Sleep(150 * time.Millisecond)
	failMode.Store(false)

	// Should allow a probe request now (half-open).
	perm, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err != nil {
		t.Fatalf("expected recovery after cooldown: %v", err)
	}
	if perm == nil || perm.Principal != "recovered-user" {
		t.Error("expected recovered-user principal")
	}
}

func TestWebhookConnector_Resolve_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewWebhookConnector(server.URL, 100*time.Millisecond, 1)
	_, err := c.Resolve(context.Background(), "api_key", "sk-test")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
