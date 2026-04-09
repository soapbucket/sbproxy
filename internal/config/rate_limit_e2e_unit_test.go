package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRateLimit_FirstRequest_E2EConfig tests the rate limit configuration
// from the e2e test fixture to verify the first request succeeds
func TestRateLimit_FirstRequest_E2EConfig(t *testing.T) {
	// Load the exact JSON config from the e2e test fixture
	configJSON := `{
		"id": "rate-limit",
		"hostname": "rate-limit.test",
		"policies": [
			{
				"type": "rate_limiting",
				"requests_per_minute": 10,
				"burst_size": 5,
				"algorithm": "sliding_window"
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://backend-server"
		}
	}`

	// Create a mock backend server that returns 200 OK
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backendServer.Close()

	// Replace the backend URL in the config with our test server
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	action := configMap["action"].(map[string]interface{})
	action["url"] = backendServer.URL

	// Re-marshal the config
	updatedConfigJSON, err := json.Marshal(configMap)
	if err != nil {
		t.Fatalf("failed to marshal updated config: %v", err)
	}

	// Load the config
	var cfg Config
	if err := json.Unmarshal(updatedConfigJSON, &cfg); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	// Create a request with a client IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Host = "rate-limit.test"
	w := httptest.NewRecorder()

	// Make the first request - should succeed with 200
	cfg.ServeHTTP(w, req)

	// Verify the first request returns 200 (as expected in the e2e test)
	if w.Code != http.StatusOK {
		t.Errorf("first request: expected status code %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify the response body from backend
	if w.Body.String() != "OK" {
		t.Errorf("first request: expected body %q, got %q", "OK", w.Body.String())
	}

	// Verify rate limit headers are present (if configured)
	// The rate limiting policy should add headers even on successful requests
	// Check for X-RateLimit-* headers if they're configured
	limitHeader := w.Header().Get("X-RateLimit-Limit")
	remainingHeader := w.Header().Get("X-RateLimit-Remaining")
	if limitHeader == "" && remainingHeader == "" {
		// Headers might not be configured, which is okay
		t.Log("Rate limit headers not present (may not be configured)")
	}
}

// TestRateLimit_FirstRequest_WithMultipleRequests verifies that the first request
// succeeds and subsequent requests within the limit also succeed
func TestRateLimit_FirstRequest_WithMultipleRequests(t *testing.T) {
	// Load the exact JSON config from the e2e test fixture
	configJSON := `{
		"id": "rate-limit",
		"hostname": "rate-limit.test",
		"policies": [
			{
				"type": "rate_limiting",
				"requests_per_minute": 10,
				"burst_size": 5,
				"algorithm": "sliding_window"
			}
		],
		"action": {
			"type": "proxy",
			"url": "http://backend-server"
		}
	}`

	// Create a mock backend server
	requestCount := 0
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backendServer.Close()

	// Replace the backend URL in the config with our test server
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	action := configMap["action"].(map[string]interface{})
	action["url"] = backendServer.URL

	// Re-marshal the config
	updatedConfigJSON, err := json.Marshal(configMap)
	if err != nil {
		t.Fatalf("failed to marshal updated config: %v", err)
	}

	// Load the config
	var cfg Config
	if err := json.Unmarshal(updatedConfigJSON, &cfg); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	clientIP := "192.168.1.100"

	// Make the first request - should succeed with 200
	t.Run("First request succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = clientIP + ":12345"
		req.Host = "rate-limit.test"
		w := httptest.NewRecorder()

		cfg.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("first request: expected status code %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
		}
		if requestCount != 1 {
			t.Errorf("expected backend to receive 1 request, got %d", requestCount)
		}
	})

	// Make a few more requests within the limit - should all succeed
	t.Run("Subsequent requests within limit succeed", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = clientIP + ":12345"
			req.Host = "rate-limit.test"
			w := httptest.NewRecorder()

			cfg.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("request %d: expected status code %d, got %d. Body: %s", i+2, http.StatusOK, w.Code, w.Body.String())
			}
		}

		// Verify backend received all requests
		if requestCount != 6 {
			t.Errorf("expected backend to receive 6 requests total, got %d", requestCount)
		}
	})
}

