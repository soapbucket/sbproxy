package ddos

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestEnforcer creates a DDoS enforcer with given thresholds for testing.
func newTestEnforcer(t *testing.T, requestThreshold, connectionThreshold int) *ddosPolicy {
	t.Helper()

	cfg := map[string]interface{}{
		"type":     "ddos_protection",
		"disabled": false,
		"detection": map[string]interface{}{
			"request_rate_threshold":    requestThreshold,
			"connection_rate_threshold": connectionThreshold,
			"detection_window":          "60s",
		},
		"mitigation": map[string]interface{}{
			"auto_block":          true,
			"block_duration":      "1m",
			"block_after_attacks": 1,
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	return enforcer.(*ddosPolicy)
}

// TestDDoS_E2E_NormalTrafficPasses verifies that normal traffic below thresholds passes through.
func TestDDoS_E2E_NormalTrafficPasses(t *testing.T) {
	dp := newTestEnforcer(t, 100, 100) // high thresholds

	passCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passCount++
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	// Send 10 requests - all should pass.
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, w.Code)
		}
	}

	if passCount != 10 {
		t.Errorf("expected 10 passed requests, got %d", passCount)
	}
}

// TestDDoS_E2E_ExcessiveRequests_TriggerBlock verifies that exceeding the threshold triggers blocking.
func TestDDoS_E2E_ExcessiveRequests_TriggerBlock(t *testing.T) {
	dp := newTestEnforcer(t, 5, 0) // low request threshold, no connection threshold

	passCount := 0
	blockCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passCount++
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	// Send requests from the same IP until we exceed the threshold.
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			blockCount++
		}
	}

	if blockCount == 0 {
		t.Error("expected at least one request to be blocked after exceeding threshold")
	}
	if passCount == 20 {
		t.Error("expected some requests to be blocked, but all 20 passed")
	}
	t.Logf("passed: %d, blocked: %d (threshold: 5)", passCount, blockCount)
}

// TestDDoS_E2E_DifferentIPs_TrackedIndependently verifies that different source IPs
// are tracked separately so traffic from one IP does not affect another.
func TestDDoS_E2E_DifferentIPs_TrackedIndependently(t *testing.T) {
	dp := newTestEnforcer(t, 5, 0) // low threshold

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	// Fill up IP1's quota (send threshold+1 requests to trigger detection).
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// IP2 should still be able to make requests.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("IP2 request %d: expected 200 (independent tracking), got %d", i, w.Code)
		}
	}
}

// TestDDoS_E2E_DisabledPolicy_PassesAll verifies that a disabled DDoS policy passes all traffic.
func TestDDoS_E2E_DisabledPolicy_PassesAll(t *testing.T) {
	cfg := map[string]interface{}{
		"type":     "ddos_protection",
		"disabled": true,
		"detection": map[string]interface{}{
			"request_rate_threshold": 1, // would block immediately if not disabled
		},
	}
	data, _ := json.Marshal(cfg)
	enforcer, err := New(data)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	dp := enforcer.(*ddosPolicy)

	passCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passCount++
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("disabled policy request %d: expected 200, got %d", i, w.Code)
		}
	}

	if passCount != 10 {
		t.Errorf("expected all 10 requests to pass, got %d", passCount)
	}
}

// TestDDoS_E2E_MultipleIPs_IndependentCounters verifies counters are per-IP.
func TestDDoS_E2E_MultipleIPs_IndependentCounters(t *testing.T) {
	dp := newTestEnforcer(t, 3, 0)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	// Send 3 requests from 5 different IPs. All should pass since each IP
	// has its own counter.
	for ip := 1; ip <= 5; ip++ {
		for req := 0; req < 3; req++ {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = fmt.Sprintf("10.0.0.%d:12345", ip)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("IP 10.0.0.%d request %d: expected 200, got %d", ip, req, w.Code)
			}
		}
	}
}

// TestDDoS_E2E_EmptyRemoteAddr_Passes verifies that requests without a remote address pass.
func TestDDoS_E2E_EmptyRemoteAddr_Passes(t *testing.T) {
	dp := newTestEnforcer(t, 1, 0) // very low threshold

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "" // no remote addr
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when remote addr is empty")
	}
}

// TestDDoS_E2E_BlockedIP_Returns429 verifies that a blocked IP gets 429 status.
func TestDDoS_E2E_BlockedIP_Returns429(t *testing.T) {
	dp := newTestEnforcer(t, 3, 0)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(next)

	// Send enough requests to exceed threshold and trigger auto-block.
	blockedSeen := false
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.99:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			blockedSeen = true
			break
		}
	}

	if !blockedSeen {
		t.Error("expected at least one 429 response after exceeding threshold")
	}
}
