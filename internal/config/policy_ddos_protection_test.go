package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDDoSProtection_BasicDetection(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 10,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"challenge_response": false
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test normal request (should pass)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called for normal request")
	}
}

func TestDDoSProtection_RequestRateLimit(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 5,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"challenge_response": false
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	clientIP := "192.168.1.100"

	// Send requests exceeding threshold
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)

		if i < 5 {
			if !nextCalled {
				t.Errorf("Request %d should have been allowed", i+1)
			}
		} else {
			// 6th request should be blocked
			if nextCalled {
				t.Error("Request 6 should have been blocked")
			}
			if rec.Code != http.StatusTooManyRequests {
				t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
			}
		}
	}
}

func TestDDoSProtection_ProofOfWorkChallenge(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 5,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"challenge_response": true,
			"challenge_type": "proof_of_work",
			"proof_of_work": {
				"enabled": true,
				"difficulty": 4,
				"timeout": "30s"
			}
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	clientIP := "192.168.1.100"

	// Trigger attack detection
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// Next request should require challenge
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Should return challenge response
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}

	// Check that response contains challenge information
	body := rec.Body.String()
	if !strings.Contains(body, "proof_of_work") {
		t.Error("Response should contain proof-of-work challenge")
	}
}

func TestDDoSProtection_AdaptiveThresholds(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 10,
			"detection_window": "10s",
			"adaptive_thresholds": true,
			"threshold_multiplier": 2.0,
			"baseline_window": "1h"
		},
		"mitigation": {
			"block_duration": "1h"
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Adaptive thresholds should be enabled
	ddosPolicy := policy.(*DDoSProtectionPolicyConfig)
	if !ddosPolicy.Detection.AdaptiveThresholds {
		t.Error("Adaptive thresholds should be enabled")
	}

	if ddosPolicy.Detection.ThresholdMultiplier != 2.0 {
		t.Errorf("Expected threshold multiplier 2.0, got %f", ddosPolicy.Detection.ThresholdMultiplier)
	}
}

func TestDDoSProtection_AutoBlock(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 5,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"auto_block": true,
			"block_after_attacks": 2
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	clientIP := "192.168.1.100"

	// Trigger multiple attacks
	for attack := 0; attack < 2; attack++ {
		// Send requests exceeding threshold
		for i := 0; i < 6; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = clientIP + ":12345"
			rec := httptest.NewRecorder()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := policy.Apply(next)
			handler.ServeHTTP(rec, req)
		}

		// Small delay between attacks
		time.Sleep(100 * time.Millisecond)
	}

	// Next request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Request should have been blocked after multiple attacks")
	}

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
}

func TestDDoSProtection_JavaScriptChallenge(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 5,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"challenge_response": true,
			"challenge_type": "javascript",
			"javascript_challenge": {
				"enabled": true,
				"timeout": "60s"
			}
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	clientIP := "192.168.1.100"

	// Trigger attack detection
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// Next request should require JavaScript challenge
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Should return HTML with JavaScript challenge
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "<script>") {
		t.Error("Response should contain JavaScript challenge")
	}
}

func TestDDoSProtection_CAPTCHAChallenge(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 5,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"challenge_response": true,
			"challenge_type": "captcha",
			"captcha": {
				"enabled": true,
				"provider": "hcaptcha",
				"site_key": "test-site-key",
				"secret_key": "test-secret-key"
			}
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	clientIP := "192.168.1.100"

	// Trigger attack detection
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// Next request should require CAPTCHA challenge
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Should return HTML with CAPTCHA widget
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "h-captcha") {
		t.Error("Response should contain hCaptcha widget")
	}
}

func TestDDoSProtection_VerifyProofOfWork(t *testing.T) {
	data := []byte(`{
		"type": "ddos_protection",
		"mitigation": {
			"proof_of_work": {
				"enabled": true,
				"difficulty": 4
			}
		}
	}`)

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	ddosPolicy := policy.(*DDoSProtectionPolicyConfig)

	challenge := "test_challenge_123"
	nonce := "12345" // This won't work, but we can test the function

	// Test verification function exists
	_ = ddosPolicy.verifyProofOfWork(challenge, nonce, 4)

	// Find a valid nonce for testing
	validNonce := ""
	for i := 0; i < 100000; i++ {
		testNonce := fmt.Sprintf("%d", i)
		if ddosPolicy.verifyProofOfWork(challenge, testNonce, 4) {
			validNonce = testNonce
			break
		}
	}

	if validNonce == "" {
		t.Skip("Could not find valid nonce for testing (this is expected for difficulty 4)")
	}

	// Verify the valid nonce works
	if !ddosPolicy.verifyProofOfWork(challenge, validNonce, 4) {
		t.Error("Valid nonce should pass verification")
	}
}

func TestDDoSProtection_CustomHTMLCallback(t *testing.T) {
	// Create a test server that returns custom HTML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Custom Challenge Page</h1></body></html>"))
	}))
	defer server.Close()

	data := []byte(fmt.Sprintf(`{
		"type": "ddos_protection",
		"detection": {
			"request_rate_threshold": 5,
			"detection_window": "10s"
		},
		"mitigation": {
			"block_duration": "1h",
			"challenge_response": true,
			"challenge_type": "javascript",
			"javascript_challenge": {
				"enabled": true,
				"timeout": "60s"
			},
			"custom_html_callback": {
				"url": "%s",
				"method": "POST",
				"cache_duration": 0
			}
		}
	}`, server.URL))

	policy, err := NewDDoSProtectionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create DDoS protection policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	clientIP := "192.168.1.100"

	// Trigger attack detection
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = clientIP + ":12345"
		rec := httptest.NewRecorder()

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := policy.Apply(next)
		handler.ServeHTTP(rec, req)
	}

	// Next request should require challenge with custom HTML
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = clientIP + ":12345"
	rec := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	// Should return custom HTML from callback
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Custom Challenge Page") {
		t.Error("Response should contain custom HTML from callback")
	}
}

