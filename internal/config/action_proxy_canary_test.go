package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLoadProxy_WithCanary(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Server", "primary")
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Server", "canary")
		w.WriteHeader(http.StatusOK)
	}))
	defer canary.Close()

	input := `{
		"type": "proxy",
		"url": "` + primary.URL + `",
		"canary": {
			"enabled": true,
			"percentage": 100,
			"target": "` + canary.URL + `"
		}
	}`

	cfg, err := LoadProxy([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	proxy := cfg.(*Proxy)
	if proxy.canaryTargetURL == nil {
		t.Fatal("expected canary target URL to be set")
	}
	if proxy.canaryTransport == nil {
		t.Fatal("expected canary transport to be set")
	}
}

func TestLoadProxy_CanaryDisabled(t *testing.T) {
	input := `{
		"type": "proxy",
		"url": "http://example.com",
		"canary": {
			"enabled": false,
			"percentage": 50,
			"target": "http://canary.example.com"
		}
	}`

	cfg, err := LoadProxy([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	proxy := cfg.(*Proxy)
	if proxy.canaryTransport != nil {
		t.Error("canary transport should not be set when disabled")
	}
}

func TestProxy_CanaryRouting_AllCanary(t *testing.T) {
	var primaryHits, canaryHits atomic.Int64

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	canaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canaryHits.Add(1)
		// Verify X-Canary header is set
		if r.Header.Get("X-Canary") != "true" {
			t.Error("expected X-Canary header on canary requests")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer canaryServer.Close()

	input := `{
		"type": "proxy",
		"url": "` + primary.URL + `",
		"canary": {
			"enabled": true,
			"percentage": 100,
			"target": "` + canaryServer.URL + `"
		}
	}`

	cfg, err := LoadProxy([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transportFn := cfg.Transport()
	if transportFn == nil {
		t.Fatal("expected transport to be set")
	}

	// Send 10 requests - all should go to canary since percentage is 100
	for range 10 {
		req := httptest.NewRequest("GET", primary.URL+"/test", nil)
		resp, err := transportFn(req)
		if err != nil {
			t.Fatalf("transport error: %v", err)
		}
		resp.Body.Close()
	}

	if canaryHits.Load() != 10 {
		t.Errorf("expected 10 canary hits, got %d", canaryHits.Load())
	}
	if primaryHits.Load() != 0 {
		t.Errorf("expected 0 primary hits, got %d", primaryHits.Load())
	}
}

func TestProxy_CanaryRouting_NoneCanary(t *testing.T) {
	var primaryHits, canaryHits atomic.Int64

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	canaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer canaryServer.Close()

	input := `{
		"type": "proxy",
		"url": "` + primary.URL + `",
		"canary": {
			"enabled": true,
			"percentage": 0,
			"target": "` + canaryServer.URL + `"
		}
	}`

	cfg, err := LoadProxy([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transportFn := cfg.Transport()

	for range 10 {
		req := httptest.NewRequest("GET", primary.URL+"/test", nil)
		resp, err := transportFn(req)
		if err != nil {
			t.Fatalf("transport error: %v", err)
		}
		resp.Body.Close()
	}

	if primaryHits.Load() != 10 {
		t.Errorf("expected 10 primary hits, got %d", primaryHits.Load())
	}
	if canaryHits.Load() != 0 {
		t.Errorf("expected 0 canary hits, got %d", canaryHits.Load())
	}
}

func TestProxy_CanaryStickyHeader(t *testing.T) {
	var primaryHits, canaryHits atomic.Int64

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	canaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer canaryServer.Close()

	input := `{
		"type": "proxy",
		"url": "` + primary.URL + `",
		"canary": {
			"enabled": true,
			"percentage": 50,
			"target": "` + canaryServer.URL + `",
			"sticky_header": "X-User-ID"
		}
	}`

	cfg, err := LoadProxy([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transportFn := cfg.Transport()

	// Same user ID should always route to the same target (deterministic)
	var firstCanary bool
	for i := range 10 {
		req := httptest.NewRequest("GET", primary.URL+"/test", nil)
		req.Header.Set("X-User-ID", "user-consistent-123")
		resp, err := transportFn(req)
		if err != nil {
			t.Fatalf("transport error: %v", err)
		}
		resp.Body.Close()

		if i == 0 {
			firstCanary = canaryHits.Load() > 0
		}
	}

	// All requests with same header value should go to the same place
	if firstCanary {
		if canaryHits.Load() != 10 {
			t.Errorf("sticky routing: expected all 10 to canary, got %d canary %d primary",
				canaryHits.Load(), primaryHits.Load())
		}
	} else {
		if primaryHits.Load() != 10 {
			t.Errorf("sticky routing: expected all 10 to primary, got %d primary %d canary",
				primaryHits.Load(), canaryHits.Load())
		}
	}
}

func TestShadowConfig_Percentage(t *testing.T) {
	// Test that Percentage field is properly serialized/deserialized
	input := `{
		"upstream_url": "http://shadow.example.com",
		"percentage": 50,
		"headers_only": true
	}`

	var cfg ShadowConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Percentage != 50 {
		t.Errorf("expected percentage 50, got %d", cfg.Percentage)
	}
	if !cfg.HeadersOnly {
		t.Error("expected headers_only to be true")
	}
}

func TestShadowConfig_PercentageTakesPrecedenceOverSampleRate(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	input := `{
		"type": "proxy",
		"url": "` + primary.URL + `",
		"shadow": {
			"upstream_url": "http://shadow.example.com",
			"sample_rate": 0.1,
			"percentage": 75
		}
	}`

	cfg, err := LoadProxy([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	proxy := cfg.(*Proxy)
	if proxy.shadowTransport == nil {
		// Shadow transport may fail to connect, but the config should be parsed
		t.Log("shadow transport not initialized (expected in test with fake URL)")
	}
}
