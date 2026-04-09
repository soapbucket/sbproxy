package config

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestGeoBlockingPolicy_BlockedCountries(t *testing.T) {
	data := []byte(`{
		"type": "geo_blocking",
		"blocked_countries": ["CN", "RU"]
	}`)

	policy, err := NewGeoBlockingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create geo-blocking policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test request from blocked country
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Add location data to request context
	requestData := reqctx.NewRequestData()
	requestData.Location = &reqctx.Location{
		CountryCode: "CN",
	}
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Next handler should not have been called for blocked country")
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestGeoBlockingPolicy_AllowedCountries(t *testing.T) {
	data := []byte(`{
		"type": "geo_blocking",
		"allowed_countries": ["US", "CA"]
	}`)

	policy, err := NewGeoBlockingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create geo-blocking policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test request from allowed country
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Add location data to request context
	requestData := reqctx.NewRequestData()
	requestData.Location = &reqctx.Location{
		CountryCode: "US",
	}
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called for allowed country")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestGeoBlockingPolicy_NoLocationData(t *testing.T) {
	data := []byte(`{
		"type": "geo_blocking",
		"blocked_countries": ["CN", "RU"]
	}`)

	policy, err := NewGeoBlockingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create geo-blocking policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test request without location data (should allow - fail open)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called when no location data")
	}
}

func TestGeoBlockingPolicy_InvalidConfig(t *testing.T) {
	data := []byte(`{
		"type": "geo_blocking",
		"allowed_countries": ["US"],
		"blocked_countries": ["CN"]
	}`)

	_, err := NewGeoBlockingPolicy(data)
	if err == nil {
		t.Error("Expected error when both allowed and blocked countries are specified")
	}
}

func TestGeoBlockingPolicy_RedirectAction(t *testing.T) {
	data := []byte(`{
		"type": "geo_blocking",
		"blocked_countries": ["CN"],
		"action": "redirect",
		"redirect_url": "https://example.com/blocked"
	}`)

	policy, err := NewGeoBlockingPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create geo-blocking policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	// Test request from blocked country with redirect action
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Add location data to request context
	requestData := reqctx.NewRequestData()
	requestData.Location = &reqctx.Location{
		CountryCode: "CN",
	}
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("Next handler should not have been called")
	}

	if rec.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rec.Code)
	}

	location := rec.Header().Get("Location")
	if location != "https://example.com/blocked" {
		t.Errorf("Expected redirect to https://example.com/blocked, got %s", location)
	}
}

