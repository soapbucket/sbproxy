package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewSRIPolicy(t *testing.T) {
	data := []byte(`{
		"type": "sri",
		"validate_responses": true,
		"fail_on_invalid_integrity": true,
		"known_hashes": {
			"https://example.com/script.js": ["sha384-abc123"]
		},
		"algorithm": "sha384"
	}`)

	policy, err := NewSRIPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create SRI policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	sriPolicy := policy.(*SRIPolicyConfig)
	if !sriPolicy.ValidateResponses {
		t.Error("ValidateResponses should be true")
	}
	if !sriPolicy.FailOnInvalidIntegrity {
		t.Error("FailOnInvalidIntegrity should be true")
	}
	if sriPolicy.validator == nil {
		t.Error("Validator should be initialized")
	}
	if sriPolicy.generator == nil {
		t.Error("Generator should be initialized")
	}
}

func TestSRIPolicy_Apply(t *testing.T) {
	data := []byte(`{
		"type": "sri",
		"validate_responses": true,
		"fail_on_invalid_integrity": false,
		"known_hashes": {
			"https://example.com/script.js": ["sha384-abc123"]
		}
	}`)

	policy, err := NewSRIPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create SRI policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/script.js", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.Header().Set("Integrity", "sha384-abc123")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Next handler should have been called")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestSRIPolicy_Disabled(t *testing.T) {
	data := []byte(`{
		"type": "sri",
		"disabled": true,
		"validate_responses": true
	}`)

	policy, err := NewSRIPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create SRI policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

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
		t.Error("Next handler should have been called when policy is disabled")
	}
}

func TestSRIPolicy_GenerateIntegrityForResponse(t *testing.T) {
	data := []byte(`{
		"type": "sri",
		"algorithm": "sha256"
	}`)

	policy, err := NewSRIPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create SRI policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	sriPolicy := policy.(*SRIPolicyConfig)

	// Verify the generator is set up correctly
	if sriPolicy.generator == nil {
		t.Error("Generator should be initialized")
	}
}

func TestSRIPolicy_ValidateRequest(t *testing.T) {
	data := []byte(`{
		"type": "sri",
		"validate_requests": true,
		"known_hashes": {
			"https://example.com/script.js": ["sha384-abc123"]
		}
	}`)

	policy, err := NewSRIPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create SRI policy: %v", err)
	}

	cfg := &Config{}
	if err := policy.Init(cfg); err != nil {
		t.Fatalf("Failed to init policy: %v", err)
	}

	sriPolicy := policy.(*SRIPolicyConfig)

	tests := []struct {
		name      string
		url       string
		integrity string
		wantErr   bool
	}{
		{"valid integrity", "https://example.com/script.js", "sha384-abc123", false},
		{"invalid integrity", "https://example.com/script.js", "sha384-invalid", true},
		{"no integrity", "https://example.com/script.js", "", false},
		{"unknown resource", "https://example.com/other.js", "sha384-abc123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			if tt.integrity != "" {
				req.Header.Set("Integrity", tt.integrity)
			}

			err := sriPolicy.ValidateRequest(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractIntegrityFromLinkHeader(t *testing.T) {
	tests := []struct {
		name      string
		linkHeader string
		want      string
	}{
		{"valid", `<https://example.com/script.js>; rel="preload"; integrity="sha384-abc123"`, "sha384-abc123"},
		{"no integrity", `<https://example.com/script.js>; rel="preload"`, ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIntegrityFromLinkHeader(tt.linkHeader)
			if got != tt.want {
				t.Errorf("extractIntegrityFromLinkHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

