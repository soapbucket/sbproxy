package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProblemDetails_Write(t *testing.T) {
	cfg := &ProblemDetailsConfig{
		Enable:  true,
		BaseURI: "https://api.example.com/problems",
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()

	writeProblemDetail(rec, req, http.StatusBadGateway, "upstream is down", cfg)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("expected application/problem+json, got %s", rec.Header().Get("Content-Type"))
	}

	var pd ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("failed to parse problem detail: %v", err)
	}

	if pd.Status != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", pd.Status)
	}

	if pd.Title != "Bad Gateway" {
		t.Errorf("expected title Bad Gateway, got %s", pd.Title)
	}

	if pd.Detail != "upstream is down" {
		t.Errorf("expected detail 'upstream is down', got %s", pd.Detail)
	}

	if pd.Instance != "/api/test" {
		t.Errorf("expected instance /api/test, got %s", pd.Instance)
	}
}

func TestProblemDetails_Disabled(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()

	writeProblemDetail(rec, req, http.StatusBadGateway, "Bad Gateway", nil)

	// Should fall back to plain text
	if rec.Header().Get("Content-Type") == "application/problem+json" {
		t.Error("should not use problem+json when disabled")
	}
}

func TestProblemTypeForStatus(t *testing.T) {
	tests := []struct {
		status   int
		baseURI  string
		expected string
	}{
		{502, "https://api.example.com", "https://api.example.com/bad-gateway"},
		{504, "https://api.example.com", "https://api.example.com/gateway-timeout"},
		{429, "https://api.example.com", "https://api.example.com/rate-limit-exceeded"},
		{425, "https://api.example.com", "https://api.example.com/too-early"},
		{500, "about:blank", "about:blank"},
		{500, "", "about:blank"},
	}

	for _, tt := range tests {
		result := problemTypeForStatus(tt.status, tt.baseURI)
		if result != tt.expected {
			t.Errorf("problemTypeForStatus(%d, %q) = %q, want %q", tt.status, tt.baseURI, result, tt.expected)
		}
	}
}
