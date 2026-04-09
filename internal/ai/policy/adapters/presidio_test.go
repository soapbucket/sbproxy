package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestPresidioAdapter_PIIDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)

		if body["language"] != "en" {
			t.Errorf("expected language 'en', got %v", body["language"])
		}

		// Presidio normally returns an array, but we wrap it for the object parser.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"entity_type": "PERSON", "score": 0.95, "start": 0, "end": 8},
				{"entity_type": "EMAIL_ADDRESS", "score": 0.87, "start": 15, "end": 35},
			},
		})
	}))
	defer server.Close()

	adapter := &PresidioAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "presidio-1",
		Name:   "pii check",
		Action: policy.GuardrailActionRedact,
		Config: map[string]any{
			"url":       server.URL,
			"threshold": 0.5,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "John Doe john@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered for PII detection")
	}
	if result.Details == "" {
		t.Error("expected details about detected entities")
	}
}

func TestPresidioAdapter_NoPII(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{},
		})
	}))
	defer server.Close()

	adapter := &PresidioAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "presidio-2",
		Name: "no pii",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "no personal info here")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered")
	}
}
