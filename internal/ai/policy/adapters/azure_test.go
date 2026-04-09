package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestAzureAdapter_HighSeverity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Azure uses subscription key header.
		if r.Header.Get("Ocp-Apim-Subscription-Key") != "azure-key" {
			t.Errorf("expected Ocp-Apim-Subscription-Key header, got %q", r.Header.Get("Ocp-Apim-Subscription-Key"))
		}
		// Azure should NOT use Bearer auth.
		if r.Header.Get("Authorization") != "" {
			t.Error("expected no Authorization header for Azure")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"categoriesAnalysis": []map[string]any{
				{"category": "Hate", "severity": float64(0)},
				{"category": "Violence", "severity": float64(4)},
			},
		})
	}))
	defer server.Close()

	adapter := &AzureAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "azure-1",
		Name:   "azure test",
		Action: policy.GuardrailActionBlock,
		Config: map[string]any{
			"url":       server.URL,
			"api_key":   "azure-key",
			"threshold": float64(2),
		},
	}

	result, err := adapter.Detect(context.Background(), config, "violent content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered for severity 4 > threshold 2")
	}
	if result.Details == "" {
		t.Error("expected details")
	}
}

func TestAzureAdapter_BelowThreshold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"categoriesAnalysis": []map[string]any{
				{"category": "Hate", "severity": float64(1)},
				{"category": "Violence", "severity": float64(0)},
			},
		})
	}))
	defer server.Close()

	adapter := &AzureAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "azure-2",
		Name: "azure safe",
		Config: map[string]any{
			"url":       server.URL,
			"api_key":   "key",
			"threshold": float64(2),
		},
	}

	result, err := adapter.Detect(context.Background(), config, "safe content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered for severity below threshold")
	}
}

func TestAzureAdapter_MissingURL(t *testing.T) {
	adapter := &AzureAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "azure-3",
		Name:   "no url",
		Config: map[string]any{},
	}

	_, err := adapter.Detect(context.Background(), config, "content")
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}
