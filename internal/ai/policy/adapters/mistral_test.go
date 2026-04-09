package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestMistralAdapter_CategoryScoreExceedsThreshold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{
					"categories": map[string]any{
						"sexual":   false,
						"violence": true,
					},
					"category_scores": map[string]any{
						"sexual":   0.1,
						"violence": 0.95,
					},
				},
			},
		})
	}))
	defer server.Close()

	adapter := &MistralAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "mistral-1",
		Name:   "mistral test",
		Action: policy.GuardrailActionBlock,
		Config: map[string]any{
			"url":       server.URL,
			"api_key":   "mistral-key",
			"threshold": 0.7,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "violent text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered for violence score 0.95 > threshold 0.7")
	}
	if result.Details == "" {
		t.Error("expected details")
	}
}

func TestMistralAdapter_BelowThreshold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{
					"categories": map[string]any{
						"sexual":   false,
						"violence": false,
					},
					"category_scores": map[string]any{
						"sexual":   0.05,
						"violence": 0.1,
					},
				},
			},
		})
	}))
	defer server.Close()

	adapter := &MistralAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "mistral-2",
		Name: "mistral safe",
		Config: map[string]any{
			"url":       server.URL,
			"threshold": 0.7,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "safe content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered for scores below threshold")
	}
}

func TestMistralAdapter_CategoryBooleanFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response with categories but no scores.
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{
					"categories": map[string]any{
						"harassment": true,
					},
				},
			},
		})
	}))
	defer server.Close()

	adapter := &MistralAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "mistral-3",
		Name: "mistral bool fallback",
		Config: map[string]any{
			"url":       server.URL,
			"threshold": 0.7,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "harassing content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered via category boolean fallback")
	}
}
