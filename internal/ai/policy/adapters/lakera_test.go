package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestLakeraAdapter_Flagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["input"] != "inject this prompt" {
			t.Errorf("expected input field, got %v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{
					"flagged": true,
					"categories": map[string]any{
						"prompt_injection": true,
						"jailbreak":        false,
					},
				},
			},
		})
	}))
	defer server.Close()

	adapter := &LakeraAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "lakera-1",
		Name:   "lakera test",
		Action: policy.GuardrailActionBlock,
		Config: map[string]any{
			"url":     server.URL,
			"api_key": "lk-test",
		},
	}

	result, err := adapter.Detect(context.Background(), config, "inject this prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered")
	}
	if result.Details != "Lakera Guard: prompt_injection detected" {
		t.Errorf("unexpected details: %s", result.Details)
	}
}

func TestLakeraAdapter_NotFlagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"flagged": false, "categories": map[string]any{}},
			},
		})
	}))
	defer server.Close()

	adapter := &LakeraAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "lakera-2",
		Name: "lakera safe",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "normal content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered")
	}
}
