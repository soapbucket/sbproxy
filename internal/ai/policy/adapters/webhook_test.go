package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestWebhookAdapter_Flagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)

		if body["text"] != "bad content" {
			t.Errorf("expected text field, got %v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"flagged": true,
			"reason":  "custom rule violated",
		})
	}))
	defer server.Close()

	adapter := &WebhookAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "webhook-1",
		Name:   "webhook test",
		Action: policy.GuardrailActionBlock,
		Config: map[string]any{
			"url": server.URL,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "bad content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered")
	}
	if result.Details != "custom rule violated" {
		t.Errorf("expected 'custom rule violated', got %q", result.Details)
	}
}

func TestWebhookAdapter_Blocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"blocked": true,
			"details": "blocked by webhook",
		})
	}))
	defer server.Close()

	adapter := &WebhookAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "webhook-2",
		Name: "blocked webhook",
		Config: map[string]any{
			"url": server.URL,
		},
	}

	result, err := adapter.Detect(context.Background(), config, "content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered via blocked field")
	}
}

func TestWebhookAdapter_CustomBodyField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)

		if body["content"] != "test data" {
			t.Errorf("expected 'content' field with 'test data', got %v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"flagged": false})
	}))
	defer server.Close()

	adapter := &WebhookAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "webhook-3",
		Name: "custom field",
		Config: map[string]any{
			"url":        server.URL,
			"body_field": "content",
		},
	}

	result, err := adapter.Detect(context.Background(), config, "test data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered")
	}
}

func TestWebhookAdapter_CustomResponseField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"is_unsafe": true,
			"reason":    "custom unsafe",
		})
	}))
	defer server.Close()

	adapter := &WebhookAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "webhook-4",
		Name: "custom response field",
		Config: map[string]any{
			"url":            server.URL,
			"response_field": "is_unsafe",
		},
	}

	result, err := adapter.Detect(context.Background(), config, "content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered via custom response field")
	}
}

func TestWebhookAdapter_MissingURL(t *testing.T) {
	adapter := &WebhookAdapter{}
	config := &policy.GuardrailConfig{
		ID:     "webhook-5",
		Name:   "no url",
		Config: map[string]any{},
	}

	_, err := adapter.Detect(context.Background(), config, "content")
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestWebhookAdapter_CustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-Header") != "custom-value" {
			t.Errorf("expected X-Custom-Header, got %q", r.Header.Get("X-Custom-Header"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"flagged": false})
	}))
	defer server.Close()

	adapter := &WebhookAdapter{}
	config := &policy.GuardrailConfig{
		ID:   "webhook-6",
		Name: "custom headers",
		Config: map[string]any{
			"url": server.URL,
			"headers": map[string]any{
				"X-Custom-Header": "custom-value",
			},
		},
	}

	result, err := adapter.Detect(context.Background(), config, "content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered")
	}
}
