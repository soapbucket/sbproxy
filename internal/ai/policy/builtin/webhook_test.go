package builtin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestWebhookDetector(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		config     map[string]any
		triggered  bool
		wantErr    bool
	}{
		{
			name: "webhook returns triggered",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"triggered": true, "details": "blocked by webhook"}`))
			},
			triggered: true,
		},
		{
			name: "webhook returns not triggered",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"triggered": false}`))
			},
			triggered: false,
		},
		{
			name: "webhook returns error status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
			},
			triggered: true,
		},
		{
			name: "custom trigger and details fields",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"blocked": true, "reason": "custom reason"}`))
			},
			config:    map[string]any{"trigger_field": "blocked", "details_field": "reason"},
			triggered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			d := NewWebhookDetector(srv.Client())

			cfg := tt.config
			if cfg == nil {
				cfg = map[string]any{}
			}
			cfg["url"] = srv.URL

			config := &policy.GuardrailConfig{
				ID:     "test-webhook",
				Name:   "Webhook",
				Action: policy.GuardrailActionBlock,
				Config: cfg,
			}

			result, err := d.Detect(context.Background(), config, "test content")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered != tt.triggered {
				t.Errorf("triggered = %v, want %v (details: %s)", result.Triggered, tt.triggered, result.Details)
			}
		})
	}
}

func TestWebhookDetectorNoURL(t *testing.T) {
	d := NewWebhookDetector(nil)
	cfg := &policy.GuardrailConfig{
		ID:     "test",
		Name:   "test",
		Action: policy.GuardrailActionBlock,
		Config: map[string]any{},
	}
	result, err := d.Detect(context.Background(), cfg, "content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected not triggered when no URL configured")
	}
}
