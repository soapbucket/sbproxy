package adapters

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

func TestNewCallback(t *testing.T) {
	tests := []struct {
		name     string
		config   *callbacks.CallbackConfig
		wantName string
		wantErr  bool
	}{
		{
			name: "langfuse",
			config: &callbacks.CallbackConfig{
				Type:      "langfuse",
				Endpoint:  "https://langfuse.example.com",
				APIKey:    "pk-test",
				SecretKey: "sk-test",
			},
			wantName: "langfuse",
		},
		{
			name: "langsmith",
			config: &callbacks.CallbackConfig{
				Type:     "langsmith",
				Endpoint: "https://api.smith.langchain.com",
				APIKey:   "ls-test",
			},
			wantName: "langsmith",
		},
		{
			name: "helicone",
			config: &callbacks.CallbackConfig{
				Type:     "helicone",
				Endpoint: "https://api.helicone.ai",
				APIKey:   "hc-test",
			},
			wantName: "helicone",
		},
		{
			name: "datadog",
			config: &callbacks.CallbackConfig{
				Type:     "datadog",
				Endpoint: "https://http-intake.logs.datadoghq.com",
				APIKey:   "dd-test",
			},
			wantName: "datadog",
		},
		{
			name: "otel",
			config: &callbacks.CallbackConfig{
				Type:     "otel",
				Endpoint: "http://localhost:4318",
			},
			wantName: "otel",
		},
		{
			name: "webhook",
			config: &callbacks.CallbackConfig{
				Type:      "webhook",
				Endpoint:  "https://example.com/hook",
				SecretKey: "webhook-secret",
			},
			wantName: "webhook",
		},
		{
			name: "unknown type",
			config: &callbacks.CallbackConfig{
				Type:     "unknown",
				Endpoint: "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "langfuse missing endpoint",
			config: &callbacks.CallbackConfig{
				Type:   "langfuse",
				APIKey: "pk",
			},
			wantErr: true,
		},
		{
			name: "webhook missing endpoint",
			config: &callbacks.CallbackConfig{
				Type: "webhook",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb, err := NewCallback(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cb.Name() != tt.wantName {
				t.Errorf("Name() = %q, want %q", cb.Name(), tt.wantName)
			}
		})
	}
}
