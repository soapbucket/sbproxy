package aiproxy

import (
	"encoding/json"
	"testing"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestAIProxy_Registration(t *testing.T) {
	factory, ok := plugin.GetAction("ai_proxy")
	if !ok {
		t.Fatal("ai_proxy action not registered")
	}
	if factory == nil {
		t.Fatal("ai_proxy factory is nil")
	}
}

func TestAIProxy_Type(t *testing.T) {
	cfg := `{
		"type": "ai_proxy",
		"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}]
	}`
	factory, ok := plugin.GetAction("ai_proxy")
	if !ok {
		t.Fatal("ai_proxy action not registered")
	}
	handler, err := factory(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler.Type() != "ai_proxy" {
		t.Errorf("expected type ai_proxy, got %s", handler.Type())
	}
}

func TestAIProxy_ConfigParsing(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr bool
	}{
		{
			name: "valid single provider",
			cfg: `{
				"type": "ai_proxy",
				"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}]
			}`,
			wantErr: false,
		},
		{
			name: "valid multiple providers",
			cfg: `{
				"type": "ai_proxy",
				"providers": [
					{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4a"},
					{"name": "anthropic", "type": "anthropic", "api_key": "tK7mR9pL2xQ4b"}
				],
				"default_model": "gpt-4",
				"timeout": "60s"
			}`,
			wantErr: false,
		},
		{
			name:    "no providers",
			cfg:     `{"type": "ai_proxy", "providers": []}`,
			wantErr: true,
		},
		{
			name:    "missing providers",
			cfg:     `{"type": "ai_proxy"}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			cfg:     `not json`,
			wantErr: true,
		},
		{
			name: "with gateway and model registry",
			cfg: `{
				"type": "ai_proxy",
				"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}],
				"gateway": true,
				"model_registry": [{"model_pattern": "gpt-*", "provider": "openai"}]
			}`,
			wantErr: false,
		},
		{
			name: "with guardrails config",
			cfg: `{
				"type": "ai_proxy",
				"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}],
				"guardrails": {"rules": []}
			}`,
			wantErr: false,
		},
		{
			name: "with failure mode overrides",
			cfg: `{
				"type": "ai_proxy",
				"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}],
				"failure_mode": "closed",
				"failure_overrides": {"budget": "open"}
			}`,
			wantErr: false,
		},
	}

	factory, ok := plugin.GetAction("ai_proxy")
	if !ok {
		t.Fatal("ai_proxy action not registered")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := factory(json.RawMessage(tt.cfg))
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAIProxy_VirtualKeyStoreNilByDefault(t *testing.T) {
	cfg := `{
		"type": "ai_proxy",
		"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}]
	}`
	factory, ok := plugin.GetAction("ai_proxy")
	if !ok {
		t.Fatal("ai_proxy action not registered")
	}
	handler, err := factory(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h, ok := handler.(*Handler)
	if !ok {
		t.Fatal("handler is not *Handler")
	}
	if h.GetVirtualKeyStore() != nil {
		t.Error("expected nil virtual key store before provision")
	}
}

func TestAIProxy_ImplementsProvisioner(t *testing.T) {
	cfg := `{
		"type": "ai_proxy",
		"providers": [{"name": "openai", "type": "openai", "api_key": "tK7mR9pL2xQ4"}]
	}`
	factory, ok := plugin.GetAction("ai_proxy")
	if !ok {
		t.Fatal("ai_proxy action not registered")
	}
	handler, err := factory(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := handler.(plugin.Provisioner); !ok {
		t.Error("handler does not implement plugin.Provisioner")
	}
	if _, ok := handler.(plugin.Validator); !ok {
		t.Error("handler does not implement plugin.Validator")
	}
	if _, ok := handler.(plugin.Cleanup); !ok {
		t.Error("handler does not implement plugin.Cleanup")
	}
}
