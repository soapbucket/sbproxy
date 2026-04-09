package config

import "testing"

func TestLoadHTTPSProxy_DefaultAIProviders(t *testing.T) {
	cfg, err := LoadHTTPSProxy([]byte(`{"type":"https_proxy"}`))
	if err != nil {
		t.Fatalf("LoadHTTPSProxy returned error: %v", err)
	}
	action, ok := cfg.(*HTTPSProxyAction)
	if !ok {
		t.Fatal("expected HTTPSProxyAction")
	}
	if len(action.KnownAIOrigins) == 0 {
		t.Fatal("expected default AI providers to be loaded")
	}
}

