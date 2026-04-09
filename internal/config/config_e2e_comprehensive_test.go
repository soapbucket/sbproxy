package config

import (
	"encoding/json"
	"testing"
)

// TestConfigUnmarshalE2E tests comprehensive config unmarshalling scenarios
func TestConfigUnmarshalE2E(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		validate   func(*testing.T, *Config)
		wantErr    bool
	}{
		{
			name: "minimal valid config",
			configJSON: `{
				"id": "minimal-config",
				"hostname": "example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ID != "minimal-config" {
					t.Errorf("ID = %s, want minimal-config", cfg.ID)
				}
				if cfg.Hostname != "example.com" {
					t.Errorf("Hostname = %s, want example.com", cfg.Hostname)
				}
				if cfg.Disabled {
					t.Error("expected config to not be disabled")
				}
			},
			wantErr: false,
		},
		{
			name: "config with all basic fields",
			configJSON: `{
				"id": "full-config",
				"hostname": "full.example.com",
				"workspace_id": "tenant-123",
				"debug": true,
				"version": "1.0.0",
				"environment": "production",
				"disabled": false,
				"force_ssl": true,
				"allowed_methods": ["GET", "POST", "PUT"],
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.WorkspaceID != "tenant-123" {
					t.Errorf("WorkspaceID = %s, want tenant-123", cfg.WorkspaceID)
				}
				if !cfg.Debug {
					t.Error("expected debug to be true")
				}
				if cfg.Version != "1.0.0" {
					t.Errorf("Version = %s, want 1.0.0", cfg.Version)
				}
				if cfg.Environment != "production" {
					t.Errorf("Environment = %s, want production", cfg.Environment)
				}
				if !cfg.ForceSSL {
					t.Error("expected ForceSSL to be true")
				}
				if len(cfg.AllowedMethods) != 3 {
					t.Errorf("AllowedMethods length = %d, want 3", len(cfg.AllowedMethods))
				}
			},
			wantErr: false,
		},
		{
			name: "config with proxy action",
			configJSON: `{
				"id": "proxy-config",
				"hostname": "proxy.example.com",
				"action": {
					"type": "proxy",
					"url": "https://api.backend.com",
					"timeout": "30s",
					"retry_count": 3
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Action == nil {
					t.Fatal("expected action to be set")
				}
				if !cfg.IsProxy() {
					t.Error("expected config to be a proxy")
				}
			},
			wantErr: false,
		},
		{
			name: "config with static action",
			configJSON: `{
				"id": "static-config",
				"hostname": "static.example.com",
				"action": {
					"type": "static",
					"status_code": 200,
					"body": "Hello, World!",
					"content_type": "text/plain"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Action == nil {
					t.Fatal("expected action to be set")
				}
			},
			wantErr: false,
		},
		{
			name: "config with redirect action",
			configJSON: `{
				"id": "redirect-config",
				"hostname": "redirect.example.com",
				"action": {
					"type": "redirect",
					"url": "https://new-location.example.com",
					"status_code": 301
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Action == nil {
					t.Fatal("expected action to be set")
				}
			},
			wantErr: false,
		},
		{
			name: "config with transforms",
			configJSON: `{
				"id": "transform-config",
				"hostname": "transform.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"transforms": [
					{
						"type": "replace_strings",
						"content_types": ["text/html"],
						"replace_strings": {
							"replacements": [
								{
									"find": "old-text",
									"replace": "new-text"
								}
							]
						}
					}
				]
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Transforms) < 1 {
					t.Error("expected at least one transform in raw JSON")
				}
			},
			wantErr: false,
		},
		{
			name: "config with request modifiers",
			configJSON: `{
				"id": "modifier-config",
				"hostname": "modifier.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"request_modifiers": [
					{
						"type": "set_header",
						"header": "X-Custom-Header",
						"value": "custom-value"
					}
				]
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.RequestModifiers) != 1 {
					t.Errorf("RequestModifiers length = %d, want 1", len(cfg.RequestModifiers))
				}
			},
			wantErr: false,
		},
		{
			name: "config with response modifiers",
			configJSON: `{
				"id": "response-modifier-config",
				"hostname": "response.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"response_modifiers": [
					{
						"type": "set_header",
						"header": "X-Response-Header",
						"value": "response-value"
					}
				]
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.ResponseModifiers) != 1 {
					t.Errorf("ResponseModifiers length = %d, want 1", len(cfg.ResponseModifiers))
				}
			},
			wantErr: false,
		},
		{
			name: "config with session config",
			configJSON: `{
				"id": "session-config",
				"hostname": "session.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"session_config": {
					"cookie_name": "my_session",
					"cookie_max_age": 3600
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.SessionConfig.CookieName != "my_session" {
					t.Errorf("CookieName = %s, want my_session", cfg.SessionConfig.CookieName)
				}
				if cfg.SessionConfig.CookieMaxAge != 3600 {
					t.Errorf("CookieMaxAge = %d, want 3600", cfg.SessionConfig.CookieMaxAge)
				}
			},
			wantErr: false,
		},
		{
			name: "config with forward rules",
			configJSON: `{
				"id": "forward-config",
				"hostname": "forward.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"forward_rules": [
					{
						"hostname": "other.example.com"
					}
				]
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.ForwardRules) != 1 {
					t.Errorf("ForwardRules length = %d, want 1", len(cfg.ForwardRules))
				}
			},
			wantErr: false,
		},
		{
			name: "config with streaming proxy config",
			configJSON: `{
				"id": "streaming-config",
				"hostname": "streaming.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"streaming_proxy_config": {
					"chunk_threshold": "8KB",
					"enable_trailers": true
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.StreamingProxyConfig == nil {
					t.Fatal("expected StreamingProxyConfig to be set")
				}
			},
			wantErr: false,
		},
		{
			name: "config with proxy headers",
			configJSON: `{
				"id": "proxy-headers-config",
				"hostname": "headers.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"proxy_headers": {
					"set_x_forwarded_for": true,
					"set_x_forwarded_proto": true,
					"set_x_forwarded_host": true
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ProxyHeaders == nil {
					t.Fatal("expected ProxyHeaders to be set")
				}
			},
			wantErr: false,
		},
		{
			name: "config with max connections",
			configJSON: `{
				"id": "connections-config",
				"hostname": "connections.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"max_connections": 100
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.MaxConnections != 100 {
					t.Errorf("MaxConnections = %d, want 100", cfg.MaxConnections)
				}
			},
			wantErr: false,
		},
		{
			name: "disabled config",
			configJSON: `{
				"id": "disabled-config",
				"hostname": "disabled.example.com",
				"disabled": true,
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.Disabled {
					t.Error("expected config to be disabled")
				}
			},
			wantErr: false,
		},
		{
			name: "config with disable compression",
			configJSON: `{
				"id": "no-compression-config",
				"hostname": "nocomp.example.com",
				"disableCompression": true,
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.DisableCompression {
					t.Error("expected compression to be disabled")
				}
			},
			wantErr: false,
		},
		{
			name: "config with disable HTTP3",
			configJSON: `{
				"id": "no-http3-config",
				"hostname": "nohttp3.example.com",
				"disableHTTP3": true,
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if !cfg.DisableHTTP3 {
					t.Error("expected HTTP3 to be disabled")
				}
			},
			wantErr: false,
		},
		{
			name: "config with flush interval",
			configJSON: `{
				"id": "flush-config",
				"hostname": "flush.example.com",
				"flush_interval": "100ms",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.FlushInterval.Duration == 0 {
					t.Error("expected FlushInterval to be set")
				}
			},
			wantErr: false,
		},
		{
			name: "config with on_request callbacks",
			configJSON: `{
				"id": "callback-config",
				"hostname": "callback.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"on_request": [
					{
						"type": "http",
						"url": "https://webhook.example.com/notify"
					}
				]
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.OnRequest) != 1 {
					t.Errorf("OnRequest length = %d, want 1", len(cfg.OnRequest))
				}
			},
			wantErr: false,
		},
		{
			name: "config with chunk cache",
			configJSON: `{
				"id": "chunk-cache-config",
				"hostname": "chunk.example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"chunk_cache": {
					"enabled": true,
					"ttl": "1h"
				}
			}`,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.ChunkCache == nil {
					t.Fatal("expected ChunkCache to be set")
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			err := cfg.UnmarshalJSON([]byte(tt.configJSON))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			tt.validate(t, cfg)
		})
	}
}

// TestConfigStringE2E tests the Config.String() method
func TestConfigStringE2E(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{
			name: "single config",
			config: &Config{
				ID: "config-1",
			},
			want: "config-1",
		},
		{
			name: "config with parent",
			config: &Config{
				ID: "child-config",
				Parent: &Config{
					ID: "parent-config",
				},
			},
			want: "parent-config→child-config",
		},
		{
			name: "config with grandparent",
			config: &Config{
				ID: "grandchild",
				Parent: &Config{
					ID: "child",
					Parent: &Config{
						ID: "grandparent",
					},
				},
			},
			want: "grandparent→child→grandchild",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.String()
			if got != tt.want {
				t.Errorf("String() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestConfigValidationE2E tests config validation
func TestConfigValidationE2E(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantErr    bool
	}{
		{
			name: "valid config passes validation",
			configJSON: `{
				"id": "valid-config",
				"hostname": "example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			wantErr: false,
		},
		{
			name: "invalid JSON fails",
			configJSON: `{
				"id": "invalid-json",
				invalid json here
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			err := cfg.UnmarshalJSON([]byte(tt.configJSON))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestConfigMarshalJSONE2E tests config serialization
func TestConfigMarshalJSONE2E(t *testing.T) {
	cfg := &Config{
		ID:          "test-config",
		Hostname:    "example.com",
		WorkspaceID:    "tenant-123",
		Debug:       true,
		Version:     "1.0.0",
		Environment: "production",
		ForceSSL:    true,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Verify it can be unmarshalled back
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if result["id"] != "test-config" {
		t.Errorf("id = %v, want test-config", result["id"])
	}

	if result["hostname"] != "example.com" {
		t.Errorf("hostname = %v, want example.com", result["hostname"])
	}
}

// TestConfigIsProxyE2E tests the IsProxy method
func TestConfigIsProxyE2E(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantProxy  bool
	}{
		{
			name: "proxy action",
			configJSON: `{
				"id": "proxy-config",
				"hostname": "example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			wantProxy: true,
		},
		{
			name: "redirect action is also proxy",
			configJSON: `{
				"id": "redirect-config",
				"hostname": "example.com",
				"action": {
					"type": "redirect",
					"url": "https://other.example.com",
					"status_code": 301
				}
			}`,
			wantProxy: true, // redirect is also considered a proxy action in this implementation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			err := cfg.UnmarshalJSON([]byte(tt.configJSON))
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			got := cfg.IsProxy()
			if got != tt.wantProxy {
				t.Errorf("IsProxy() = %v, want %v", got, tt.wantProxy)
			}
		})
	}
}

// TestConfigHasSessionConfigE2E tests session config detection
func TestConfigHasSessionConfigE2E(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantHas    bool
	}{
		{
			name: "with session config",
			configJSON: `{
				"id": "session-config",
				"hostname": "example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"session_config": {
					"cookie_name": "session"
				}
			}`,
			wantHas: true,
		},
		{
			name: "without session config",
			configJSON: `{
				"id": "no-session-config",
				"hostname": "example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				}
			}`,
			wantHas: false,
		},
		{
			name: "with disabled session config",
			configJSON: `{
				"id": "disabled-session-config",
				"hostname": "example.com",
				"action": {
					"type": "proxy",
					"url": "https://backend.example.com"
				},
				"session_config": {
					"disabled": true
				}
			}`,
			wantHas: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			err := cfg.UnmarshalJSON([]byte(tt.configJSON))
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			got := cfg.HasSessionConfig()
			if got != tt.wantHas {
				t.Errorf("HasSessionConfig() = %v, want %v", got, tt.wantHas)
			}
		})
	}
}

// BenchmarkConfigUnmarshalE2E benchmarks config unmarshalling
func BenchmarkConfigUnmarshalE2E(b *testing.B) {
	b.ReportAllocs()
	configJSON := []byte(`{
		"id": "benchmark-config",
		"hostname": "benchmark.example.com",
		"workspace_id": "tenant-123",
		"debug": true,
		"version": "1.0.0",
		"environment": "production",
		"force_ssl": true,
		"allowed_methods": ["GET", "POST", "PUT", "DELETE"],
		"action": {
			"type": "proxy",
			"url": "https://backend.example.com",
			"timeout": "30s"
		},
		"transforms": [
			{
				"type": "replace_strings",
				"content_types": ["text/html"],
				"replace_strings": {
					"replacements": [
						{
							"find": "old",
							"replace": "new"
						}
					]
				}
			}
		],
		"request_modifiers": [
			{
				"type": "set_header",
				"header": "X-Custom",
				"value": "value"
			}
		]
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := &Config{}
		_ = cfg.UnmarshalJSON(configJSON)
	}
}
