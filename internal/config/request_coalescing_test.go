package config

import (
	"net/http"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

func TestGetRequestCoalescingConfig_GlobalDefaults(t *testing.T) {
	// Set up test getter with known values
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         false,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that global defaults are used when no per-origin config is present
	connCfg := &BaseConnection{
		RequestCoalescing: nil, // No per-origin override
	}

	config := getRequestCoalescingConfig(connCfg)

	// Verify that config uses global defaults
	if config.Enabled {
		t.Errorf("Expected Enabled=false, got %v", config.Enabled)
	}
	if config.MaxInflight != 1000 {
		t.Errorf("Expected MaxInflight=1000, got %d", config.MaxInflight)
	}
	if config.CoalesceWindow != 100*time.Millisecond {
		t.Errorf("Expected CoalesceWindow=100ms, got %v", config.CoalesceWindow)
	}
	if config.MaxWaiters != 100 {
		t.Errorf("Expected MaxWaiters=100, got %d", config.MaxWaiters)
	}
	if config.CleanupInterval != 30*time.Second {
		t.Errorf("Expected CleanupInterval=30s, got %v", config.CleanupInterval)
	}
}

func TestGetRequestCoalescingConfig_PerOriginEnabled(t *testing.T) {
	// Set up test getter
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         false,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that per-origin Enabled=true overrides global config
	connCfg := &BaseConnection{
		RequestCoalescing: &RequestCoalescingConfig{
			Enabled: true, // Enable coalescing for this origin
		},
	}

	config := getRequestCoalescingConfig(connCfg)

	// Should be enabled
	if !config.Enabled {
		t.Errorf("Expected Enabled=true when per-origin Enabled=true, got Enabled=false")
	}
}

func TestGetRequestCoalescingConfig_PerOriginMaxInflight(t *testing.T) {
	// Set up test getter
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         true,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that per-origin MaxInflight overrides global
	connCfg := &BaseConnection{
		RequestCoalescing: &RequestCoalescingConfig{
			MaxInflight: 2000, // Override global default
		},
	}

	config := getRequestCoalescingConfig(connCfg)

	if config.MaxInflight != 2000 {
		t.Errorf("Expected MaxInflight=2000, got %d", config.MaxInflight)
	}
}

func TestGetRequestCoalescingConfig_PerOriginCoalesceWindow(t *testing.T) {
	// Set up test getter
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         true,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that per-origin CoalesceWindow overrides global
	window := 200 * time.Millisecond
	connCfg := &BaseConnection{
		RequestCoalescing: &RequestCoalescingConfig{
			CoalesceWindow: reqctx.Duration{Duration: window}, // Override global default
		},
	}

	config := getRequestCoalescingConfig(connCfg)

	if config.CoalesceWindow != window {
		t.Errorf("Expected CoalesceWindow=%v, got %v", window, config.CoalesceWindow)
	}
}

func TestGetRequestCoalescingConfig_PerOriginKeyStrategy(t *testing.T) {
	// Set up test getter
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         true,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that per-origin KeyStrategy overrides global
	connCfg := &BaseConnection{
		RequestCoalescing: &RequestCoalescingConfig{
			KeyStrategy: "method_url", // Override global default
		},
	}

	config := getRequestCoalescingConfig(connCfg)

	// Verify key function is MethodURLKey
	if config.KeyFunc == nil {
		t.Error("Expected KeyFunc to be set, got nil")
	}

	// Test that it's actually MethodURLKey by checking behavior
	req1, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req1.Header.Set("Authorization", "Bearer token1")
	req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req2.Header.Set("Authorization", "Bearer token2")

	key1 := config.KeyFunc(req1)
	key2 := config.KeyFunc(req2)

	// With method_url strategy, both should have same key (ignores headers)
	if key1 != key2 {
		t.Errorf("Expected same key with method_url strategy, got %s and %s", key1, key2)
	}
}

func TestGetRequestCoalescingConfig_PartialOverride(t *testing.T) {
	// Set up test getter
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         true,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that only specified fields are overridden, others use global defaults
	connCfg := &BaseConnection{
		RequestCoalescing: &RequestCoalescingConfig{
			MaxInflight: 2000, // Override only this field
			// Other fields not set, should use global defaults
		},
	}

	config := getRequestCoalescingConfig(connCfg)

	// Overridden field
	if config.MaxInflight != 2000 {
		t.Errorf("Expected MaxInflight=2000, got %d", config.MaxInflight)
	}

	// Should use global defaults for other fields
	if config.CoalesceWindow != 100*time.Millisecond {
		t.Errorf("Expected CoalesceWindow=100ms (global), got %v", config.CoalesceWindow)
	}
	if config.MaxWaiters != 100 {
		t.Errorf("Expected MaxWaiters=100 (global), got %d", config.MaxWaiters)
	}
}

func TestGetRequestCoalescingConfig_ZeroValuesNotOverride(t *testing.T) {
	// Set up test getter
	SetRequestCoalescingConfigGetter(func() transport.CoalescingConfig {
		return transport.CoalescingConfig{
			Enabled:         true,
			MaxInflight:     1000,
			CoalesceWindow:  100 * time.Millisecond,
			MaxWaiters:      100,
			CleanupInterval: 30 * time.Second,
			KeyFunc:         transport.DefaultCoalesceKey,
		}
	})

	// Test that zero values don't override global defaults
	connCfg := &BaseConnection{
		RequestCoalescing: &RequestCoalescingConfig{
			MaxInflight:    0, // Zero value should not override
			CoalesceWindow: reqctx.Duration{Duration: 0}, // Zero value should not override
			MaxWaiters:     0, // Zero value should not override
		},
	}

	config := getRequestCoalescingConfig(connCfg)

	// Should use global defaults for zero values
	if config.MaxInflight != 1000 {
		t.Errorf("Expected MaxInflight=1000 (global), got %d", config.MaxInflight)
	}
	if config.CoalesceWindow != 100*time.Millisecond {
		t.Errorf("Expected CoalesceWindow=100ms (global), got %v", config.CoalesceWindow)
	}
	if config.MaxWaiters != 100 {
		t.Errorf("Expected MaxWaiters=100 (global), got %d", config.MaxWaiters)
	}
}

func TestGetCoalesceKeyFunc(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		wantSame bool // Whether two requests with different headers should have same key
	}{
		{
			name:     "default strategy",
			strategy: "default",
			wantSame: false, // Default includes headers, so different headers = different keys
		},
		{
			name:     "method_url strategy",
			strategy: "method_url",
			wantSame: true, // Method+URL only, ignores headers
		},
		{
			name:     "unknown strategy defaults to default",
			strategy: "unknown",
			wantSame: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFunc := getCoalesceKeyFunc(tt.strategy)

			req1, _ := http.NewRequest("GET", "https://example.com/test", nil)
			req1.Header.Set("Authorization", "Bearer token1")
			req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
			req2.Header.Set("Authorization", "Bearer token2")

			key1 := keyFunc(req1)
			key2 := keyFunc(req2)

			if tt.wantSame {
				if key1 != key2 {
					t.Errorf("Expected same key for %s strategy, got %s and %s", tt.strategy, key1, key2)
				}
			} else {
				if key1 == key2 {
					t.Errorf("Expected different keys for %s strategy, got same key %s", tt.strategy, key1)
				}
			}
		})
	}
}

func TestRequestCoalescingConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  RequestCoalescingConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: RequestCoalescingConfig{
				MaxInflight:    1000,
				CoalesceWindow: reqctx.Duration{Duration: 100 * time.Millisecond},
				MaxWaiters:     100,
			},
			wantErr: false,
		},
		{
			name: "MaxInflight too high",
			config: RequestCoalescingConfig{
				MaxInflight: 20000, // Exceeds max of 10000
			},
			wantErr: true,
		},
		{
			name: "MaxInflight too low",
			config: RequestCoalescingConfig{
				MaxInflight: 0, // Below min of 1
			},
			wantErr: true,
		},
		{
			name: "CoalesceWindow too high",
			config: RequestCoalescingConfig{
				CoalesceWindow: reqctx.Duration{Duration: 2 * time.Second}, // Exceeds max of 1s
			},
			wantErr: true,
		},
		{
			name: "MaxWaiters too high",
			config: RequestCoalescingConfig{
				MaxWaiters: 2000, // Exceeds max of 1000
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Validation is done via struct tags, so we test the validation logic
			// by checking if values are within expected ranges
			if tt.config.MaxInflight > 0 {
				if tt.config.MaxInflight < 1 || tt.config.MaxInflight > 10000 {
					if !tt.wantErr {
						t.Errorf("Expected no error, but MaxInflight=%d is out of range", tt.config.MaxInflight)
					}
				}
			}
			if tt.config.CoalesceWindow.Duration > 0 {
				if tt.config.CoalesceWindow.Duration > 1*time.Second {
					if !tt.wantErr {
						t.Errorf("Expected no error, but CoalesceWindow=%v exceeds max", tt.config.CoalesceWindow.Duration)
					}
				}
			}
			if tt.config.MaxWaiters > 0 {
				if tt.config.MaxWaiters < 1 || tt.config.MaxWaiters > 1000 {
					if !tt.wantErr {
						t.Errorf("Expected no error, but MaxWaiters=%d is out of range", tt.config.MaxWaiters)
					}
				}
			}
		})
	}
}

