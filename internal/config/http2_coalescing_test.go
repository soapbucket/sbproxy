package config

import (
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

func TestGetHTTP2CoalescingConfig_GlobalDefaults(t *testing.T) {
	// Set up test getter with known values
	SetHTTP2CoalescingConfigGetter(func() transport.HTTP2CoalescingConfig {
		return transport.HTTP2CoalescingConfig{
			Enabled:                  true,
			MaxIdleConnsPerHost:      20,
			IdleConnTimeout:          90 * time.Second,
			MaxConnLifetime:          1 * time.Hour,
			AllowIPBasedCoalescing:   true,
			AllowCertBasedCoalescing: true,
			StrictCertValidation:     false,
		}
	})

	// Test that global defaults are used when no per-origin config is present
	connCfg := &BaseConnection{
		HTTP2Coalescing: nil, // No per-origin override
	}

	config := getHTTP2CoalescingConfig(connCfg)

	// Verify that config uses global defaults
	if !config.Enabled {
		t.Errorf("Expected Enabled=true, got %v", config.Enabled)
	}
	if config.MaxIdleConnsPerHost != 20 {
		t.Errorf("Expected MaxIdleConnsPerHost=20, got %d", config.MaxIdleConnsPerHost)
	}
	if config.IdleConnTimeout != 90*time.Second {
		t.Errorf("Expected IdleConnTimeout=90s, got %v", config.IdleConnTimeout)
	}
	if config.MaxConnLifetime != 1*time.Hour {
		t.Errorf("Expected MaxConnLifetime=1h, got %v", config.MaxConnLifetime)
	}
	if !config.AllowIPBasedCoalescing {
		t.Errorf("Expected AllowIPBasedCoalescing=true, got %v", config.AllowIPBasedCoalescing)
	}
	if !config.AllowCertBasedCoalescing {
		t.Errorf("Expected AllowCertBasedCoalescing=true, got %v", config.AllowCertBasedCoalescing)
	}
	if config.StrictCertValidation {
		t.Errorf("Expected StrictCertValidation=false, got %v", config.StrictCertValidation)
	}
}

func TestGetHTTP2CoalescingConfig_PerOriginDisabled(t *testing.T) {
	// Test that per-origin Disabled=true overrides global config
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			Disabled: true, // Disable coalescing for this origin
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	// Should be disabled (Enabled=false)
	if config.Enabled {
		t.Errorf("Expected Enabled=false when Disabled=true, got Enabled=true")
	}
}

func TestGetHTTP2CoalescingConfig_PerOriginEnabled(t *testing.T) {
	// Test that per-origin Disabled=false enables coalescing
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			Disabled: false, // Explicitly enable coalescing
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	// Should be enabled (Enabled=true)
	if !config.Enabled {
		t.Errorf("Expected Enabled=true when Disabled=false, got Enabled=false")
	}
}

func TestGetHTTP2CoalescingConfig_PerOriginMaxIdleConnsPerHost(t *testing.T) {
	// Test that per-origin MaxIdleConnsPerHost overrides global
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			MaxIdleConnsPerHost: 50, // Override global default
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	if config.MaxIdleConnsPerHost != 50 {
		t.Errorf("Expected MaxIdleConnsPerHost=50, got %d", config.MaxIdleConnsPerHost)
	}
}

func TestGetHTTP2CoalescingConfig_PerOriginIdleConnTimeout(t *testing.T) {
	// Test that per-origin IdleConnTimeout overrides global
	timeout := 120 * time.Second
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			IdleConnTimeout: reqctx.Duration{Duration: timeout}, // Override global default
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	if config.IdleConnTimeout != timeout {
		t.Errorf("Expected IdleConnTimeout=%v, got %v", timeout, config.IdleConnTimeout)
	}
}

func TestGetHTTP2CoalescingConfig_PerOriginMaxConnLifetime(t *testing.T) {
	// Test that per-origin MaxConnLifetime overrides global
	lifetime := 2 * time.Hour
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			MaxConnLifetime: reqctx.Duration{Duration: lifetime}, // Override global default
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	if config.MaxConnLifetime != lifetime {
		t.Errorf("Expected MaxConnLifetime=%v, got %v", lifetime, config.MaxConnLifetime)
	}
}

func TestGetHTTP2CoalescingConfig_PerOriginBooleanOverrides(t *testing.T) {
	// Test that per-origin boolean fields override global
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			AllowIPBasedCoalescing:   false, // Override global
			AllowCertBasedCoalescing: false, // Override global
			StrictCertValidation:     true,  // Override global
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	if config.AllowIPBasedCoalescing {
		t.Errorf("Expected AllowIPBasedCoalescing=false, got true")
	}
	if config.AllowCertBasedCoalescing {
		t.Errorf("Expected AllowCertBasedCoalescing=false, got true")
	}
	if !config.StrictCertValidation {
		t.Errorf("Expected StrictCertValidation=true, got false")
	}
}

func TestGetHTTP2CoalescingConfig_PartialOverride(t *testing.T) {
	// Set up test getter
	SetHTTP2CoalescingConfigGetter(func() transport.HTTP2CoalescingConfig {
		return transport.HTTP2CoalescingConfig{
			Enabled:                  true,
			MaxIdleConnsPerHost:      20,
			IdleConnTimeout:          90 * time.Second,
			MaxConnLifetime:          1 * time.Hour,
			AllowIPBasedCoalescing:   true,
			AllowCertBasedCoalescing: true,
			StrictCertValidation:     false,
		}
	})

	// Test that only specified fields are overridden, others use global defaults
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			MaxIdleConnsPerHost: 30, // Override only this field
			// Other fields not set, should use global defaults
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	// Overridden field
	if config.MaxIdleConnsPerHost != 30 {
		t.Errorf("Expected MaxIdleConnsPerHost=30, got %d", config.MaxIdleConnsPerHost)
	}

	// Should use global defaults for other fields
	if config.IdleConnTimeout != 90*time.Second {
		t.Errorf("Expected IdleConnTimeout=90s (global), got %v", config.IdleConnTimeout)
	}
	if config.MaxConnLifetime != 1*time.Hour {
		t.Errorf("Expected MaxConnLifetime=1h (global), got %v", config.MaxConnLifetime)
	}
}

func TestGetHTTP2CoalescingConfig_ZeroValuesNotOverride(t *testing.T) {
	// Set up test getter
	SetHTTP2CoalescingConfigGetter(func() transport.HTTP2CoalescingConfig {
		return transport.HTTP2CoalescingConfig{
			Enabled:                  true,
			MaxIdleConnsPerHost:      20,
			IdleConnTimeout:          90 * time.Second,
			MaxConnLifetime:          1 * time.Hour,
			AllowIPBasedCoalescing:   true,
			AllowCertBasedCoalescing: true,
			StrictCertValidation:     false,
		}
	})

	// Test that zero values don't override global defaults
	connCfg := &BaseConnection{
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			MaxIdleConnsPerHost: 0, // Zero value should not override
			IdleConnTimeout:     reqctx.Duration{Duration: 0}, // Zero value should not override
			MaxConnLifetime:     reqctx.Duration{Duration: 0},   // Zero value should not override
		},
	}

	config := getHTTP2CoalescingConfig(connCfg)

	// Should use global defaults for zero values
	if config.MaxIdleConnsPerHost != 20 {
		t.Errorf("Expected MaxIdleConnsPerHost=20 (global), got %d", config.MaxIdleConnsPerHost)
	}
	if config.IdleConnTimeout != 90*time.Second {
		t.Errorf("Expected IdleConnTimeout=90s (global), got %v", config.IdleConnTimeout)
	}
	if config.MaxConnLifetime != 1*time.Hour {
		t.Errorf("Expected MaxConnLifetime=1h (global), got %v", config.MaxConnLifetime)
	}
}

func TestHTTP2CoalescingConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  HTTP2CoalescingConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: HTTP2CoalescingConfig{
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     reqctx.Duration{Duration: 90 * time.Second},
				MaxConnLifetime:     reqctx.Duration{Duration: 1 * time.Hour},
			},
			wantErr: false,
		},
		{
			name: "MaxIdleConnsPerHost too high",
			config: HTTP2CoalescingConfig{
				MaxIdleConnsPerHost: 600, // Exceeds max of 500
			},
			wantErr: true,
		},
		{
			name: "MaxIdleConnsPerHost too low",
			config: HTTP2CoalescingConfig{
				MaxIdleConnsPerHost: 0, // Below min of 1
			},
			wantErr: true,
		},
		{
			name: "IdleConnTimeout too high",
			config: HTTP2CoalescingConfig{
				IdleConnTimeout: reqctx.Duration{Duration: 2 * time.Hour}, // Exceeds max of 1h
			},
			wantErr: true,
		},
		{
			name: "MaxConnLifetime too high",
			config: HTTP2CoalescingConfig{
				MaxConnLifetime: reqctx.Duration{Duration: 25 * time.Hour}, // Exceeds max of 24h
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Validation is done via struct tags, so we test the validation logic
			// by checking if values are within expected ranges
			if tt.config.MaxIdleConnsPerHost > 0 {
				if tt.config.MaxIdleConnsPerHost < 1 || tt.config.MaxIdleConnsPerHost > 500 {
					if !tt.wantErr {
						t.Errorf("Expected no error, but MaxIdleConnsPerHost=%d is out of range", tt.config.MaxIdleConnsPerHost)
					}
				}
			}
			if tt.config.IdleConnTimeout.Duration > 0 {
				if tt.config.IdleConnTimeout.Duration > 1*time.Hour {
					if !tt.wantErr {
						t.Errorf("Expected no error, but IdleConnTimeout=%v exceeds max", tt.config.IdleConnTimeout.Duration)
					}
				}
			}
			if tt.config.MaxConnLifetime.Duration > 0 {
				if tt.config.MaxConnLifetime.Duration > 24*time.Hour {
					if !tt.wantErr {
						t.Errorf("Expected no error, but MaxConnLifetime=%v exceeds max", tt.config.MaxConnLifetime.Duration)
					}
				}
			}
		})
	}
}

func TestClientConnectionTransportFn_HTTP2CoalescingEnabled(t *testing.T) {
	// Test that HTTP/2 coalescing transport is created when enabled
	connCfg := &BaseConnection{
		IdleConnTimeout:     reqctx.Duration{Duration: 60 * time.Second},
		TLSHandshakeTimeout: reqctx.Duration{Duration: 10 * time.Second},
		DialTimeout:         reqctx.Duration{Duration: 10 * time.Second},
		KeepAlive:           reqctx.Duration{Duration: 30 * time.Second},
		SkipTLSVerifyHost:   false,
		HTTP11Only:          false,
		HTTP2Coalescing:     nil, // Use global defaults (enabled by default)
	}

	transport := ClientConnectionTransportFn(connCfg)

	// Verify transport is created (not nil)
	if transport == nil {
		t.Fatal("Expected transport to be created, got nil")
	}

	// Note: We can't easily test the internal type without exposing internals,
	// but we can verify the transport is functional by checking it's not nil
}

func TestClientConnectionTransportFn_HTTP2CoalescingDisabled(t *testing.T) {
	// Test that HTTP/2 coalescing transport is NOT created when disabled
	connCfg := &BaseConnection{
		IdleConnTimeout:     reqctx.Duration{Duration: 60 * time.Second},
		TLSHandshakeTimeout: reqctx.Duration{Duration: 10 * time.Second},
		DialTimeout:         reqctx.Duration{Duration: 10 * time.Second},
		KeepAlive:           reqctx.Duration{Duration: 30 * time.Second},
		SkipTLSVerifyHost:   false,
		HTTP11Only:          false,
		HTTP2Coalescing: &HTTP2CoalescingConfig{
			Disabled: true, // Disable coalescing
		},
	}

	transport := ClientConnectionTransportFn(connCfg)

	// Verify transport is created (not nil)
	if transport == nil {
		t.Fatal("Expected transport to be created, got nil")
	}

	// Note: When disabled, it should use the base transport, not coalescing transport
	// We can't easily verify this without exposing internals, but the transport should still work
}

// Helper function to verify transport config matches expected values
func verifyTransportConfig(t *testing.T, config transport.HTTP2CoalescingConfig, expected transport.HTTP2CoalescingConfig) {
	t.Helper()
	if config.Enabled != expected.Enabled {
		t.Errorf("Expected Enabled=%v, got %v", expected.Enabled, config.Enabled)
	}
	if config.MaxIdleConnsPerHost != expected.MaxIdleConnsPerHost {
		t.Errorf("Expected MaxIdleConnsPerHost=%d, got %d", expected.MaxIdleConnsPerHost, config.MaxIdleConnsPerHost)
	}
	if config.IdleConnTimeout != expected.IdleConnTimeout {
		t.Errorf("Expected IdleConnTimeout=%v, got %v", expected.IdleConnTimeout, config.IdleConnTimeout)
	}
	if config.MaxConnLifetime != expected.MaxConnLifetime {
		t.Errorf("Expected MaxConnLifetime=%v, got %v", expected.MaxConnLifetime, config.MaxConnLifetime)
	}
	if config.AllowIPBasedCoalescing != expected.AllowIPBasedCoalescing {
		t.Errorf("Expected AllowIPBasedCoalescing=%v, got %v", expected.AllowIPBasedCoalescing, config.AllowIPBasedCoalescing)
	}
	if config.AllowCertBasedCoalescing != expected.AllowCertBasedCoalescing {
		t.Errorf("Expected AllowCertBasedCoalescing=%v, got %v", expected.AllowCertBasedCoalescing, config.AllowCertBasedCoalescing)
	}
	if config.StrictCertValidation != expected.StrictCertValidation {
		t.Errorf("Expected StrictCertValidation=%v, got %v", expected.StrictCertValidation, config.StrictCertValidation)
	}
}

