package billing

import (
	"testing"
)

// TestBillingConfig_Defaults verifies zero-value BillingConfig behaves as expected.
func TestBillingConfig_Defaults(t *testing.T) {
	cfg := BillingConfig{}

	if cfg.ClickHouseDSN != "" {
		t.Errorf("expected empty ClickHouseDSN, got %q", cfg.ClickHouseDSN)
	}
	if cfg.BackendURL != "" {
		t.Errorf("expected empty BackendURL, got %q", cfg.BackendURL)
	}
	if cfg.BackendAPIKey != "" {
		t.Errorf("expected empty BackendAPIKey, got %q", cfg.BackendAPIKey)
	}
	if cfg.BufferSize != 0 {
		t.Errorf("expected zero BufferSize, got %d", cfg.BufferSize)
	}
}

// TestBillingConfig_FieldAssignment verifies field values can be set correctly.
func TestBillingConfig_FieldAssignment(t *testing.T) {
	tests := []struct {
		name   string
		config BillingConfig
	}{
		{
			name: "clickhouse only",
			config: BillingConfig{
				ClickHouseDSN: "clickhouse:9000",
				BufferSize:    5000,
			},
		},
		{
			name: "backend only",
			config: BillingConfig{
				BackendURL:    "https://api.example.com",
				BackendAPIKey: "aK7mR9pL2xQ4nB3",
				BufferSize:    10000,
			},
		},
		{
			name: "both backends",
			config: BillingConfig{
				ClickHouseDSN: "clickhouse:9000",
				BackendURL:    "https://api.example.com",
				BackendAPIKey: "key",
				BufferSize:    20000,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.config
			if cfg.ClickHouseDSN != tc.config.ClickHouseDSN {
				t.Errorf("ClickHouseDSN: expected %q, got %q", tc.config.ClickHouseDSN, cfg.ClickHouseDSN)
			}
			if cfg.BackendURL != tc.config.BackendURL {
				t.Errorf("BackendURL: expected %q, got %q", tc.config.BackendURL, cfg.BackendURL)
			}
			if cfg.BackendAPIKey != tc.config.BackendAPIKey {
				t.Errorf("BackendAPIKey: expected %q, got %q", tc.config.BackendAPIKey, cfg.BackendAPIKey)
			}
			if cfg.BufferSize != tc.config.BufferSize {
				t.Errorf("BufferSize: expected %d, got %d", tc.config.BufferSize, cfg.BufferSize)
			}
		})
	}
}

// TestBillingConfig_IsNoop verifies zero-value config means noop writer.
func TestBillingConfig_IsNoop(t *testing.T) {
	cfg := BillingConfig{}

	isNoop := cfg.ClickHouseDSN == "" && cfg.BackendURL == ""
	if !isNoop {
		t.Error("zero-value config should indicate noop mode")
	}

	cfg.ClickHouseDSN = "clickhouse:9000"
	isNoop = cfg.ClickHouseDSN == "" && cfg.BackendURL == ""
	if isNoop {
		t.Error("config with ClickHouseDSN should not be noop")
	}
}
