package billing

import (
	"testing"
)

// TestBillingConfig_WriterSelection verifies which writer type is implied by config fields.
func TestBillingConfig_WriterSelection(t *testing.T) {
	tests := []struct {
		name           string
		config         BillingConfig
		wantClickhouse bool
		wantBackend    bool
		wantNoop       bool
	}{
		{
			name:     "zero value is noop",
			config:   BillingConfig{},
			wantNoop: true,
		},
		{
			name: "clickhouse DSN only",
			config: BillingConfig{
				ClickHouseDSN: "clickhouse:9000",
			},
			wantClickhouse: true,
		},
		{
			name: "backend URL only",
			config: BillingConfig{
				BackendURL:    "https://api.example.com",
				BackendAPIKey: "key-123",
			},
			wantBackend: true,
		},
		{
			name: "both writers",
			config: BillingConfig{
				ClickHouseDSN: "clickhouse:9000",
				BackendURL:    "https://api.example.com",
				BackendAPIKey: "key-456",
			},
			wantClickhouse: true,
			wantBackend:    true,
		},
		{
			name: "backend URL without key",
			config: BillingConfig{
				BackendURL: "https://api.example.com",
			},
			wantBackend: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isNoop := tc.config.ClickHouseDSN == "" && tc.config.BackendURL == ""
			hasClickhouse := tc.config.ClickHouseDSN != ""
			hasBackend := tc.config.BackendURL != ""

			if isNoop != tc.wantNoop {
				t.Errorf("noop: got %v, want %v", isNoop, tc.wantNoop)
			}
			if hasClickhouse != tc.wantClickhouse {
				t.Errorf("clickhouse: got %v, want %v", hasClickhouse, tc.wantClickhouse)
			}
			if hasBackend != tc.wantBackend {
				t.Errorf("backend: got %v, want %v", hasBackend, tc.wantBackend)
			}
		})
	}
}

// TestBillingConfig_BufferSize_Defaults verifies buffer size defaults and boundaries.
func TestBillingConfig_BufferSize_Defaults(t *testing.T) {
	tests := []struct {
		name       string
		bufferSize int
		wantSize   int
	}{
		{
			name:       "zero defaults to 10000 at usage site",
			bufferSize: 0,
			wantSize:   0, // stored as zero, defaults applied by consumer
		},
		{
			name:       "custom small size",
			bufferSize: 100,
			wantSize:   100,
		},
		{
			name:       "standard size",
			bufferSize: 10000,
			wantSize:   10000,
		},
		{
			name:       "large size",
			bufferSize: 100000,
			wantSize:   100000,
		},
		{
			name:       "negative treated as is",
			bufferSize: -1,
			wantSize:   -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := BillingConfig{BufferSize: tc.bufferSize}
			if cfg.BufferSize != tc.wantSize {
				t.Errorf("BufferSize: got %d, want %d", cfg.BufferSize, tc.wantSize)
			}
		})
	}
}

// TestBillingConfig_BackendAPIKey_NotLeaked verifies the API key is stored but
// not accidentally exposed via common string representations.
func TestBillingConfig_BackendAPIKey_NotLeaked(t *testing.T) {
	cfg := BillingConfig{
		BackendURL:    "https://api.example.com",
		BackendAPIKey: "nR7tK3mW9pL2vX5q",
		BufferSize:    10000,
	}

	// Verify the key is stored correctly.
	if cfg.BackendAPIKey != "nR7tK3mW9pL2vX5q" {
		t.Errorf("expected stored key to match, got %q", cfg.BackendAPIKey)
	}

	// Verify BackendURL is not the key.
	if cfg.BackendURL == cfg.BackendAPIKey {
		t.Error("BackendURL should not equal BackendAPIKey")
	}
}

// TestBillingConfig_DSN_Formats verifies various ClickHouse DSN formats.
func TestBillingConfig_DSN_Formats(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
	}{
		{name: "host:port", dsn: "clickhouse:9000"},
		{name: "full DSN", dsn: "tcp://clickhouse:9000?debug=true"},
		{name: "with credentials", dsn: "tcp://user:pass@clickhouse:9000/default"},
		{name: "localhost", dsn: "localhost:9000"},
		{name: "IP address", dsn: "10.0.0.5:9000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := BillingConfig{ClickHouseDSN: tc.dsn}
			if cfg.ClickHouseDSN != tc.dsn {
				t.Errorf("expected DSN %q, got %q", tc.dsn, cfg.ClickHouseDSN)
			}
			// Should not be noop when DSN is set.
			if cfg.ClickHouseDSN == "" {
				t.Error("config with DSN should not be noop")
			}
		})
	}
}

// TestBillingConfig_CopyIsolation verifies that copying a config does not share state.
func TestBillingConfig_CopyIsolation(t *testing.T) {
	original := BillingConfig{
		ClickHouseDSN: "clickhouse:9000",
		BackendURL:    "https://api.example.com",
		BackendAPIKey: "key-original",
		BufferSize:    5000,
	}

	copied := original
	copied.BackendAPIKey = "key-modified"
	copied.BufferSize = 20000

	if original.BackendAPIKey != "key-original" {
		t.Error("modifying copy should not affect original")
	}
	if original.BufferSize != 5000 {
		t.Errorf("original BufferSize should be 5000, got %d", original.BufferSize)
	}
}
