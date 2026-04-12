package config

import "testing"

func TestConfig_OriginChain(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "single config no parent",
			config:   &Config{Hostname: "www.example.com", Version: "1.2"},
			expected: "www.example.com/1.2",
		},
		{
			name: "two-level chain",
			config: &Config{
				Hostname: "api.internal",
				Version:  "3.0",
				Parent:   &Config{Hostname: "www.example.com", Version: "1.2"},
			},
			expected: "www.example.com/1.2, api.internal/3.0",
		},
		{
			name: "three-level chain",
			config: &Config{
				Hostname: "api-v2.internal",
				Version:  "4.3",
				Parent: &Config{
					Hostname: "router.internal",
					Version:  "1.1",
					Parent:   &Config{Hostname: "gateway.example.com", Version: "2.0"},
				},
			},
			expected: "gateway.example.com/2.0, router.internal/1.1, api-v2.internal/4.3",
		},
		{
			name:     "empty version",
			config:   &Config{Hostname: "www.example.com", Version: ""},
			expected: "www.example.com/",
		},
		{
			name:     "empty hostname",
			config:   &Config{Hostname: "", Version: "1.0"},
			expected: "/1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.OriginChain()
			if result != tt.expected {
				t.Errorf("OriginChain() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func BenchmarkConfig_OriginChain(b *testing.B) {
	b.ReportAllocs()
	cfg := &Config{
		Hostname: "api-v2.internal",
		Version:  "4.3",
		Parent: &Config{
			Hostname: "router.internal",
			Version:  "1.1",
			Parent:   &Config{Hostname: "gateway.example.com", Version: "2.0"},
		},
	}
	for i := 0; i < b.N; i++ {
		_ = cfg.OriginChain()
	}
}
