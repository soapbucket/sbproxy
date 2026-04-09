package classifier

import (
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestSettings_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		enabled bool
	}{
		{"empty address", "", false},
		{"with address", "127.0.0.1:9400", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Settings{Address: tt.addr}
			if got := s.IsEnabled(); got != tt.enabled {
				t.Fatalf("IsEnabled() = %v, want %v", got, tt.enabled)
			}
		})
	}
}

func TestSettings_WithDefaults(t *testing.T) {
	// Zero-value settings should get all defaults (except FailOpen which is a bool
	// and cannot be distinguished from "explicitly false" vs "not set" - it is
	// handled by viper defaults instead).
	s := Settings{Address: "localhost:9400"}
	filled := s.withDefaults()

	if filled.PoolSize != 4 {
		t.Fatalf("expected pool_size 4, got %d", filled.PoolSize)
	}
	if filled.Timeout.Duration != 2*time.Second {
		t.Fatalf("expected timeout 2s, got %v", filled.Timeout.Duration)
	}
	if filled.ReadyTimeout.Duration != 10*time.Second {
		t.Fatalf("expected ready_timeout 10s, got %v", filled.ReadyTimeout.Duration)
	}
	if filled.RateLimit.RequestsPerSecond != 100 {
		t.Fatalf("expected 100 rps, got %f", filled.RateLimit.RequestsPerSecond)
	}
	if filled.RateLimit.Burst != 50 {
		t.Fatalf("expected burst 50, got %d", filled.RateLimit.Burst)
	}
	if filled.EmbeddingCache.MaxEntries != 10000 {
		t.Fatalf("expected 10000 max entries, got %d", filled.EmbeddingCache.MaxEntries)
	}
	if filled.EmbeddingCache.TTL.Duration != 5*time.Minute {
		t.Fatalf("expected 5m TTL, got %v", filled.EmbeddingCache.TTL.Duration)
	}
}

func TestSettings_WithDefaultsPreservesExplicit(t *testing.T) {
	s := Settings{
		Address:  "localhost:9400",
		PoolSize: 8,
		Timeout:  reqctx.Duration{Duration: 5 * time.Second},
		RateLimit: RateLimitSettings{
			RequestsPerSecond: 200,
			Burst:             100,
		},
	}
	filled := s.withDefaults()

	if filled.PoolSize != 8 {
		t.Fatalf("expected explicit pool_size 8, got %d", filled.PoolSize)
	}
	if filled.Timeout.Duration != 5*time.Second {
		t.Fatalf("expected explicit timeout 5s, got %v", filled.Timeout.Duration)
	}
	if filled.RateLimit.RequestsPerSecond != 200 {
		t.Fatalf("expected explicit 200 rps, got %f", filled.RateLimit.RequestsPerSecond)
	}
	if filled.RateLimit.Burst != 100 {
		t.Fatalf("expected explicit burst 100, got %d", filled.RateLimit.Burst)
	}
	// Non-explicit fields should still get defaults
	if filled.ReadyTimeout.Duration != 10*time.Second {
		t.Fatalf("expected default ready_timeout 10s, got %v", filled.ReadyTimeout.Duration)
	}
}

func TestDefaultSettings(t *testing.T) {
	d := DefaultSettings()

	if d.PoolSize != 4 {
		t.Fatalf("expected pool_size 4, got %d", d.PoolSize)
	}
	if !d.FailOpen {
		t.Fatal("expected fail_open true")
	}
	if d.EmbeddingCache.MaxEntries != 10000 {
		t.Fatalf("expected 10000, got %d", d.EmbeddingCache.MaxEntries)
	}
}
