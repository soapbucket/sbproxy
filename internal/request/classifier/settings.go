// Package classifier wraps the prompt-classifier sidecar client with circuit
// breaker protection, per-workspace rate limiting, and an embedding cache.
package classifier

import (
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// Settings is parsed from the `local_llm` key in sb.yml.
type Settings struct {
	Address        string                 `yaml:"address" mapstructure:"address"`
	PoolSize       int                    `yaml:"pool_size" mapstructure:"pool_size"`
	Timeout        reqctx.Duration        `yaml:"timeout" mapstructure:"timeout"`
	ReadyTimeout   reqctx.Duration        `yaml:"ready_timeout" mapstructure:"ready_timeout"`
	FailOpen       bool                   `yaml:"fail_open" mapstructure:"fail_open"`
	RateLimit      RateLimitSettings      `yaml:"rate_limit" mapstructure:"rate_limit"`
	EmbeddingCache EmbeddingCacheSettings `yaml:"embedding_cache" mapstructure:"embedding_cache"`
}

// RateLimitSettings configures per-workspace rate limiting for sidecar calls.
type RateLimitSettings struct {
	RequestsPerSecond float64 `yaml:"requests_per_second" mapstructure:"requests_per_second"`
	Burst             int     `yaml:"burst" mapstructure:"burst"`
}

// EmbeddingCacheSettings configures the LRU embedding cache.
type EmbeddingCacheSettings struct {
	MaxEntries int             `yaml:"max_entries" mapstructure:"max_entries"`
	TTL        reqctx.Duration `yaml:"ttl" mapstructure:"ttl"`
}

// IsEnabled returns true when an address is configured, meaning the sidecar should be used.
func (s *Settings) IsEnabled() bool { return s.Address != "" }

// DefaultSettings returns Settings with production defaults applied.
func DefaultSettings() Settings {
	return Settings{
		PoolSize:     4,
		Timeout:      reqctx.Duration{Duration: 2 * time.Second},
		ReadyTimeout: reqctx.Duration{Duration: 10 * time.Second},
		FailOpen:     true,
		RateLimit: RateLimitSettings{
			RequestsPerSecond: 100,
			Burst:             50,
		},
		EmbeddingCache: EmbeddingCacheSettings{
			MaxEntries: 10000,
			TTL:        reqctx.Duration{Duration: 5 * time.Minute},
		},
	}
}

// withDefaults fills in zero-value fields with production defaults.
func (s Settings) withDefaults() Settings {
	d := DefaultSettings()
	if s.PoolSize == 0 {
		s.PoolSize = d.PoolSize
	}
	if s.Timeout.Duration == 0 {
		s.Timeout = d.Timeout
	}
	if s.ReadyTimeout.Duration == 0 {
		s.ReadyTimeout = d.ReadyTimeout
	}
	if s.RateLimit.RequestsPerSecond == 0 {
		s.RateLimit.RequestsPerSecond = d.RateLimit.RequestsPerSecond
	}
	if s.RateLimit.Burst == 0 {
		s.RateLimit.Burst = d.RateLimit.Burst
	}
	if s.EmbeddingCache.MaxEntries == 0 {
		s.EmbeddingCache.MaxEntries = d.EmbeddingCache.MaxEntries
	}
	if s.EmbeddingCache.TTL.Duration == 0 {
		s.EmbeddingCache.TTL = d.EmbeddingCache.TTL
	}
	return s
}
