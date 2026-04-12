// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// HTTPCacheConfig configures HTTP-aware caching for callbacks
type HTTPCacheConfig struct {
	// Enable HTTP header-aware caching
	HonorHTTPHeaders bool `json:"honor_http_headers,omitempty"`

	// Size threshold for L2 cache (default: 1MB)
	L2MaxSize int64 `json:"l2_max_size,omitempty"`

	// Stale-while-revalidate configuration
	StaleWhileRevalidate *StaleWhileRevalidateConfig `json:"stale_while_revalidate,omitempty"`

	// Stale-if-error configuration
	StaleIfError *StaleIfErrorConfig `json:"stale_if_error,omitempty"`

	// Background refresh configuration
	BackgroundRefresh *BackgroundRefreshConfig `json:"background_refresh,omitempty"`

	// Message bus for cache invalidation
	InvalidationTopic string `json:"invalidation_topic,omitempty"`
}

// StaleWhileRevalidateConfig configures stale-while-revalidate behavior
type StaleWhileRevalidateConfig struct {
	Enabled  bool            `json:"enabled,omitempty"`
	Duration reqctx.Duration `json:"duration,omitempty"` // Default duration if not in headers
}

// StaleIfErrorConfig configures stale-if-error behavior
type StaleIfErrorConfig struct {
	Enabled  bool            `json:"enabled,omitempty"`
	Duration reqctx.Duration `json:"duration,omitempty"` // Default duration if not in headers
}

// BackgroundRefreshConfig configures background refresh queue
type BackgroundRefreshConfig struct {
	Enabled      bool `json:"enabled,omitempty"`
	Workers      int  `json:"workers,omitempty"`
	MaxQueueSize int  `json:"max_queue_size,omitempty"`
}

// HTTPCallbackContext provides HTTP cache context to callbacks
type HTTPCallbackContext struct {
	HTTPCache    *HTTPCallbackCache
	Parser       *HTTPCacheParser
	RefreshQueue *RefreshQueue
	Messenger    messenger.Messenger
	Config       *HTTPCacheConfig
}
