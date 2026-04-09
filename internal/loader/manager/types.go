// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/request/geoip"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/uaparser"
)

// CacheLevel is a numeric type for cache level.
type CacheLevel int

const (
	// L1Cache is a constant for l1 cache.
	L1Cache CacheLevel = iota
	// L2Cache is a constant for l2 cache.
	L2Cache
	// L3Cache is a constant for l3 cache.
	L3Cache
)

// Manager defines the interface for manager operations.
type Manager interface {
	GetLocation(*http.Request) (*geoip.Result, error)
	GetUserAgent(*http.Request) (*uaparser.Result, error)

	// Crypto
	EncryptString(string) (string, error)
	DecryptString(string) (string, error)
	EncryptStringWithContext(data string, context string) (string, error)
	DecryptStringWithContext(data string, context string) (string, error)
	SignString(string) (string, error)
	VerifyString(string, string) (bool, error)

	// Session
	GetSessionCache() SessionCache

	// Getters
	GetStorage() storage.Storage
	GetGlobalSettings() GlobalSettings
	GetCache(CacheLevel) cacher.Cacher
	GetMessenger() messenger.Messenger

	GetServerContext() context.Context

	// Worker pools for goroutine management
	GetCallbackPool() WorkerPool
	GetCachePool() WorkerPool

	// Lifecycle
	Close() error
}

// WorkerPool interface for submitting tasks
type WorkerPool interface {
	Submit(ctx context.Context, task func() error) error
	Stats() WorkerPoolStats
}

// WorkerPoolStats represents worker pool statistics
type WorkerPoolStats struct {
	Name           string
	MaxWorkers     int
	ActiveWorkers  int
	TotalSubmitted int64
	TotalCompleted int64
	TotalFailed    int64
}

// OriginLoaderSettings holds configuration for origin loader.
type OriginLoaderSettings struct {
	MaxOriginRecursionDepth   int           `json:"max_origin_recursion_depth"`
	MaxOriginForwardDepth     int           `json:"max_origin_forward_depth"`
	OriginCacheTTL            time.Duration `json:"origin_cache_ttl"`
	HostnameFallback          bool          `json:"hostname_fallback"`
	HostFilterEnabled         bool          `json:"host_filter_enabled"`
	HostFilterEstimatedItems  int           `json:"host_filter_estimated_items"`
	HostFilterFPRate          float64       `json:"host_filter_fp_rate"`
	HostFilterRebuildInterval time.Duration `json:"host_filter_rebuild_interval"`
	HostFilterRebuildJitter   float64       `json:"host_filter_rebuild_jitter"`
}

// CookieSettings holds configuration for cookie.
type CookieSettings struct {
	SessionCookieName string `json:"session_cookie_name"`
	SessionMaxAge     int    `json:"session_max_age"`
	StickyCookieName  string `json:"sticky_cookie_name"`
}

// HTTP3Settings holds configuration for http3.
type HTTP3Settings struct {
	EnableHTTP3   bool `json:"enable_http3"`
	HTTP3BindPort int  `json:"http3_bind_port"`
}

// DebugSettings holds configuration for debug.
type DebugSettings struct {
	Debug          bool `json:"debug"`
	DisplayHeaders bool `json:"display_headers"`
}

// GlobalSettings holds configuration for global.
type GlobalSettings struct {
	OriginLoaderSettings OriginLoaderSettings           `json:"origin_loader_settings"`
	StorageSettings      storage.Settings               `json:"storage_settings"`
	CacherSettings       map[CacheLevel]cacher.Settings `json:"cacher_settings"`
	MessengerSettings    messenger.Settings             `json:"messenger_settings"`
	GeoIPSettings        geoip.Settings                 `json:"geoip_settings"`
	UAParserSettings     uaparser.Settings              `json:"uaparser_settings"`
	CryptoSettings       crypto.Settings                `json:"crypto_settings"`
	CookieSettings       CookieSettings                 `json:"cookie_settings"`
	HTTP3Settings        HTTP3Settings                  `json:"http3_settings"`
	DebugSettings        DebugSettings                  `json:"debug_settings"`

	// other settings
	CompressionLevel  int           `json:"compression_level"`
	L2CacheTimeout    time.Duration `json:"l2_cache_timeout"`
	MaxRecursionDepth int           `json:"max_recursion_depth"`
}

// SessionCache defines the interface for session cache operations.
type SessionCache interface {
	Get(context.Context, string) (io.Reader, error)
	Put(context.Context, string, io.Reader, time.Duration) error
	Delete(context.Context, string) error
}
