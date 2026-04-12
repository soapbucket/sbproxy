// Package cacher implements multi-tier response caching with support for memory and Redis backends.
package cacher

import "time"

// Driver names
const (
	// DriverMemory is a constant for driver memory.
	DriverMemory    = "memory"
	// DriverRedis is a constant for driver redis.
	DriverRedis     = "redis"
	// DriverPebble is a constant for driver pebble.
	DriverPebble    = "pebble"
	// DriverFile is a constant for driver file.
	DriverFile      = "file"
	// DriverNoop is a constant for driver noop.
	DriverNoop      = "noop"
	// DriverMemcached is a constant for driver memcached.
	DriverMemcached = "memcached"
	// WrapperDSN is a constant for wrapper dsn.
	WrapperDSN      = "wrapper"
)

// DSN parameter key
const (
	// ParamDSN is a constant for param dsn.
	ParamDSN = "dsn"
)

// Tracing constants
const (
	tracerName = "github.com/soapbucket/sbproxy/internal/cache/store"
)

// File cacher constants
const (
	defaultBaseDir     = "/tmp/cache"
	defaultCompression = false
	// SettingBaseDir is a constant for setting base dir.
	SettingBaseDir     = "base_dir"
	// SettingMaxSize is a constant for setting max size.
	SettingMaxSize     = "max_size"
	// SettingCompression is a constant for setting compression.
	SettingCompression = "compression"
)

// Memory cacher constants
const (
	defaultCleanupInterval = time.Minute
	defaultExpireInterval  = time.Minute * 5
	defaultCapacity        = 100000

	// SettingDuration is a constant for setting duration.
	SettingDuration        = "duration"
	// SettingCapacity is a constant for setting capacity.
	SettingCapacity        = "capacity"
	// SettingCleanupInterval is a constant for setting cleanup interval.
	SettingCleanupInterval = "cleanup_interval"
	// SettingMaxObjects is a constant for setting max objects.
	SettingMaxObjects      = "max_objects"
	// SettingMaxMemory is a constant for setting max memory.
	SettingMaxMemory       = "max_memory"
)

// Pebble cacher constants
const (
	// SettingPath is a constant for setting path.
	SettingPath                  = "path"
	// SettingBlockCacheSize is a constant for setting block cache size.
	SettingBlockCacheSize        = "block_cache_size"
	// SettingMemTableSize is a constant for setting mem table size.
	SettingMemTableSize          = "mem_table_size"
	// SettingL0CompactionThreshold is a constant for setting l0 compaction threshold.
	SettingL0CompactionThreshold = "l0_compaction_threshold"
	// SettingL0StopWritesThreshold is a constant for setting l0 stop writes threshold.
	SettingL0StopWritesThreshold = "l0_stop_writes_threshold"

	defaultBlockCacheSize        = 100 << 20 // 100MB block cache
	defaultMemTableSize          = 64 << 20  // 64MB memtable
	defaultL0CompactionThreshold = 4         // Start compaction at 4 L0 files
	defaultL0StopWritesThreshold = 8         // Stop writes at 8 L0 files
)

// Memcached cacher constants
const (
	// SettingServers is a constant for setting servers.
	SettingServers        = "servers"
	// SettingPrefix is a constant for setting prefix.
	SettingPrefix         = "prefix"
	// SettingMaxItemSize is a constant for setting max item size.
	SettingMaxItemSize    = "max_item_size"
	// SettingConnectTimeout is a constant for setting connect timeout.
	SettingConnectTimeout = "connect_timeout"
	// SettingTimeout is a constant for setting timeout.
	SettingTimeout        = "timeout"
	// SettingMaxIdleConns is a constant for setting max idle conns.
	SettingMaxIdleConns   = "max_idle_conns"

	defaultPrefix         = "sb"
	defaultMaxItemSize    = 1 << 20 // 1MB
	defaultConnectTimeout = 100     // ms
	defaultTimeout        = 50      // ms
	defaultMaxIdleConns   = 10
	maxMemcachedKeyLen    = 250
)


