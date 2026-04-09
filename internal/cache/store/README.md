# Cacher Package

This package provides a flexible caching interface with support for multiple storage backends. It offers a unified API for caching operations including reading, writing, deleting, and counter operations.

## Supported Backends

- **Memory** - In-memory cache with LRU eviction and configurable limits
- **Redis** - Distributed cache using Redis
- **Pebble** - Embedded key-value database (RocksDB/LevelDB inspired)
- **File** - File-based cache for persistent storage
- **Noop** - No-operation implementation for testing

## Features

- **Unified Interface**: Single API for all cache operations
- **Context Support**: All operations support context cancellation
- **Type Safety**: Strong typing with `cType` parameter for key namespacing
- **TTL Support**: Time-to-live for cached entries
- **Counter Operations**: Atomic increment/decrement with expiration
- **Pattern Matching**: Delete operations with pattern matching
- **Prefix Operations**: Get/Put/Delete operations with key prefixes
- **Thread Safe**: All implementations are safe for concurrent use

## Quick Start

### Memory Cache (Fast, Single-Instance)

```go
import "github.com/soapbucket/sbproxy/internal/cache/store"

// Create settings for memory cache
settings := &cacher.Settings{
    Driver: "memory",
    MaxObjects: 1000,
    MaxMemory: 100 * 1024 * 1024, // 100MB
}

cache, err := cacher.NewCacher(settings)
if err != nil {
    log.Fatal(err)
}
defer cache.Close()

// Store and retrieve data
data := []byte("hello world")
err = cache.Put(context.Background(), "users", "user123", bytes.NewReader(data))
```

### Pebble Cache (Persistent, High-Performance)

```go
// Create settings for Pebble cache - just needs a path
settings := &cacher.Settings{
    Driver: "pebble",
    Params: map[string]string{
        "path": "./data/cache.db",  // Simple path-based configuration
    },
}

cache, err := cacher.NewCacher(settings)
if err != nil {
    log.Fatal(err)
}
defer cache.Close()

// Store and retrieve data
data := []byte("hello world")
err = cache.Put(context.Background(), "users", "user123", bytes.NewReader(data))
```

## Configuration

### Memory Cache

```go
settings := &cacher.Settings{
    Driver: "memory",
    MaxObjects: 1000,        // Maximum number of objects
    MaxMemory: 100 * 1024 * 1024, // Maximum memory usage in bytes
    Params: map[string]string{
        "duration": "1h",           // Default TTL
        "cleanup_interval": "5m",   // Cleanup interval
    },
}
```

### Redis Cache

```go
settings := &cacher.Settings{
    Driver: "redis",
    Params: map[string]string{
        "dsn":      "redis://localhost:6379",
        "password": "secret",
        "db":       "0",
    },
}
```

### Pebble Cache

```go
settings := &cacher.Settings{
    Driver: "pebble",
    Params: map[string]string{
        "path": "/path/to/pebble.db",  // Path to database directory
        // Optional parameters:
        // "block_cache_size": "104857600",        // 100MB (default)
        // "mem_table_size": "67108864",           // 64MB (default)
        // "l0_compaction_threshold": "4",         // Start compaction at 4 L0 files (default)
        // "l0_stop_writes_threshold": "8",        // Stop writes at 8 L0 files (default)
    },
}
```

### File Cache

```go
settings := &cacher.Settings{
    Driver: "file",
    Params: map[string]string{
        "base_dir":    "/path/to/cache/directory",
        "max_size":    "1048576",  // 1MB max file size
        "compression": "true",     // Enable compression
    },
}
```

## API Reference

### Core Interface

```go
type Cacher interface {
    // Reader operations
    Get(ctx context.Context, cType string, key string) (io.Reader, error)
    GetWithPrefix(ctx context.Context, cType string, key string) (io.Reader, error)
    
    // Writer operations
    Put(ctx context.Context, cType string, key string, r io.Reader) error
    PutWithExpires(ctx context.Context, cType string, key string, r io.Reader, expires time.Duration) error
    PutWithPrefix(ctx context.Context, cType string, key string, r io.Reader) error
    PutWithPrefixAndExpires(ctx context.Context, cType string, key string, r io.Reader, expires time.Duration) error
    
    // Delete operations
    Delete(ctx context.Context, cType string, key string) error
    DeleteByPattern(ctx context.Context, cType string, pattern string) error
    DeleteWithPrefix(ctx context.Context, cType string, key string) error
    
    // Counter operations
    Increment(ctx context.Context, cType string, key string, count int64) (int64, error)
    IncrementWithExpires(ctx context.Context, cType string, key string, count int64, expires time.Duration) (int64, error)
    
    // Lifecycle
    Close() error
}
```

### Settings Structure

```go
type Settings struct {
    Driver     string            `json:"driver"`      // Backend driver name
    MaxObjects int               `json:"max_objects"` // Max objects (memory driver)
    MaxMemory  int64             `json:"max_memory"`  // Max memory in bytes (memory driver)
    Params     map[string]string `json:"params"`      // Driver-specific parameters
}
```

## Usage Examples

### Basic Operations

```go
// Store with TTL
err := cache.PutWithExpires(ctx, "sessions", "session123", 
    bytes.NewReader(data), 30*time.Minute)

// Get data
reader, err := cache.Get(ctx, "sessions", "session123")
if err != nil {
    if err == cacher.ErrNotFound {
        // Handle not found
    }
    return err
}
defer reader.Close()

// Delete data
err = cache.Delete(ctx, "sessions", "session123")
```

### Counter Operations

```go
// Increment counter
count, err := cache.Increment(ctx, "stats", "page_views", 1)
if err != nil {
    log.Fatal(err)
}

// Increment with expiration
count, err := cache.IncrementWithExpires(ctx, "temp_stats", "visits", 1, time.Hour)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Current count: %d\n", count)
```

### Pattern Operations

```go
// Delete all keys matching pattern
err := cache.DeleteByPattern(ctx, "sessions", "user_*")

// Get with prefix
reader, err := cache.GetWithPrefix(ctx, "cache", "prefix_")
```

### Available Drivers

```go
drivers := cacher.AvailableDrivers()
fmt.Println("Available drivers:", drivers)
// Output: [memory redis pebble file noop]
```

## Error Handling

The package defines several error types:

- `ErrNotFound` - Key not found
- `ErrUnsupportedDriver` - Unknown driver specified
- `ErrInvalidDuration` - Invalid duration parameter
- `ErrInvalidInterval` - Invalid cleanup interval

## Thread Safety

All cacher implementations are safe for concurrent use by multiple goroutines. The memory implementation uses read-write locks for optimal performance, while other implementations rely on their underlying storage mechanisms for thread safety.

## File Cache Features

The file cache implementation has been optimized for better performance and storage efficiency:

### Optimized File Format
- **Binary Header**: Uses efficient binary format instead of JSON
- **Compression Support**: Optional gzip compression to reduce disk usage
- **Fast Seeking**: Fixed-size header length for quick file parsing
- **Atomic Operations**: Temporary files ensure data integrity

### File Format Structure
```
{header_length}{header}{data}
```
- `header_length`: 4 bytes (big-endian uint32)
- `header`: `{expires},{compression}` (comma-separated)
- `data`: Raw data or gzip-compressed data

### Compression Configuration
```go
settings := &cacher.Settings{
    Driver: "file",
    Params: map[string]string{
        "base_dir":    "/tmp/cache",
        "compression": "true",  // Enable gzip compression
        "max_size":    "1048576", // 1MB max file size
    },
}
```

### Performance Benefits
- **Faster I/O**: No JSON parsing overhead
- **Reduced Storage**: Compression saves disk space
- **Better Performance**: Direct binary operations
- **Configurable**: Enable/disable compression per instance

## Performance Considerations

- **Memory Cache**: Fastest for single-instance applications
- **Redis**: Best for distributed applications with multiple instances
- **Pebble**: Good balance of performance and persistence with excellent stability
- **File Cache**: Optimized with binary format and optional compression
- **Noop**: Zero overhead for testing scenarios

## Testing

The package includes comprehensive tests and a noop implementation for testing:

```go
// Use noop for testing
settings := &cacher.Settings{Driver: "noop"}
cache, err := cacher.NewCacher(settings)
// All operations will succeed but not store data
```
