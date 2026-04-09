# HTTP Cache Transport

A comprehensive HTTP caching implementation for Go that provides RFC 7234 compliant HTTP caching with support for ETags, Cache-Control directives, conditional requests, and more.

## Features

- **RFC 7234 Compliant**: Full support for HTTP caching specifications
- **ETag Support**: Automatic ETag generation and validation
- **Cache-Control Directives**: Respects all standard cache control directives
- **Conditional Requests**: Handles If-None-Match and If-Modified-Since
- **Vary Header Support**: Proper cache key generation considering Vary headers
- **Pragma Support**: HTTP/1.0 compatibility with Pragma: no-cache
- **Configurable**: Flexible configuration for different caching scenarios
- **High Performance**: Optimized for speed with connection pooling and efficient algorithms
- **Multiple Backends**: Works with any `cacher.Cacher` implementation

## Quick Start

```go
package main

import (
    "net/http"
    "github.com/soapbucket/sbproxy/internal/cache/store"
    "github.com/soapbucket/sbproxy/internal/engine/transport"
)

func main() {
    // Create a cache manager (memory, Redis, Pebble, etc.)
    cacheManager, err := cacher.NewCacher("memory://")
    if err != nil {
        panic(err)
    }
    defer cacheManager.Close()

    // Create HTTP client with caching
    client := &http.Client{
        Transport: transport.NewHTTPCacheTransport(
            http.DefaultTransport,
            cacheManager,
            transport.DefaultCacheConfig(),
        ),
    }

    // Make requests - they will be automatically cached
    resp, err := client.Get("https://api.example.com/data")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
}
```

## Configuration

### CacheConfig

The `CacheConfig` struct allows you to customize caching behavior:

```go
config := &transport.CacheConfig{
    // Cache error responses (4xx, 5xx)
    CacheErrors: false,
    
    // Default TTL for responses without cache headers
    DefaultTTL: 5 * time.Minute,
    
    // Maximum TTL for any cached response
    MaxTTL: 24 * time.Hour,
    
    // Respect no-cache directives in requests
    RespectNoCache: true,
    
    // Respect private cache directives
    RespectPrivate: true,
}
```

### Default Configuration

```go
config := transport.DefaultCacheConfig()
// CacheErrors: false
// DefaultTTL: 5 minutes
// MaxTTL: 24 hours
// RespectNoCache: true
// RespectPrivate: true
```

## Cache Backends

The HTTP cache works with any `cacher.Cacher` implementation:

### Memory Cache
```go
cacheManager, err := cacher.NewCacher("memory://")
```

### Redis Cache
```go
cacheManager, err := cacher.NewCacher("redis://localhost:6379")
```

### Pebble Cache
```go
settings := &cacher.Settings{
    Driver: "pebble",
    Params: map[string]string{
        "path": "/tmp/pebble.db",
    },
}
cacheManager, err := cacher.NewCacher(settings)
```

### File Cache
```go
cacheManager, err := cacher.NewCacher("file:///tmp/cache")
```

## HTTP Cache Features

### ETag Support

The cache automatically generates ETags for responses and handles conditional requests:

```go
// First request - response is cached with ETag
resp1, err := client.Get("https://api.example.com/data")
// Response includes ETag: "abc123"

// Second request with If-None-Match
req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
req.Header.Set("If-None-Match", `"abc123"`)
resp2, err := client.Do(req)
// Returns 304 Not Modified if content hasn't changed
```

### Cache-Control Directives

The cache respects all standard Cache-Control directives:

```go
// Server response with cache control
// Cache-Control: max-age=3600, public
// Response will be cached for 1 hour

// Server response with no-cache
// Cache-Control: no-cache
// Response will not be cached

// Server response with private
// Cache-Control: private
// Response will not be cached (unless RespectPrivate: false)
```

### Conditional Requests

Automatic handling of conditional requests:

```go
// If-None-Match (ETag validation)
req.Header.Set("If-None-Match", `"etag-value"`)

// If-Modified-Since (Last-Modified validation)
req.Header.Set("If-Modified-Since", "Mon, 01 Jan 2024 12:00:00 GMT")
```

### Vary Header Support

The cache considers Vary headers when generating cache keys:

```go
// Server response with Vary header
// Vary: Accept, User-Agent
// Different Accept or User-Agent headers will create separate cache entries
```

## Advanced Usage

### Custom Cache Key Generation

The cache uses the existing `common.CreateCacheKey` function which considers:
- HTTP method
- URL (with sorted query parameters)
- Vary headers
- Custom options

### Error Response Caching

Enable caching of error responses:

```go
config := &transport.CacheConfig{
    CacheErrors: true, // Cache 4xx and 5xx responses
}
```

### Bypassing Cache

Clients can bypass the cache using standard HTTP headers:

```go
// Request with no-cache
req.Header.Set("Cache-Control", "no-cache")

// Request with Pragma no-cache (HTTP/1.0)
req.Header.Set("Pragma", "no-cache")
```

### Cache Invalidation

The cache automatically expires entries based on:
- Cache-Control max-age
- Expires header
- Default TTL

Manual invalidation can be done through the cache manager:

```go
// Delete specific cache entry
cacheManager.Delete(context.Background(), "cache.header:key")

// Delete all cache entries with prefix
cacheManager.DeleteByPrefix(context.Background(), "cache.header:")
```

## Performance Considerations

### Memory Usage

- Maximum cache size per response: 2MB
- Uses xxHash for fast ETag generation
- Efficient header cleaning (removes Set-Cookie)
- Connection pooling for underlying transport

### Concurrent Access

The cache is safe for concurrent use:
- Thread-safe cache operations
- Efficient read/write patterns
- Minimal locking overhead

### Benchmark Results

Typical performance characteristics:
- Cache hit: ~10-50μs
- Cache miss: ~1-5ms (depending on network)
- Memory allocation: Minimal with object pooling
- ETag generation: ~1-5μs

## Testing

### Unit Tests

```bash
go test ./internal/engine/transport -v
```

### Benchmark Tests

```bash
go test ./internal/engine/transport -bench=. -benchmem
```

### Integration Tests

```bash
go test ./internal/engine/transport -tags=integration
```

## Examples

### Basic HTTP Client with Caching

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "time"
    
    "github.com/soapbucket/sbproxy/internal/cache/store"
    "github.com/soapbucket/sbproxy/internal/engine/transport"
)

func main() {
    // Create cache manager
    cacheManager, err := cacher.NewCacher("memory://")
    if err != nil {
        panic(err)
    }
    defer cacheManager.Close()

    // Create HTTP client with caching
    client := &http.Client{
        Transport: transport.NewHTTPCacheTransport(
            http.DefaultTransport,
            cacheManager,
            transport.DefaultCacheConfig(),
        ),
        Timeout: 30 * time.Second,
    }

    // Make requests
    for i := 0; i < 5; i++ {
        resp, err := client.Get("https://httpbin.org/cache/60")
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            continue
        }
        
        body, _ := io.ReadAll(resp.Body)
        fmt.Printf("Request %d: Status %d, Body length %d\n", 
            i+1, resp.StatusCode, len(body))
        resp.Body.Close()
        
        time.Sleep(1 * time.Second)
    }
}
```

### Custom Configuration

```go
package main

import (
    "net/http"
    "time"
    
    "github.com/soapbucket/sbproxy/internal/cache/store"
    "github.com/soapbucket/sbproxy/internal/engine/transport"
)

func main() {
    // Custom cache configuration
    config := &transport.CacheConfig{
        CacheErrors:    true,                // Cache error responses
        DefaultTTL:     10 * time.Minute,    // 10 minute default TTL
        MaxTTL:         2 * time.Hour,       // 2 hour maximum TTL
        RespectNoCache: false,               // Ignore no-cache directives
        RespectPrivate: false,               // Cache private responses
    }

    // Create cache manager with Redis
    cacheManager, err := cacher.NewCacher("redis://localhost:6379")
    if err != nil {
        panic(err)
    }
    defer cacheManager.Close()

    // Create HTTP client
    client := &http.Client{
        Transport: transport.NewHTTPCacheTransport(
            http.DefaultTransport,
            cacheManager,
            config,
        ),
    }

    // Use client...
    resp, err := client.Get("https://api.example.com/data")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
}
```

### Conditional Requests

```go
package main

import (
    "fmt"
    "net/http"
    
    "github.com/soapbucket/sbproxy/internal/cache/store"
    "github.com/soapbucket/sbproxy/internal/engine/transport"
)

func main() {
    cacheManager, _ := cacher.NewManager("memory://")
    defer cacheManager.Close()

    client := &http.Client{
        Transport: transport.NewHTTPCacheTransport(
            http.DefaultTransport,
            cacheManager,
            transport.DefaultCacheConfig(),
        ),
    }

    // First request
    resp1, err := client.Get("https://httpbin.org/etag/test-etag")
    if err != nil {
        panic(err)
    }
    defer resp1.Body.Close()
    
    etag := resp1.Header.Get("ETag")
    fmt.Printf("First request: Status %d, ETag %s\n", resp1.StatusCode, etag)

    // Conditional request
    req, _ := http.NewRequest("GET", "https://httpbin.org/etag/test-etag", nil)
    req.Header.Set("If-None-Match", etag)
    
    resp2, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp2.Body.Close()
    
    fmt.Printf("Conditional request: Status %d\n", resp2.StatusCode)
    // Should return 304 Not Modified if content hasn't changed
}
```

## Troubleshooting

### Common Issues

1. **Cache not working**: Check if the response has cacheable headers
2. **Memory usage**: Monitor cache size and consider TTL settings
3. **Stale data**: Ensure proper cache invalidation or TTL settings
4. **Performance**: Use benchmark tests to identify bottlenecks

### Debug Logging

Enable debug logging to see cache operations:

```go
import "log/slog"

// Set log level to debug
slog.SetLogLoggerLevel(slog.LevelDebug)
```

### Cache Statistics

Monitor cache performance:

```go
// Check cache hit/miss ratios
// Monitor memory usage
// Track response times
```

## Migration from Original Cacher

The new HTTP cache is a drop-in replacement for the original `CacherTransport`:

```go
// Old way
transport := transport.NewCacher(http.DefaultTransport, cacheManager, false)

// New way
transport := transport.NewHTTPCacheTransport(http.DefaultTransport, cacheManager, nil)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run benchmarks to ensure performance
5. Submit a pull request

## License

Apache License 2.0. See the project root LICENSE file for details.