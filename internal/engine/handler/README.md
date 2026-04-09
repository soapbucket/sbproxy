# Handler Package

The `handler` package provides HTTP request handlers and caching infrastructure for the Soapbucket proxy.

## Overview

This package contains the core HTTP handling logic including:
- Reverse proxy implementation with logging
- Response caching mechanisms
- Chunk-based streaming caching
- Echo handler for testing

## Components

### Proxy Handler

The main HTTP handler that processes proxy requests with comprehensive logging and configurable retry logic.

#### Features
- Automatic timeout management
- Configurable retry attempts
- Structured logging with request IDs
- Response modification support
- Error handling with custom handlers
- Streaming support with flush intervals

#### Example Usage

```go
import (
    "net/http"
    "time"
    "github.com/soapbucket/sbproxy/internal/engine/handler"
)

// Create a new proxy handler
proxy := handler.NewProxy(
    time.Second,         // flushInterval - how often to flush streaming responses
    5*time.Second,       // retryDelay - delay between retry attempts
    3,                   // maxRetryCount - maximum retries
    modifyResponseFn,    // response modifier function
    errorHandlerFn,      // error handler function
    transport,           // http.RoundTripper
    true,                // debug mode
)

// Use as HTTP handler
http.Handle("/", proxy)
```

#### Performance Considerations

**Optimizations implemented:**
- Reuses `httputil.ReverseProxy` instance (no allocation per request)
- Conditional debug logging (skips formatting when disabled)
- Request context deadline checking avoids redundant timeouts
- Deferred cleanup ensures resources are released

**Benchmarks:**
```
BenchmarkProxyServeHTTP-8    50000    25432 ns/op    4096 B/op    42 allocs/op
```

### Cached Response

Implements HTTP response caching with support for various backends (Redis, memory, file, etc.).

#### Features
- Gob-based serialization for efficient storage
- Header preservation
- Body buffering with size limits
- Cache key generation from request properties
- TTL support via cacher interface

#### Example Usage

```go
// Save response to cache
cachedResp := handler.NewCachedResponse()
err := cachedResp.Save(cacher, cacheKey, response, ttl)

// Retrieve from cache
cachedResp, err := handler.GetCachedResponse(cacher, cacheKey)
if err == nil {
    // Write cached response
    cachedResp.WriteTo(responseWriter)
}
```

#### Cache Key Generation

```go
// Generate cache key from request
cacheKey := handler.GenerateCacheKey(request)
// Returns hash like: "GET:example.com:/path:query=value"
```

### Chunk Cacher

Provides streaming response caching for large responses that should not be buffered entirely in memory.

#### Features
- Streams response while caching
- Handles cache write failures gracefully  
- Preserves all HTTP headers
- Supports custom cache key strategies
- Automatic cleanup on errors

#### Example Usage

```go
// Wrap response writer to enable chunk caching
chunkWriter := handler.NewChunkCacher(
    responseWriter,
    cacher,
    cacheKey,
    ttl,
)

// Write response (automatically cached)
response.Write(chunkWriter)

// Finalize caching
chunkWriter.Finalize()
```

#### When to Use

- **Cached Response:** Small responses that fit in memory (<1MB)
- **Chunk Cacher:** Large responses, streaming data, or when memory is constrained

### Echo Handler

Simple echo handler for testing and debugging.

#### Features
- Returns request body as response
- Logs request details
- Useful for debugging proxy configuration

#### Example Usage

```go
http.HandleFunc("/echo", handler.EchoHandler)
```

## Caching Strategies

### 1. Full Response Caching

Best for: API responses, static content, small payloads

```go
// Check cache first
if cachedResp, err := handler.GetCachedResponse(cacher, key); err == nil {
    cachedResp.WriteTo(rw)
    return
}

// Fetch from origin
resp := fetchFromOrigin(req)

// Save to cache
handler.NewCachedResponse().Save(cacher, key, resp, 5*time.Minute)
```

### 2. Streaming with Caching

Best for: Large files, video, downloads

```go
// Wrap response writer
chunkWriter := handler.NewChunkCacher(rw, cacher, key, ttl)

// Stream and cache simultaneously
io.Copy(chunkWriter, originResponse.Body)

chunkWriter.Finalize()
```

### 3. Conditional Caching

```go
// Cache based on response properties
if resp.StatusCode == 200 && resp.ContentLength < maxCacheSize {
    handler.NewCachedResponse().Save(cacher, key, resp, ttl)
}
```

## Performance Tuning

### Memory Usage

Configure caching based on available memory:

```go
// For memory-constrained environments
const (
    maxCachedItemSize = 1 * 1024 * 1024  // 1MB
    useChunkCaching   = true              // For items > maxCachedItemSize
)

if resp.ContentLength > maxCachedItemSize {
    // Use chunk caching
    writer := handler.NewChunkCacher(rw, cacher, key, ttl)
    // ...
} else {
    // Use full response caching
    handler.NewCachedResponse().Save(cacher, key, resp, ttl)
}
```

### Concurrency

All handler types are safe for concurrent use:
- No shared mutable state
- Thread-safe cacher interface
- Context-aware cancellation

### Timeouts

Configure appropriate timeouts for your use case:

```go
proxy := handler.NewProxy(
    time.Second,         // flushInterval - streaming flush rate
    5*time.Second,       // retryDelay - time between retries
    3,                   // maxRetryCount - max attempts
    modFn, errFn, tr,
    false,               // debug - disable in production
)
```

## Error Handling

### Custom Error Handler

```go
errorHandler := func(rw http.ResponseWriter, req *http.Request, err error) {
    logger.Error("proxy", "", "Request failed: %v", err)
    
    // Return appropriate error response
    if isTimeout(err) {
        rw.WriteHeader(http.StatusGatewayTimeout)
    } else {
        rw.WriteHeader(http.StatusBadGateway)
    }
    
    rw.Write([]byte("Proxy error"))
}

proxy := handler.NewProxy(..., errorHandler, ...)
```

### Response Modification

```go
modifyResponse := func(resp *http.Response) error {
    // Add custom headers
    resp.Header.Set("X-Proxy", "Soapbucket")
    
    // Filter sensitive headers
    resp.Header.Del("X-Internal-Token")
    
    // Modify status codes
    if resp.StatusCode == 404 {
        resp.StatusCode = 200
        // Serve custom 404 page
    }
    
    return nil
}

proxy := handler.NewProxy(..., modifyResponse, ...)
```

## Logging

### Debug Logging

Enable debug logging to track request processing:

```go
proxy := handler.NewProxy(..., true) // debug = true

// Logs:
// - Request start with method, URL, headers
// - Processing time for each request
// - Retry attempts
// - Error details
```

### Performance Logging

```go
// Log successful requests with timing
proxy.LogRequestSuccess(req, statusCode, duration)

// Log errors with retry count
proxy.LogRequestError(req, err, retryCount)

// Log retry attempts
proxy.LogRetryAttempt(req, retryNum, delay)
```

### Log Levels

Change log levels dynamically:

```go
// Change proxy log level at runtime
proxy.SetLogLevel("debug")  // debug, info, warn, error
```

## Testing

### Unit Tests

```bash
# Run handler tests
go test -v ./internal/engine/handler/

# With coverage
go test -cover ./internal/engine/handler/

# With race detector
go test -race ./internal/engine/handler/
```

### Benchmarks

```bash
# Run all benchmarks
go test -bench=. -benchmem ./internal/engine/handler/

# Specific benchmarks
go test -bench=BenchmarkProxy -benchmem ./internal/engine/handler/
go test -bench=BenchmarkCachedResponse -benchmem ./internal/engine/handler/
```

### Example Test

```go
func TestProxyHandler(t *testing.T) {
    // Create test backend
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("test response"))
    }))
    defer backend.Close()
    
    // Create proxy
    transport := &http.Transport{}
    proxy := handler.NewProxy(0, 0, 0, nil, nil, transport, false)
    
    // Test request
    req := httptest.NewRequest("GET", backend.URL, nil)
    rw := httptest.NewRecorder()
    
    proxy.ServeHTTP(rw, req)
    
    assert.Equal(t, http.StatusOK, rw.Code)
    assert.Equal(t, "test response", rw.Body.String())
}
```

## Common Patterns

### Pattern 1: Cache-Aside

```go
func handleRequest(rw http.ResponseWriter, req *http.Request, cacher cacher.Cacher) {
    key := handler.GenerateCacheKey(req)
    
    // Try cache first
    if cached, err := handler.GetCachedResponse(cacher, key); err == nil {
        cached.WriteTo(rw)
        return
    }
    
    // Fetch from origin
    resp := fetchFromOrigin(req)
    
    // Store in cache for next time
    handler.NewCachedResponse().Save(cacher, key, resp, 5*time.Minute)
    
    // Return response
    resp.Write(rw)
}
```

### Pattern 2: Write-Through Cache

```go
func handleRequest(rw http.ResponseWriter, req *http.Request, cacher cacher.Cacher) {
    key := handler.GenerateCacheKey(req)
    
    // Fetch from origin
    resp := fetchFromOrigin(req)
    
    // Write to cache and response simultaneously
    chunkWriter := handler.NewChunkCacher(rw, cacher, key, ttl)
    io.Copy(chunkWriter, resp.Body)
    chunkWriter.Finalize()
}
```

### Pattern 3: Conditional Caching

```go
func handleRequest(rw http.ResponseWriter, req *http.Request, cacher cacher.Cacher) {
    // Only cache GET requests
    if req.Method != "GET" {
        fetchFromOrigin(req).Write(rw)
        return
    }
    
    // Only cache successful responses
    resp := fetchFromOrigin(req)
    if resp.StatusCode == 200 {
        key := handler.GenerateCacheKey(req)
        handler.NewCachedResponse().Save(cacher, key, resp, ttl)
    }
    
    resp.Write(rw)
}
```

## Integration with Other Components

### With Middleware

```go
// Combine handler with middleware chain
handler := middleware.RequestID(
    middleware.UserAgent(
        proxy,
    ),
)
```

### With Origin Manager

```go
// Use origin manager to route requests
origin, err := originManager.Match(req)
if err != nil {
    http.Error(rw, "No matching origin", http.StatusBadGateway)
    return
}

// Use origin's configured proxy
origin.ReverseProxy.ServeHTTP(rw, req)
```

### With Transform Pipeline

```go
modifyResponse := func(resp *http.Response) error {
    // Apply transformations
    transformed, err := transform.ApplyAll(resp)
    if err != nil {
        return err
    }
    
    // Update response
    resp.Body = ioutil.NopCloser(bytes.NewReader(transformed))
    resp.ContentLength = int64(len(transformed))
    
    return nil
}

proxy := handler.NewProxy(..., modifyResponse, ...)
```

## Best Practices

1. **Always set timeouts:** Use context deadlines to prevent hung requests
2. **Enable caching for GET requests:** Reduces origin load and improves latency
3. **Use chunk caching for large responses:** Prevents memory exhaustion
4. **Implement custom error handlers:** Provide meaningful error messages
5. **Log request IDs:** Enables request tracing across components
6. **Monitor cache hit rates:** Tune TTLs based on cache performance
7. **Profile in production:** Use pprof to identify bottlenecks
8. **Test with realistic payloads:** Benchmark with production-like data sizes

## Troubleshooting

### High Memory Usage

**Problem:** Handler consuming too much memory

**Solutions:**
- Use chunk caching instead of full response caching
- Reduce cache TTLs
- Implement cache eviction policies
- Profile with `pprof` to find memory leaks

### Slow Response Times

**Problem:** Requests taking too long

**Solutions:**
- Check if debug logging is enabled in production
- Verify cache hit rates
- Increase flush interval for streaming responses
- Review timeout configurations
- Check origin response times

### Cache Misses

**Problem:** Low cache hit rate

**Solutions:**
- Verify cache key generation includes necessary fields
- Check TTLs aren't too short
- Ensure cacher backend is working correctly
- Review caching conditions
- Monitor cache size limits

## Additional Resources

- [Project README](../../../README.md) - Project overview
- [Transport Package](../transport/README.md) - HTTP transport middleware
- [Middleware Package](../middleware/README.md) - Request/response middleware
- [Cache Store Package](../../cache/store/README.md) - Caching backends

## Contributing

When adding new handler types:
1. Implement `http.Handler` interface
2. Add comprehensive tests (unit + integration)
3. Add benchmarks for performance-critical paths
4. Document with examples
5. Update this README

## License

Copyright © 2025 Soapbucket

