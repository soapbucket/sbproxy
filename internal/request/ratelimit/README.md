# Rate Limiting Package

**Package**: `lib/ratelimit`  
**Purpose**: Distributed rate limiting with sliding window algorithm

---

## Overview

This package provides a distributed rate limiter that works across multiple proxy instances using a shared cache backend (Redis, Pebble, etc.). It implements the sliding window counter algorithm for accurate rate limiting without the boundary issues of fixed window approaches.

---

## Features

✅ **Distributed**: Works across multiple server instances  
✅ **Sliding Window**: Accurate rate limiting without boundary problems  
✅ **Atomic Operations**: Uses cache INCREMENT operations for thread safety  
✅ **Multiple Time Windows**: Per-minute, per-hour, per-day limits  
✅ **Fail Open**: Allows requests if cache is unavailable (availability over strict limiting)  
✅ **Statistics**: Tracks allowed/denied/error counts  
✅ **Batch Operations**: `AllowN` for weighted rate limiting  
✅ **Reset Support**: Admin ability to reset limits for specific keys  

---

## Usage

### Basic Usage

```go
import (
    "github.com/soapbucket/proxy/lib/cacher"
    "github.com/soapbucket/proxy/lib/ratelimit"
)

// Create cache backend (Redis recommended for production)
cache, err := cacher.NewCacher(cacher.Settings{
    Driver: "redis",
    Params: map[string]string{
        "addr": "localhost:6379",
    },
})

// Create rate limiter
limiter := ratelimit.NewDistributedRateLimiter(cache, "api")

// Check if request is allowed
ctx := context.Background()
key := "user:123"              // Unique identifier (user ID, IP, API key, etc.)
limit := 100                    // 100 requests
window := time.Minute           // per minute

allowed, remaining, resetTime, err := limiter.Allow(ctx, key, limit, window)
if err != nil {
    // Handle error (request is allowed on error - fail open)
    log.Printf("rate limit check error: %v", err)
}

if !allowed {
    // Rate limit exceeded
    http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
    w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
    w.Header().Set("X-RateLimit-Remaining", "0")
    w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
    return
}

// Request allowed, add headers
w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

// Process request...
```

### Batch Operations

For weighted rate limiting (e.g., charging N credits per request):

```go
// Allow N requests at once
n := 5  // Request costs 5 credits
allowed, remaining, resetTime, err := limiter.AllowN(ctx, key, n, limit, window)
```

### Reset Rate Limit

Admin operation to reset a user's rate limit:

```go
err := limiter.Reset(ctx, "user:123")
if err != nil {
    log.Printf("failed to reset rate limit: %v", err)
}
```

### Get Statistics

```go
stats := limiter.GetStats()
fmt.Printf("Allowed: %d, Denied: %d, Errors: %d\n", 
    stats.AllowedCount,
    stats.DeniedCount, 
    stats.ErrorCount)

fmt.Printf("Allow Rate: %.2f%%\n", stats.AllowRate())
fmt.Printf("Error Rate: %.2f%%\n", stats.ErrorRate())
```

---

## Algorithm: Sliding Window Counter

The sliding window counter algorithm divides time into small buckets (1 second each) and counts requests in each bucket. When checking if a request is allowed, it counts requests across all buckets within the window.

### Example

With a 60-second window and limit of 100:
- Current time: 12:00:45
- Window: 12:00:00 - 12:00:59 (last 60 seconds)
- Buckets checked: seconds 46, 47, 48, ..., 45
- Count: Sum of requests in all 60 buckets
- Decision: Allow if count < 100

### Advantages

1. **No Boundary Issues**: Unlike fixed windows, sliding windows don't have sudden resets
2. **Fair Distribution**: Requests are counted across the exact time window
3. **Accurate Counting**: Uses atomic increment operations
4. **Memory Efficient**: Old buckets automatically expire

---

## Architecture

### Components

```
┌─────────────────────────────────────────┐
│   Distributed Rate Limiter              │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Sliding Window Algorithm          │ │
│  │  - Bucket per second               │ │
│  │  - Atomic increments               │ │
│  │  - Automatic expiration            │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Cacher Interface                  │ │
│  │  - Increment()                     │ │
│  │  - IncrementWithExpires()          │ │
│  │  - DeleteByPattern()               │ │
│  └────────────────────────────────────┘ │
│                 │                        │
└─────────────────┼────────────────────────┘
                  │
                  ▼
    ┌──────────────────────────┐
    │   Cache Backend          │
    │   - Redis (recommended)  │
    │   - Pebble               │
    │   - Memory (testing)     │
    └──────────────────────────┘
```

### Multi-Instance Synchronization

When running multiple proxy instances:

1. **Shared Cache**: All instances use the same Redis/Pebble
2. **Atomic Operations**: INCREMENT operations are atomic across all instances
3. **Consistency**: All instances see the same rate limit state
4. **No Coordination Needed**: Cache backend handles synchronization

```
┌──────────────┐         ┌──────────────┐
│  Instance 1  │         │  Instance 2  │
│              │         │              │
│  RateLimiter │         │  RateLimiter │
└──────┬───────┘         └───────┬──────┘
       │                         │
       └────────┬────────────────┘
                │
                ▼
        ┌───────────────┐
        │  Redis Cache  │
        │  (Shared)     │
        └───────────────┘
```

---

## Key Design Decisions

### 1. Fail Open vs Fail Closed

**Decision**: Fail Open (allow requests on cache errors)

**Rationale**:
- Prioritizes availability over strict rate limiting
- Prevents complete service outage if cache fails
- Acceptable for most use cases (DDoS protection has separate layer)
- Can be changed to fail closed if needed

### 2. Time Bucket Granularity

**Decision**: 1-second buckets

**Rationale**:
- Good balance between accuracy and performance
- Prevents excessive key creation
- Works well for common rate limit windows (minute, hour, day)
- Can be adjusted if needed

### 3. Atomic vs Distributed Lock

**Decision**: Atomic INCREMENT operations

**Rationale**:
- Simpler implementation
- Better performance (no lock contention)
- Natural fit for cache backends
- Works across instances without coordination

---

## Performance

### Benchmarks

```
BenchmarkDistributedRateLimiter_Allow          ~100µs per operation
BenchmarkDistributedRateLimiter_AllowParallel  ~120µs per operation
```

### Scalability

- **Horizontal**: Add more proxy instances freely
- **Vertical**: Each instance can handle 10,000+ checks/sec
- **Cache**: Redis can handle 100,000+ ops/sec

### Memory Usage

- **Per Key**: ~10-100 bytes (depends on window size)
- **TTL**: Keys automatically expire after window + 1 second
- **Cleanup**: Automatic, no manual intervention needed

---

## Testing

### Run Tests

```bash
go test ./lib/ratelimit/... -v
```

### With Race Detector

```bash
go test ./lib/ratelimit/... -race
```

### Benchmarks

```bash
go test ./lib/ratelimit/... -bench=. -benchmem
```

### Test Coverage

```bash
go test ./lib/ratelimit/... -cover
```

Current coverage: **~95%**

---

## Integration with Existing Rate Limiting

The distributed rate limiter is designed to be a drop-in replacement for the existing in-memory rate limiting in `internal/config/policy_rate_limiting.go`.

### Migration Steps

1. Create distributed rate limiter in policy config:
```go
func (p *RateLimitingPolicyConfig) Init(config *Config) error {
    // Get L2 cache from manager
    cache := manager.GetCache(manager.L2Cache)
    
    // Create distributed rate limiter
    p.rateLimiter = ratelimit.NewDistributedRateLimiter(cache, "policy")
    
    return nil
}
```

2. Use in Apply method:
```go
func (p *RateLimitingPolicyConfig) Apply(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getClientIPFromRequest(r)
        limits := p.getLimitsForIP(clientIP)
        
        // Check minute limit using distributed rate limiter
        if limits.RequestsPerMinute > 0 {
            allowed, remaining, resetTime, _ := p.rateLimiter.Allow(
                r.Context(),
                fmt.Sprintf("%s:minute", clientIP),
                limits.RequestsPerMinute,
                time.Minute,
            )
            
            if !allowed {
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }
        }
        
        next.ServeHTTP(w, r)
    })
}
```

---

## Production Deployment

### Recommendations

1. **Use Redis**: Recommended for production (atomic operations, persistence, clustering)
2. **Connection Pool**: Configure Redis connection pool appropriately
3. **Monitoring**: Track rate limiter statistics and cache performance
4. **Alerting**: Alert on high error rates or cache failures
5. **Backup**: Consider fail-safe behavior if cache is down

### Configuration

```go
// Production Redis configuration
cache, err := cacher.NewCacher(cacher.Settings{
    Driver: "redis",
    Params: map[string]string{
        "addr":         "redis-cluster:6379",
        "password":     os.Getenv("REDIS_PASSWORD"),
        "db":           "0",
        "pool_size":    "100",
        "max_retries":  "3",
        "timeout":      "1s",
    },
    EnableMetrics: true,
    EnableTracing: true,
})
```

---

## Future Enhancements

### Planned

- [ ] Token bucket algorithm (alternative to sliding window)
- [ ] Distributed rate limit quotas
- [ ] Rate limit bypass for whitelisted IPs/users
- [ ] Dynamic rate limit adjustment based on load
- [ ] Rate limit warming/ramping
- [ ] Prometheus metrics export

### Under Consideration

- [ ] Lua scripts for atomic multi-window checks
- [ ] Adaptive windows based on traffic patterns
- [ ] Cost-based rate limiting (different costs per endpoint)
- [ ] Hierarchical rate limiting (user + organization limits)

---

## API Reference

### Types

#### `DistributedRateLimiter`
Main rate limiter implementation.

#### `RateLimiterStats`
Statistics about rate limiting operations.

### Functions

#### `NewDistributedRateLimiter(cache cacher.Cacher, prefix string) *DistributedRateLimiter`
Creates a new distributed rate limiter.

#### `Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, time.Time, error)`
Checks if a single request is allowed.

Returns:
- `allowed`: Whether the request is allowed
- `remaining`: Number of requests remaining in window
- `resetTime`: When the rate limit resets
- `error`: Any error that occurred

#### `AllowN(ctx context.Context, key string, n int, limit int, window time.Duration) (bool, int, time.Time, error)`
Checks if N requests are allowed (batch/weighted).

#### `Reset(ctx context.Context, key string) error`
Resets the rate limit for a specific key.

#### `GetStats() RateLimiterStats`
Returns current statistics.

---

## License

Same as parent project.

---

**End of Rate Limiting Documentation**

