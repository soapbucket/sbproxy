// concurrency_limiter.go implements a distributed semaphore for AI requests.
//
// The semaphore uses atomic increment/decrement operations on the distributed
// cache to track in-flight requests per provider. A TTL on counter keys
// provides crash recovery: if a process dies without calling Release, the
// counter expires and self-corrects within concurrencyKeyTTL (5 minutes).
// Active counters refresh their TTL on every Acquire, so they never expire
// prematurely during normal operation.
//
// The limiter fails open on cache errors. This is intentional: briefly
// exceeding concurrency during a cache outage is preferable to rejecting
// all requests.
package limits

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	concurrencyNamespace = "ai_concurrency"
	// concurrencyKeyTTL is the TTL applied to in-flight counter keys.
	// This acts as a safety net: if a process crashes without calling Release,
	// the counter will expire and self-correct. The TTL is refreshed on every
	// Acquire, so active counters never expire prematurely.
	concurrencyKeyTTL = 5 * time.Minute
)

// ConcurrencyLimiter enforces max parallel requests per provider using distributed counters.
// It uses cacher.Cacher.IncrementWithExpires so that counters auto-expire if a process
// crashes without releasing slots.
type ConcurrencyLimiter struct {
	cache  cacher.Cacher
	prefix string
	limits map[string]int // provider name -> max parallel
}

// NewConcurrencyLimiter creates a limiter backed by the given cache.
func NewConcurrencyLimiter(cache cacher.Cacher) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		cache:  cache,
		prefix: "ai:inflight",
		limits: make(map[string]int),
	}
}

// Configure sets the max parallel requests for a provider.
func (l *ConcurrencyLimiter) Configure(provider string, maxParallel int) {
	l.limits[provider] = maxParallel
}

// Acquire tries to acquire a slot for the provider. Returns true if allowed.
// The caller must call Release when done (use defer).
func (l *ConcurrencyLimiter) Acquire(ctx context.Context, provider string) (bool, error) {
	limit, ok := l.limits[provider]
	if !ok || limit <= 0 {
		return true, nil // No limit configured, always allow
	}

	key := fmt.Sprintf("%s:%s", l.prefix, provider)
	current, err := l.cache.IncrementWithExpires(ctx, concurrencyNamespace, key, 1, concurrencyKeyTTL)
	if err != nil {
		slog.Debug("concurrency limiter cache error, allowing request", "provider", provider, "error", err)
		return true, nil // Fail open on cache error
	}

	if current > int64(limit) {
		// Over limit - decrement back and reject
		_, _ = l.cache.IncrementWithExpires(ctx, concurrencyNamespace, key, -1, concurrencyKeyTTL)
		return false, nil
	}
	return true, nil
}

// Release gives back a slot for the provider.
func (l *ConcurrencyLimiter) Release(ctx context.Context, provider string) {
	if _, ok := l.limits[provider]; !ok {
		return
	}
	key := fmt.Sprintf("%s:%s", l.prefix, provider)
	_, _ = l.cache.IncrementWithExpires(ctx, concurrencyNamespace, key, -1, concurrencyKeyTTL)
}
