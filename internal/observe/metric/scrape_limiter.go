package metric

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// --- Default Configuration ---

const (
	// DefaultMinScrapeInterval is the minimum time between Prometheus scrape requests.
	DefaultMinScrapeInterval = 5 * time.Second
)

// --- ScrapeLimiter ---

// ScrapeLimiter rate-limits Prometheus scrape requests to prevent scrape storms.
// If scraped more frequently than MinInterval, it returns HTTP 429 with a Retry-After header.
type ScrapeLimiter struct {
	mu          sync.Mutex
	minInterval time.Duration
	lastScrape  time.Time
	maxBodySize int64 // max response size in bytes (0 = unlimited)
}

// NewScrapeLimiter creates a scrape limiter with the given minimum interval and max body size.
// A maxBodySize of 0 means unlimited.
func NewScrapeLimiter(minInterval time.Duration, maxBodySize int64) *ScrapeLimiter {
	if minInterval <= 0 {
		minInterval = DefaultMinScrapeInterval
	}
	return &ScrapeLimiter{
		minInterval: minInterval,
		maxBodySize: maxBodySize,
	}
}

// Wrap wraps an http.Handler with rate limiting for the /metrics endpoint.
// Requests arriving before minInterval has elapsed since the last scrape receive
// a 429 Too Many Requests response with a Retry-After header.
func (sl *ScrapeLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(sl.lastScrape)

		if !sl.lastScrape.IsZero() && elapsed < sl.minInterval {
			retryAfter := sl.minInterval - elapsed
			sl.mu.Unlock()

			retrySeconds := int(retryAfter.Seconds()) + 1
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySeconds))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		sl.lastScrape = now
		maxBody := sl.maxBodySize
		sl.mu.Unlock()

		if maxBody > 0 {
			lrw := &limitedResponseWriter{
				ResponseWriter: w,
				maxBytes:       maxBody,
			}
			next.ServeHTTP(lrw, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- limitedResponseWriter ---

// limitedResponseWriter wraps http.ResponseWriter to enforce a max response body size.
// Once the limit is reached, subsequent writes are silently discarded.
type limitedResponseWriter struct {
	http.ResponseWriter
	maxBytes    int64
	written     int64
	headersSent bool
}

func (lrw *limitedResponseWriter) Write(p []byte) (int, error) {
	if !lrw.headersSent {
		lrw.headersSent = true
	}

	remaining := lrw.maxBytes - lrw.written
	if remaining <= 0 {
		// Silently discard; the client already has partial data.
		return len(p), nil
	}

	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	n, err := lrw.ResponseWriter.Write(p)
	lrw.written += int64(n)
	return n, err
}
