// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"net/http"

	"golang.org/x/time/rate"
)

// RateLimiter represents a rate limiter.
type RateLimiter struct {
	tr    http.RoundTripper
	limit *rate.Limiter
}

// RoundTrip performs the round trip operation on the RateLimiter.
func (l *RateLimiter) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.limit.Allow() {
		return l.tr.RoundTrip(req)
	}

	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     make(http.Header),
		Request:    req,
		Body:       http.NoBody,
	}
	return resp, nil
}

// NewRateLimiter creates and initializes a new RateLimiter.
func NewRateLimiter(tr http.RoundTripper, r int, b int) http.RoundTripper {
	limiter := &RateLimiter{
		tr:    tr,
		limit: rate.NewLimiter(rate.Limit(r), b),
	}
	return limiter
}
