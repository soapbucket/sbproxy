// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/settings"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// retryLogLimiter limits retry log spam by tracking per-origin retry counts.
// Logs the first retry per origin, then every 10th retry after that.
var retryLogLimiter = &retryLogger{counts: make(map[string]*atomic.Int64)}

type retryLogger struct {
	mu     sync.RWMutex
	counts map[string]*atomic.Int64
}

// shouldLog returns true if this retry attempt for the given origin should be logged.
// Logs attempt 1, 10, 20, 30, etc. (i.e., count%10 == 1 or count == 1).
func (rl *retryLogger) shouldLog(origin string) bool {
	rl.mu.RLock()
	counter, ok := rl.counts[origin]
	rl.mu.RUnlock()

	if !ok {
		rl.mu.Lock()
		counter, ok = rl.counts[origin]
		if !ok {
			counter = &atomic.Int64{}
			rl.counts[origin] = counter
		}
		rl.mu.Unlock()
	}

	count := counter.Add(1)
	return count == 1 || count%10 == 0
}

// RetryTransport implements automatic retry with exponential backoff
type RetryTransport struct {
	// Base transport to wrap
	Base http.RoundTripper

	// Maximum number of retry attempts (not including initial request)
	MaxRetries int

	// Initial delay before first retry
	InitialDelay time.Duration

	// Maximum delay between retries
	MaxDelay time.Duration

	// Multiplier for exponential backoff (default: 2.0)
	BackoffMultiplier float64

	// Jitter adds randomness to backoff (0.0 = no jitter, 1.0 = full jitter)
	Jitter float64

	// RetryableStatusCodes defines which status codes should trigger retry
	// If nil, uses default: 502, 503, 504, 429
	RetryableStatusCodes []int

	// RetryableFunc allows custom retry logic
	// If provided, this takes precedence over RetryableStatusCodes
	RetryableFunc func(*http.Response, error) bool
}

// NewRetryTransport creates a retry transport with sensible defaults
func NewRetryTransport(base http.RoundTripper, maxRetries int) *RetryTransport {
	if base == nil {
		base = http.DefaultTransport
	}

	return &RetryTransport{
		Base:                 base,
		MaxRetries:           maxRetries,
		InitialDelay:         100 * time.Millisecond,
		MaxDelay:             30 * time.Second,
		BackoffMultiplier:    2.0,
		Jitter:               0.1,
		RetryableStatusCodes: []int{502, 503, 504, 429}, // Bad Gateway, Service Unavailable, Gateway Timeout, Too Many Requests
	}
}

// RoundTrip implements http.RoundTripper with retry logic
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Ensure the request body is retryable if present
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		if err := MakeRequestRetryable(req); err != nil {
			// If we can't make it retryable, proceed without retry capability
			slog.Debug("retry: could not buffer request body, retries will be body-less",
				"error", err)
		}
	}

	// Clone the request for potential retries
	originalReq := req

	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt <= t.MaxRetries; attempt++ {
		// Clone request for this attempt (body needs to be preserved)
		attemptReq, err := cloneRequest(originalReq)
		if err != nil {
			return nil, fmt.Errorf("failed to clone request: %w", err)
		}

		// Execute request
		slog.Debug("executing request attempt",
			"attempt", attempt+1,
			"max_attempts", t.MaxRetries+1,
			"url", attemptReq.URL.String(),
			"method", attemptReq.Method)

		resp, err := t.Base.RoundTrip(attemptReq)

		// Check if we should retry
		shouldRetry := t.shouldRetry(resp, err, attempt)

		if !shouldRetry {
			// Success or non-retryable error
			if err != nil {
				slog.Debug("request failed (not retrying)",
					"error", err,
					"attempt", attempt+1)
			} else {
				slog.Debug("request succeeded",
					"status", resp.StatusCode,
					"attempt", attempt+1)
				// Record successful retry if this was a retry attempt
				if attempt > 0 {
					origin := t.getOrigin(attemptReq)
					retryReason := t.getRetryReason(resp, err)
					metric.RetryAttempt(origin, retryReason, true)
				}
			}
			return resp, err
		}

		// Store error/response for potential final return
		lastErr = err
		if lastResp != nil && lastResp.Body != nil {
			lastResp.Body.Close()
		}
		lastResp = resp

		// Record retry attempt
		origin := t.getOrigin(attemptReq)
		retryReason := t.getRetryReason(resp, err)
		metric.RetryAttempt(origin, retryReason, false) // false because we're retrying

		// Don't delay after last attempt
		if attempt == t.MaxRetries {
			break
		}

		// Calculate backoff delay
		delay := t.calculateBackoff(attempt)

		// Rate-limit retry logs: log the first retry per origin, then every 10th
		if retryLogLimiter.shouldLog(origin) {
			slog.Info("retrying request after delay",
				"attempt", attempt+1,
				"delay", delay,
				"url", attemptReq.URL.String(),
				"status", getStatusCode(resp),
				"error", err)
		}

		// Wait with context cancellation support using pre-allocated timer
		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			// Continue to retry
		case <-req.Context().Done():
			timer.Stop()
			// Context cancelled during backoff
			if lastResp != nil && lastResp.Body != nil {
				lastResp.Body.Close()
			}
			origin := t.getOrigin(req)
			cancelReason := "timeout"
			if req.Context().Err() == context.Canceled {
				cancelReason = "client_cancelled"
			}
			metric.RequestCancellation(origin, cancelReason)
			return nil, req.Context().Err()
		}
	}

	// All retries exhausted
	slog.Warn("all retry attempts exhausted",
		"max_retries", t.MaxRetries,
		"url", originalReq.URL.String(),
		"last_error", lastErr,
		"last_status", getStatusCode(lastResp))

	if lastErr != nil {
		// Close any dangling response body from a previous attempt before returning error.
		if lastResp != nil && lastResp.Body != nil {
			lastResp.Body.Close()
		}
		return nil, fmt.Errorf("request failed after %d attempts: %w", t.MaxRetries+1, lastErr)
	}

	return lastResp, nil
}

// getOrigin extracts origin from request (prefers config_id from RequestData)
func (t *RetryTransport) getOrigin(req *http.Request) string {
	if req == nil {
		return "unknown"
	}
	// Try to get config_id from RequestData first
	requestData := reqctx.GetRequestData(req.Context())
	if requestData != nil && requestData.Config != nil {
		if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
			return id
		}
	}
	// Fallback to hostname
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host == "" {
		return "unknown"
	}
	// Extract just the hostname without port
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

// getRetryReason determines the reason for retry
func (t *RetryTransport) getRetryReason(resp *http.Response, err error) string {
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
			return "timeout"
		}
		if strings.Contains(errStr, "connection") || strings.Contains(errStr, "refused") {
			return "connection_error"
		}
		return "network_error"
	}
	if resp != nil {
		switch resp.StatusCode {
		case 502:
			return "bad_gateway"
		case 503:
			return "service_unavailable"
		case 504:
			return "gateway_timeout"
		case 429:
			return "rate_limit"
		default:
			return "status_code"
		}
	}
	return "unknown"
}

// shouldRetry determines if a request should be retried
func (t *RetryTransport) shouldRetry(resp *http.Response, err error, attempt int) bool {
	// No more retries available
	if attempt >= t.MaxRetries {
		return false
	}

	// Use custom retry function if provided
	if t.RetryableFunc != nil {
		return t.RetryableFunc(resp, err)
	}

	// Retry on network errors
	if err != nil {
		return true
	}

	// No response means network error (already handled above)
	if resp == nil {
		return true
	}

	// Check if status code is retryable
	for _, code := range t.RetryableStatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}

	return false
}

// calculateBackoff calculates the delay before the next retry
func (t *RetryTransport) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff: initialDelay * (multiplier ^ attempt)
	multiplier := t.BackoffMultiplier
	if multiplier <= 0 {
		multiplier = 2.0
	}

	delay := float64(t.InitialDelay) * math.Pow(multiplier, float64(attempt))

	// Add jitter
	if t.Jitter > 0 {
		jitterAmount := delay * t.Jitter
		// Random jitter between [-jitterAmount, +jitterAmount]
		jitter := (float64(time.Now().UnixNano()%1000)/1000.0*2.0 - 1.0) * jitterAmount
		delay += jitter
	}

	// Cap at max delay
	if delay > float64(t.MaxDelay) {
		delay = float64(t.MaxDelay)
	}

	return time.Duration(delay)
}

// cloneRequest creates a copy of the request for retry
func cloneRequest(req *http.Request) (*http.Request, error) {
	// Clone the request
	clone := req.Clone(req.Context())

	// If there's a body, we need to handle it carefully
	if req.Body != nil && req.Body != http.NoBody {
		// For retry to work, the body must be reusable
		// This is a limitation - bodies should be backed by io.Seeker or be buffered
		// For now, we'll just reuse the same body (works for GetBody or nil body)
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("failed to get request body: %w", err)
			}
			clone.Body = body
		}
	}

	return clone, nil
}

// getStatusCode safely gets status code from response
func getStatusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// MakeRequestRetryable wraps a request to make its body retryable
// This should be called before using RetryTransport if the request has a body
func MakeRequestRetryable(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	// Read the entire body into memory with size limit
	limitedBody := io.LimitReader(req.Body, settings.Global.MaxRetryBodyBytes)
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	req.Body.Close()

	// Check if we hit the size limit
	if int64(len(body)) >= settings.Global.MaxRetryBodyBytes {
		return fmt.Errorf("request body exceeds maximum size of %d bytes", settings.Global.MaxRetryBodyBytes)
	}

	// Set up GetBody function for retries
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	// Update ContentLength if it was unknown
	if req.ContentLength == -1 {
		req.ContentLength = int64(len(body))
	}

	return nil
}
