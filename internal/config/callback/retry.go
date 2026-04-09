// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// RetryConfig configures retry behavior for callbacks
type RetryConfig struct {
	// Enabled controls whether retries are enabled (default: false)
	Enabled bool `json:"enabled,omitempty"`

	// MaxAttempts is the maximum number of retry attempts (default: 3)
	MaxAttempts int `json:"max_attempts,omitempty"`

	// InitialDelay is the initial delay before first retry (default: 100ms)
	InitialDelay Duration `json:"initial_delay,omitempty"`

	// MaxDelay is the maximum delay between retries (default: 10s)
	MaxDelay Duration `json:"max_delay,omitempty"`

	// Multiplier is the exponential backoff multiplier (default: 2.0)
	Multiplier float64 `json:"multiplier,omitempty"`

	// Jitter is the random jitter factor (0.0-1.0) to prevent thundering herd (default: 0.1)
	Jitter float64 `json:"jitter,omitempty"`

	// RetryOn specifies which HTTP status codes to retry on (default: [502, 503, 504])
	RetryOn []int `json:"retry_on,omitempty"`

	// RetryOnNetworkErrors controls whether to retry on network errors (default: true)
	RetryOnNetworkErrors bool `json:"retry_on_network_errors,omitempty"`

	// RetryOnTimeout controls whether to retry on timeout errors (default: true)
	RetryOnTimeout bool `json:"retry_on_timeout,omitempty"`
}

// Duration is a JSON-friendly time.Duration
type Duration struct {
	time.Duration
}

// UnmarshalJSON implements json.Unmarshaler for Duration
func (d *Duration) UnmarshalJSON(b []byte) error {
	// Remove quotes
	s := strings.Trim(string(b), "\"")
	if s == "" || s == "null" {
		return nil
	}

	// Try parsing as duration string
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = duration
	return nil
}

// MarshalJSON implements json.Marshaler for Duration
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Duration.String() + `"`), nil
}

// DefaultRetryConfig returns a retry config with sensible defaults
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		Enabled:              false,
		MaxAttempts:          3,
		InitialDelay:         Duration{100 * time.Millisecond},
		MaxDelay:             Duration{10 * time.Second},
		Multiplier:           2.0,
		Jitter:               0.1,
		RetryOn:              []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout},
		RetryOnNetworkErrors: true,
		RetryOnTimeout:       true,
	}
}

// Normalize fills in default values for unset fields
func (rc *RetryConfig) Normalize() {
	if rc.MaxAttempts <= 0 {
		rc.MaxAttempts = 3
	}
	if rc.InitialDelay.Duration <= 0 {
		rc.InitialDelay = Duration{100 * time.Millisecond}
	}
	if rc.MaxDelay.Duration <= 0 {
		rc.MaxDelay = Duration{10 * time.Second}
	}
	if rc.Multiplier <= 0 {
		rc.Multiplier = 2.0
	}
	// Use default jitter if invalid (negative or greater than 1)
	// Note: 0 is a valid value meaning no jitter
	if rc.Jitter < 0 || rc.Jitter > 1 {
		rc.Jitter = 0.1
	}
	if rc.RetryOn == nil {
		rc.RetryOn = []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}
	}
}

// RetryError wraps an error with retry context
type RetryError struct {
	Err          error
	Attempt      int
	MaxAttempts  int
	LastDelay    time.Duration
	TotalElapsed time.Duration
}

// Error performs the error operation on the RetryError.
func (e *RetryError) Error() string {
	return e.Err.Error()
}

// Unwrap performs the unwrap operation on the RetryError.
func (e *RetryError) Unwrap() error {
	return e.Err
}

// HTTPStatusError represents an HTTP status code error
type HTTPStatusError struct {
	StatusCode int
	Message    string
}

// Error performs the error operation on the HTTPStatusError.
func (e *HTTPStatusError) Error() string {
	return e.Message
}

// IsRetryableError determines if an error is retryable based on config
func IsRetryableError(err error, config *RetryConfig) bool {
	if err == nil {
		return false
	}

	// Check for context cancellation (not retryable)
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Check for timeout errors
	if errors.Is(err, context.DeadlineExceeded) {
		return config.RetryOnTimeout
	}

	// Check for network errors
	if isNetworkError(err) {
		return config.RetryOnNetworkErrors
	}

	// Check for HTTP status code errors
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return isRetryableStatusCode(httpErr.StatusCode, config.RetryOn)
	}

	// Default: don't retry
	return false
}

// isNetworkError checks if an error is a network-related error
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network operation errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Temporary() || netErr.Timeout()
	}

	// Check for specific syscall errors
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ETIMEDOUT,
			syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNABORTED:
			return true
		}
	}

	// Check for DNS errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.Temporary()
	}

	// Check error string for common patterns
	errStr := err.Error()
	networkPatterns := []string{
		"connection refused",
		"connection reset",
		"no such host",
		"network is unreachable",
		"host is down",
		"connection timed out",
		"connection closed",
		"i/o timeout",
		"EOF",
		"broken pipe",
		"dial tcp",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isRetryableStatusCode checks if a status code should be retried
func isRetryableStatusCode(statusCode int, retryOn []int) bool {
	for _, code := range retryOn {
		if code == statusCode {
			return true
		}
	}
	return false
}

// RetryExecutor executes a function with retry logic
type RetryExecutor struct {
	config *RetryConfig
}

// NewRetryExecutor creates a new retry executor
func NewRetryExecutor(config *RetryConfig) *RetryExecutor {
	if config == nil {
		config = DefaultRetryConfig()
	}
	config.Normalize()
	return &RetryExecutor{config: config}
}

// Execute runs a function with retry logic
func (re *RetryExecutor) Execute(ctx context.Context, fn func() error) error {
	if !re.config.Enabled {
		return fn()
	}

	var lastErr error
	delay := re.config.InitialDelay.Duration
	startTime := time.Now()

	for attempt := 1; attempt <= re.config.MaxAttempts; attempt++ {
		// Execute function
		err := fn()
		if err == nil {
			if attempt > 1 {
				slog.Info("callback succeeded after retry",
					"attempt", attempt,
					"total_attempts", re.config.MaxAttempts,
					"elapsed", time.Since(startTime))
			}
			return nil
		}

		lastErr = err

		// Log the attempt
		slog.Warn("callback attempt failed",
			"attempt", attempt,
			"max_attempts", re.config.MaxAttempts,
			"error", err)

		// Check if error is retryable
		if !IsRetryableError(err, re.config) {
			slog.Debug("error is not retryable, giving up",
				"error", err)
			return &RetryError{
				Err:          lastErr,
				Attempt:      attempt,
				MaxAttempts:  re.config.MaxAttempts,
				TotalElapsed: time.Since(startTime),
			}
		}

		// Don't sleep after last attempt
		if attempt == re.config.MaxAttempts {
			break
		}

		// Calculate delay with jitter
		actualDelay := addJitter(delay, re.config.Jitter)

		slog.Debug("retrying callback",
			"attempt", attempt+1,
			"delay", actualDelay)

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return &RetryError{
				Err:          ctx.Err(),
				Attempt:      attempt,
				MaxAttempts:  re.config.MaxAttempts,
				LastDelay:    actualDelay,
				TotalElapsed: time.Since(startTime),
			}
		case <-time.After(actualDelay):
		}

		// Exponential backoff
		delay = time.Duration(float64(delay) * re.config.Multiplier)
		if delay > re.config.MaxDelay.Duration {
			delay = re.config.MaxDelay.Duration
		}
	}

	return &RetryError{
		Err:          lastErr,
		Attempt:      re.config.MaxAttempts,
		MaxAttempts:  re.config.MaxAttempts,
		TotalElapsed: time.Since(startTime),
	}
}

// addJitter adds random jitter to a duration
func addJitter(duration time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return duration
	}

	// Add random jitter between -jitter% and +jitter%
	jitterAmount := float64(duration) * jitter
	randomJitter := (rand.Float64()*2 - 1) * jitterAmount
	return time.Duration(float64(duration) + randomJitter)
}

// ExponentialBackoff calculates backoff duration for an attempt
func ExponentialBackoff(attempt int, initialDelay, maxDelay time.Duration, multiplier float64) time.Duration {
	delay := float64(initialDelay) * math.Pow(multiplier, float64(attempt))
	if delay > float64(maxDelay) {
		return maxDelay
	}
	return time.Duration(delay)
}
