package callback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Retry Configuration Tests
// =============================================================================

func TestRetryConfig_Normalize(t *testing.T) {
	t.Run("fills defaults for empty config", func(t *testing.T) {
		config := &RetryConfig{}
		config.Normalize()

		if config.MaxAttempts != 3 {
			t.Errorf("expected MaxAttempts=3, got %d", config.MaxAttempts)
		}
		if config.InitialDelay.Duration != 100*time.Millisecond {
			t.Errorf("expected InitialDelay=100ms, got %v", config.InitialDelay.Duration)
		}
		if config.MaxDelay.Duration != 10*time.Second {
			t.Errorf("expected MaxDelay=10s, got %v", config.MaxDelay.Duration)
		}
		if config.Multiplier != 2.0 {
			t.Errorf("expected Multiplier=2.0, got %f", config.Multiplier)
		}
		// Note: 0 is a valid value for Jitter (meaning no jitter), so Normalize doesn't change it
		if config.Jitter != 0 {
			t.Errorf("expected Jitter=0 (unchanged), got %f", config.Jitter)
		}
		if len(config.RetryOn) != 3 {
			t.Errorf("expected 3 retry status codes, got %d", len(config.RetryOn))
		}
	})

	t.Run("preserves custom values", func(t *testing.T) {
		config := &RetryConfig{
			MaxAttempts:  5,
			InitialDelay: Duration{200 * time.Millisecond},
			MaxDelay:     Duration{30 * time.Second},
			Multiplier:   3.0,
			Jitter:       0.2,
			RetryOn:      []int{500, 502},
		}
		config.Normalize()

		if config.MaxAttempts != 5 {
			t.Errorf("expected MaxAttempts=5, got %d", config.MaxAttempts)
		}
		if config.InitialDelay.Duration != 200*time.Millisecond {
			t.Errorf("expected InitialDelay=200ms, got %v", config.InitialDelay.Duration)
		}
		if len(config.RetryOn) != 2 {
			t.Errorf("expected 2 retry status codes, got %d", len(config.RetryOn))
		}
	})

	t.Run("corrects invalid jitter", func(t *testing.T) {
		config := &RetryConfig{Jitter: 2.0} // Invalid: > 1.0
		config.Normalize()

		if config.Jitter != 0.1 {
			t.Errorf("expected Jitter to be corrected to 0.1, got %f", config.Jitter)
		}
	})
}

func TestRetryConfig_JSON(t *testing.T) {
	t.Run("unmarshal from JSON", func(t *testing.T) {
		jsonConfig := `{
			"enabled": true,
			"max_attempts": 5,
			"initial_delay": "200ms",
			"max_delay": "30s",
			"multiplier": 2.5,
			"jitter": 0.15,
			"retry_on": [500, 502, 503],
			"retry_on_network_errors": true,
			"retry_on_timeout": false
		}`

		var config RetryConfig
		if err := json.Unmarshal([]byte(jsonConfig), &config); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if !config.Enabled {
			t.Error("expected Enabled=true")
		}
		if config.MaxAttempts != 5 {
			t.Errorf("expected MaxAttempts=5, got %d", config.MaxAttempts)
		}
		if config.InitialDelay.Duration != 200*time.Millisecond {
			t.Errorf("expected InitialDelay=200ms, got %v", config.InitialDelay.Duration)
		}
		if config.MaxDelay.Duration != 30*time.Second {
			t.Errorf("expected MaxDelay=30s, got %v", config.MaxDelay.Duration)
		}
		if config.Multiplier != 2.5 {
			t.Errorf("expected Multiplier=2.5, got %f", config.Multiplier)
		}
		if config.Jitter != 0.15 {
			t.Errorf("expected Jitter=0.15, got %f", config.Jitter)
		}
		if len(config.RetryOn) != 3 {
			t.Errorf("expected 3 retry codes, got %d", len(config.RetryOn))
		}
		if !config.RetryOnNetworkErrors {
			t.Error("expected RetryOnNetworkErrors=true")
		}
		if config.RetryOnTimeout {
			t.Error("expected RetryOnTimeout=false")
		}
	})

	t.Run("marshal to JSON", func(t *testing.T) {
		config := &RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: Duration{100 * time.Millisecond},
		}

		data, err := json.Marshal(config)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var unmarshaled RetryConfig
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if !unmarshaled.Enabled {
			t.Error("expected Enabled=true after round-trip")
		}
	})
}

// =============================================================================
// Retry Error Classification Tests
// =============================================================================

func TestIsRetryableError(t *testing.T) {
	config := DefaultRetryConfig()
	config.Enabled = true
	config.RetryOnNetworkErrors = true
	config.RetryOnTimeout = true

	t.Run("nil error is not retryable", func(t *testing.T) {
		if IsRetryableError(nil, config) {
			t.Error("nil error should not be retryable")
		}
	})

	t.Run("context.Canceled is not retryable", func(t *testing.T) {
		if IsRetryableError(context.Canceled, config) {
			t.Error("context.Canceled should not be retryable")
		}
	})

	t.Run("context.DeadlineExceeded is retryable when configured", func(t *testing.T) {
		if !IsRetryableError(context.DeadlineExceeded, config) {
			t.Error("context.DeadlineExceeded should be retryable")
		}

		noTimeoutConfig := *config
		noTimeoutConfig.RetryOnTimeout = false
		if IsRetryableError(context.DeadlineExceeded, &noTimeoutConfig) {
			t.Error("context.DeadlineExceeded should not be retryable when disabled")
		}
	})

	t.Run("HTTP 502 is retryable by default", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 502, Message: "Bad Gateway"}
		if !IsRetryableError(err, config) {
			t.Error("502 should be retryable")
		}
	})

	t.Run("HTTP 503 is retryable by default", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 503, Message: "Service Unavailable"}
		if !IsRetryableError(err, config) {
			t.Error("503 should be retryable")
		}
	})

	t.Run("HTTP 504 is retryable by default", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 504, Message: "Gateway Timeout"}
		if !IsRetryableError(err, config) {
			t.Error("504 should be retryable")
		}
	})

	t.Run("HTTP 500 is not retryable by default", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 500, Message: "Internal Server Error"}
		if IsRetryableError(err, config) {
			t.Error("500 should not be retryable by default")
		}
	})

	t.Run("HTTP 500 is retryable when configured", func(t *testing.T) {
		customConfig := *config
		customConfig.RetryOn = []int{500, 502, 503, 504}
		err := &HTTPStatusError{StatusCode: 500, Message: "Internal Server Error"}
		if !IsRetryableError(err, &customConfig) {
			t.Error("500 should be retryable when configured")
		}
	})

	t.Run("HTTP 400 is not retryable", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 400, Message: "Bad Request"}
		if IsRetryableError(err, config) {
			t.Error("400 should not be retryable")
		}
	})

	t.Run("HTTP 401 is not retryable", func(t *testing.T) {
		err := &HTTPStatusError{StatusCode: 401, Message: "Unauthorized"}
		if IsRetryableError(err, config) {
			t.Error("401 should not be retryable")
		}
	})
}

func TestIsNetworkError(t *testing.T) {
	testCases := []struct {
		name      string
		err       error
		isNetwork bool
	}{
		{"nil error", nil, false},
		{"connection refused", fmt.Errorf("connection refused"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"no such host", fmt.Errorf("no such host"), true},
		{"network unreachable", fmt.Errorf("network is unreachable"), true},
		{"EOF", fmt.Errorf("EOF"), true},
		{"broken pipe", fmt.Errorf("broken pipe"), true},
		{"dial tcp", fmt.Errorf("dial tcp: lookup failed"), true},
		{"generic error", fmt.Errorf("generic error"), false},
		{"http client error", fmt.Errorf("http: connection closed"), true},
		{"timeout message", fmt.Errorf("i/o timeout"), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isNetworkError(tc.err)
			if result != tc.isNetwork {
				t.Errorf("expected %v, got %v for error: %v", tc.isNetwork, result, tc.err)
			}
		})
	}
}

// =============================================================================
// Retry Executor Tests
// =============================================================================

func TestRetryExecutor_Execute(t *testing.T) {
	t.Run("no retry when disabled", func(t *testing.T) {
		config := &RetryConfig{Enabled: false}
		executor := NewRetryExecutor(config)

		attempts := 0
		err := executor.Execute(context.Background(), func() error {
			attempts++
			return errors.New("always fails")
		})

		if err == nil {
			t.Error("expected error")
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt when disabled, got %d", attempts)
		}
	})

	t.Run("succeeds on first attempt", func(t *testing.T) {
		config := DefaultRetryConfig()
		config.Enabled = true
		executor := NewRetryExecutor(config)

		attempts := 0
		err := executor.Execute(context.Background(), func() error {
			attempts++
			return nil
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("retries on retryable error", func(t *testing.T) {
		config := &RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: Duration{10 * time.Millisecond},
			Multiplier:   2.0,
			RetryOn:      []int{503},
		}
		config.Normalize()
		executor := NewRetryExecutor(config)

		attempts := 0
		err := executor.Execute(context.Background(), func() error {
			attempts++
			return &HTTPStatusError{StatusCode: 503, Message: "Service Unavailable"}
		})

		if err == nil {
			t.Error("expected error after max attempts")
		}
		if attempts != 3 {
			t.Errorf("expected 3 attempts, got %d", attempts)
		}

		// Check that error is wrapped
		var retryErr *RetryError
		if !errors.As(err, &retryErr) {
			t.Error("expected RetryError")
		}
	})

	t.Run("stops on non-retryable error", func(t *testing.T) {
		config := &RetryConfig{
			Enabled:     true,
			MaxAttempts: 5,
			RetryOn:     []int{503},
		}
		config.Normalize()
		executor := NewRetryExecutor(config)

		attempts := 0
		err := executor.Execute(context.Background(), func() error {
			attempts++
			return &HTTPStatusError{StatusCode: 400, Message: "Bad Request"}
		})

		if err == nil {
			t.Error("expected error")
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt for non-retryable error, got %d", attempts)
		}
	})

	t.Run("succeeds after retries", func(t *testing.T) {
		config := &RetryConfig{
			Enabled:              true,
			MaxAttempts:          5,
			InitialDelay:         Duration{10 * time.Millisecond},
			Multiplier:           2.0,
			RetryOnNetworkErrors: true,
		}
		config.Normalize()
		executor := NewRetryExecutor(config)

		attempts := 0
		err := executor.Execute(context.Background(), func() error {
			attempts++
			if attempts < 3 {
				return errors.New("connection refused")
			}
			return nil
		})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if attempts != 3 {
			t.Errorf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		config := &RetryConfig{
			Enabled:              true,
			MaxAttempts:          10,
			InitialDelay:         Duration{100 * time.Millisecond},
			RetryOnNetworkErrors: true,
		}
		config.Normalize()
		executor := NewRetryExecutor(config)

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		attempts := 0
		start := time.Now()
		err := executor.Execute(ctx, func() error {
			attempts++
			return errors.New("connection refused")
		})

		duration := time.Since(start)

		if !errors.Is(err, context.DeadlineExceeded) {
			// Check if it's wrapped
			var retryErr *RetryError
			if errors.As(err, &retryErr) {
				if !errors.Is(retryErr.Err, context.DeadlineExceeded) {
					t.Logf("got wrapped error: %v (inner: %v)", err, retryErr.Err)
				}
			}
		}

		// Should not have run all 10 attempts
		if attempts >= 10 {
			t.Errorf("expected fewer than 10 attempts due to context, got %d", attempts)
		}

		t.Logf("Executed %d attempts in %v", attempts, duration)
	})

	t.Run("exponential backoff", func(t *testing.T) {
		config := &RetryConfig{
			Enabled:              true,
			MaxAttempts:          4,
			InitialDelay:         Duration{20 * time.Millisecond},
			MaxDelay:             Duration{500 * time.Millisecond},
			Multiplier:           2.0,
			Jitter:               0.0, // No jitter for predictable timing
			RetryOnNetworkErrors: true,
		}
		config.Normalize()
		executor := NewRetryExecutor(config)

		var timestamps []time.Time
		err := executor.Execute(context.Background(), func() error {
			timestamps = append(timestamps, time.Now())
			return errors.New("connection refused")
		})

		if err == nil {
			t.Error("expected error")
		}

		// Check that delays increase
		if len(timestamps) < 3 {
			t.Fatal("expected at least 3 attempts")
		}

		delay1 := timestamps[1].Sub(timestamps[0])
		delay2 := timestamps[2].Sub(timestamps[1])

		t.Logf("Delays: %v, %v", delay1, delay2)

		// Delay2 should be roughly 2x delay1 (with some tolerance)
		if delay2 < delay1 {
			t.Errorf("expected delay2 > delay1, got %v <= %v", delay2, delay1)
		}
	})
}

// =============================================================================
// Integration Tests with HTTP Server
// =============================================================================

func TestRetryWithHTTPServer(t *testing.T) {
	t.Run("retries on 503 and succeeds", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&requestCount, 1)
			if count < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"success": true})
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
			Retry: &RetryConfig{
				Enabled:      true,
				MaxAttempts:  5,
				InitialDelay: Duration{10 * time.Millisecond},
				RetryOn:      []int{503},
			},
		}

		ctx := context.Background()
		result, err := callback.DoWithRetry(ctx, map[string]any{"test": true})

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		finalCount := atomic.LoadInt32(&requestCount)
		if finalCount != 3 {
			t.Errorf("expected 3 requests, got %d", finalCount)
		}

		t.Logf("Succeeded after %d attempts", finalCount)
	})

	t.Run("fails after max retries", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
			Retry: &RetryConfig{
				Enabled:      true,
				MaxAttempts:  3,
				InitialDelay: Duration{10 * time.Millisecond},
				RetryOn:      []int{503},
			},
		}

		ctx := context.Background()
		_, err := callback.DoWithRetry(ctx, map[string]any{"test": true})

		if err == nil {
			t.Error("expected error after max retries")
		}

		finalCount := atomic.LoadInt32(&requestCount)
		if finalCount != 3 {
			t.Errorf("expected 3 requests, got %d", finalCount)
		}
	})

	t.Run("no retry on 400 error", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		callback := &Callback{
			URL:    server.URL,
			Method: "POST",
			Retry: &RetryConfig{
				Enabled:      true,
				MaxAttempts:  5,
				InitialDelay: Duration{10 * time.Millisecond},
				RetryOn:      []int{503},
			},
		}

		ctx := context.Background()
		_, err := callback.DoWithRetry(ctx, map[string]any{"test": true})

		if err == nil {
			t.Error("expected error")
		}

		finalCount := atomic.LoadInt32(&requestCount)
		if finalCount != 1 {
			t.Errorf("expected 1 request (no retry on 400), got %d", finalCount)
		}
	})
}

// =============================================================================
// Backoff Calculation Tests
// =============================================================================

func TestExponentialBackoff(t *testing.T) {
	testCases := []struct {
		attempt      int
		initialDelay time.Duration
		maxDelay     time.Duration
		multiplier   float64
		expected     time.Duration
	}{
		{0, 100 * time.Millisecond, 10 * time.Second, 2.0, 100 * time.Millisecond},
		{1, 100 * time.Millisecond, 10 * time.Second, 2.0, 200 * time.Millisecond},
		{2, 100 * time.Millisecond, 10 * time.Second, 2.0, 400 * time.Millisecond},
		{3, 100 * time.Millisecond, 10 * time.Second, 2.0, 800 * time.Millisecond},
		{10, 100 * time.Millisecond, 10 * time.Second, 2.0, 10 * time.Second}, // Capped at max
		{0, 50 * time.Millisecond, 1 * time.Second, 3.0, 50 * time.Millisecond},
		{2, 50 * time.Millisecond, 1 * time.Second, 3.0, 450 * time.Millisecond},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("attempt_%d", tc.attempt), func(t *testing.T) {
			result := ExponentialBackoff(tc.attempt, tc.initialDelay, tc.maxDelay, tc.multiplier)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestAddJitter(t *testing.T) {
	duration := 100 * time.Millisecond

	t.Run("zero jitter returns original", func(t *testing.T) {
		result := addJitter(duration, 0.0)
		if result != duration {
			t.Errorf("expected %v, got %v", duration, result)
		}
	})

	t.Run("jitter produces variation", func(t *testing.T) {
		// Run multiple times to check jitter produces different values
		results := make(map[time.Duration]bool)
		for i := 0; i < 100; i++ {
			result := addJitter(duration, 0.5)
			results[result] = true

			// Should be within range
			min := time.Duration(float64(duration) * 0.5)
			max := time.Duration(float64(duration) * 1.5)
			if result < min || result > max {
				t.Errorf("result %v out of range [%v, %v]", result, min, max)
			}
		}

		// Should have some variation
		if len(results) < 10 {
			t.Errorf("expected more variation in jitter results, got %d unique values", len(results))
		}
	})
}

// =============================================================================
// Retry Error Tests
// =============================================================================

func TestRetryError(t *testing.T) {
	t.Run("wraps underlying error", func(t *testing.T) {
		underlyingErr := errors.New("underlying error")
		retryErr := &RetryError{
			Err:          underlyingErr,
			Attempt:      3,
			MaxAttempts:  5,
			TotalElapsed: 500 * time.Millisecond,
		}

		if retryErr.Error() != "underlying error" {
			t.Errorf("expected underlying error message, got %s", retryErr.Error())
		}

		if !errors.Is(retryErr, underlyingErr) {
			t.Error("expected errors.Is to match underlying error")
		}

		unwrapped := retryErr.Unwrap()
		if unwrapped != underlyingErr {
			t.Error("expected Unwrap to return underlying error")
		}
	})
}
