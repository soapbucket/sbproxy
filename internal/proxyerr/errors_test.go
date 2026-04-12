package proxyerr

import (
	"errors"
	"testing"
)

func TestProxyError(t *testing.T) {
	t.Run("basic error", func(t *testing.T) {
		err := New(ErrCodeConfigLoad, "failed to load config")
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		if err.Code != ErrCodeConfigLoad {
			t.Errorf("expected code %s, got %s", ErrCodeConfigLoad, err.Code)
		}

		if err.Message != "failed to load config" {
			t.Errorf("expected message 'failed to load config', got '%s'", err.Message)
		}
	})

	t.Run("wrapped error", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := Wrap(ErrCodeTransportFailed, "transport failed", cause)

		if err.Cause != cause {
			t.Error("expected cause to be preserved")
		}

		if !errors.Is(err, cause) {
			t.Error("expected errors.Is to work with wrapped error")
		}
	})

	t.Run("error with details", func(t *testing.T) {
		err := New(ErrCodeRateLimited, "rate limited").
			WithDetail("limit", 100).
			WithDetail("window", "1m")

		if err.Details["limit"] != 100 {
			t.Error("expected limit detail to be set")
		}

		if err.Details["window"] != "1m" {
			t.Error("expected window detail to be set")
		}
	})

	t.Run("retryable error", func(t *testing.T) {
		err := New(ErrCodeTransportTimeout, "timeout").
			WithRetryable(true)

		if !err.Retryable {
			t.Error("expected error to be retryable")
		}

		if !IsRetryable(err) {
			t.Error("IsRetryable should return true")
		}
	})
}

func TestIs(t *testing.T) {
	err := New(ErrCodeConfigLoad, "config load failed")

	if !Is(err, ErrCodeConfigLoad) {
		t.Error("Is should return true for matching code")
	}

	if Is(err, ErrCodeAuthFailed) {
		t.Error("Is should return false for non-matching code")
	}

	// Test with non-ProxyError
	regularErr := errors.New("regular error")
	if Is(regularErr, ErrCodeConfigLoad) {
		t.Error("Is should return false for non-ProxyError")
	}
}

func TestGetCode(t *testing.T) {
	err := New(ErrCodeTransportTimeout, "timeout")

	code := GetCode(err)
	if code != ErrCodeTransportTimeout {
		t.Errorf("expected code %s, got %s", ErrCodeTransportTimeout, code)
	}

	// Test with non-ProxyError
	regularErr := errors.New("regular error")
	code = GetCode(regularErr)
	if code != "" {
		t.Errorf("expected empty code for non-ProxyError, got %s", code)
	}
}

func TestGetDetails(t *testing.T) {
	err := New(ErrCodeCacheMiss, "cache miss").
		WithDetail("key", "test-key").
		WithDetail("ttl", 300)

	details := GetDetails(err)
	if details["key"] != "test-key" {
		t.Error("expected key detail to match")
	}

	if details["ttl"] != 300 {
		t.Error("expected ttl detail to match")
	}

	// Test with non-ProxyError
	regularErr := errors.New("regular error")
	details = GetDetails(regularErr)
	if details != nil {
		t.Error("expected nil details for non-ProxyError")
	}
}
