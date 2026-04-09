package config

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitHeaders_Applied(t *testing.T) {
	rec := httptest.NewRecorder()

	info := &RateLimitInfo{
		Limit:     100,
		Remaining: 42,
		Reset:     time.Now().Add(30 * time.Second),
	}

	cfg := &RateLimitHeaderConfig{Enable: true}

	applyRateLimitHeaders(rec, info, cfg)

	if rec.Header().Get("RateLimit-Limit") != "100" {
		t.Errorf("expected RateLimit-Limit: 100, got %s", rec.Header().Get("RateLimit-Limit"))
	}

	if rec.Header().Get("RateLimit-Remaining") != "42" {
		t.Errorf("expected RateLimit-Remaining: 42, got %s", rec.Header().Get("RateLimit-Remaining"))
	}

	reset := rec.Header().Get("RateLimit-Reset")
	if reset == "" {
		t.Error("expected RateLimit-Reset header")
	}
}

func TestRateLimitHeaders_Disabled(t *testing.T) {
	rec := httptest.NewRecorder()

	info := &RateLimitInfo{
		Limit:     100,
		Remaining: 42,
		Reset:     time.Now().Add(30 * time.Second),
	}

	applyRateLimitHeaders(rec, info, nil)

	if rec.Header().Get("RateLimit-Limit") != "" {
		t.Error("should not set headers when config is nil")
	}

	applyRateLimitHeaders(rec, info, &RateLimitHeaderConfig{Enable: false})

	if rec.Header().Get("RateLimit-Limit") != "" {
		t.Error("should not set headers when disabled")
	}
}

func TestRetryAfterHeader(t *testing.T) {
	rec := httptest.NewRecorder()

	info := &RateLimitInfo{
		Reset: time.Now().Add(10 * time.Second),
	}

	applyRetryAfterHeader(rec, info)

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header")
	}
}
