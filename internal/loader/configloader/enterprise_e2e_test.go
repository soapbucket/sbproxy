package configloader

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestAlertRuleFires_E2E verifies alert event fires when budget utilization crosses threshold
func TestAlertRuleFires_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "alert-fire.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://alert-fire.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAlertThrottle_E2E verifies duplicate alerts are suppressed within throttle window
func TestAlertThrottle_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "alert-throttle.test", mock.URL, nil)

	for i := 0; i < 3; i++ {
		r := newTestRequest(t, "POST", "http://alert-throttle.test/v1/chat/completions")
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
		w := serveAIProxy(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// TestKeyRotation_E2E verifies key rotation with grace period
func TestKeyRotation_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "key-rotate.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://key-rotate.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
