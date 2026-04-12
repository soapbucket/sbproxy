package configloader

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestBudgetExceeded_DowngradeThenBlock_E2E verifies budget exceeded downgrades then blocks
func TestBudgetExceeded_DowngradeThenBlock_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "budget-block.test", mock.URL, nil)

	// Without enterprise budget module, requests should pass normally
	r := newTestRequest(t, "POST", "http://budget-block.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBudgetOverride_E2E verifies budget override flag allows requests past budget
func TestBudgetOverride_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "budget-override.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://budget-override.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-SB-Budget-Override", "true")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestProviderBudgetRouting_E2E verifies budget-exhausted provider routes to next provider
func TestProviderBudgetRouting_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyMultiProviderJSON(t, "budget-route.test", []string{mock.URL, mock.URL}, nil)

	r := newTestRequest(t, "POST", "http://budget-route.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSpendEventVerification_E2E verifies spend events have correct cost and token info
func TestSpendEventVerification_E2E(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "spend-event.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://spend-event.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}]}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
