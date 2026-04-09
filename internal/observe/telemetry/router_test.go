package telemetry_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/observe/telemetry"
)

func TestHealthzEndpoint(t *testing.T) {
	// Test healthz endpoint without profiler
	router := telemetry.InitializeRouter(false)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expected := "ok"
	if string(body) != expected {
		t.Errorf("Expected body %q, got %q", expected, string(body))
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf-8" {
		t.Errorf("Expected Content-Type %q, got %q", "text/plain; charset=utf-8", contentType)
	}
}

func TestHealthzEndpointWithHead(t *testing.T) {
	// Test that HEAD requests work (middleware.GetHead should handle this)
	router := telemetry.InitializeRouter(false)

	req := httptest.NewRequest("HEAD", "/healthz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// HEAD requests should return the same headers as GET, including Content-Length
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf-8" {
		t.Errorf("Expected Content-Type %q, got %q", "text/plain; charset=utf-8", contentType)
	}
}

func TestHealthzEndpointWithProfilerEnabled(t *testing.T) {
	// Test healthz endpoint with profiler enabled
	router := telemetry.InitializeRouter(true)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expected := "ok"
	if string(body) != expected {
		t.Errorf("Expected body %q, got %q", expected, string(body))
	}
}

func TestMetricsEndpoint(t *testing.T) {
	// Test that the metrics endpoint is registered
	router := telemetry.InitializeRouter(false)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Metrics endpoint should exist and return 200
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestMetricsEndpoint_HasExpectedMetrics(t *testing.T) {
	router := telemetry.InitializeRouter(false)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)

	// These metrics are registered via promauto in metric.go and should
	// appear in the Prometheus scrape output (at minimum as TYPE/HELP lines).
	// Note: CounterVec/GaugeVec metrics (like sb_requests_total and
	// active_connections) only appear once observed with labels, so we
	// check non-Vec metrics that are always present, plus Vec metrics via
	// their HELP line which promauto always emits.
	expectedMetrics := []string{
		"http_req_total",
		"http_response_time_seconds",
		"proxy_max_connections_rejected_total",
	}

	for _, name := range expectedMetrics {
		if !strings.Contains(bodyStr, name) {
			t.Errorf("Expected /metrics response to contain metric %q, but it was not found", name)
		}
	}
}

func TestProfilerEndpointWhenDisabled(t *testing.T) {
	// Test that profiler endpoint is not available when disabled
	router := telemetry.InitializeRouter(false)

	req := httptest.NewRequest("GET", "/debug/pprof/", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 404 when profiler is disabled
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
}

func TestProfilerEndpointWhenEnabled(t *testing.T) {
	// Test that profiler endpoint is available when enabled
	router := telemetry.InitializeRouter(true)

	req := httptest.NewRequest("GET", "/debug/pprof/", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 200 when profiler is enabled
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestNonExistentRoute(t *testing.T) {
	// Test that non-existent routes return 404
	router := telemetry.InitializeRouter(false)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
}
