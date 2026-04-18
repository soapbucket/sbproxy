package logging

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestLogAccess_NoExtraFields(t *testing.T) {
	// Ensure LogAccess does not panic with nil extra map
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	LogAccess(req, 200, 1024, 150*time.Millisecond, "test-origin", nil)
}

func TestLogAccess_WithExtraFields(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/api/v1", nil)
	extra := map[string]any{
		"cache_hit":    true,
		"workspace_id": "ws-123",
	}
	LogAccess(req, 201, 512, 50*time.Millisecond, "api-origin", extra)
}

func TestLogAccessCombined(t *testing.T) {
	// Ensure combined format does not panic
	req := httptest.NewRequest("GET", "http://example.com/path?q=1", nil)
	req.Header.Set("Referer", "http://example.com/")
	req.Header.Set("User-Agent", "TestAgent/1.0")
	LogAccessCombined(req, 200, 2048, 100*time.Millisecond, "test-origin")
}

func TestFilterAccessLogFields_Default(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	attrs := FilterAccessLogFields(req, 200, 1024, 100*time.Millisecond, "test-origin", nil)

	if len(attrs) != len(defaultAccessLogFields) {
		t.Errorf("expected %d attrs with default fields, got %d", len(defaultAccessLogFields), len(attrs))
	}
}

func TestFilterAccessLogFields_Custom(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	fields := []string{"method", "status_code"}
	attrs := FilterAccessLogFields(req, 200, 1024, 100*time.Millisecond, "test-origin", fields)

	if len(attrs) != 2 {
		t.Errorf("expected 2 attrs with custom fields, got %d", len(attrs))
	}
}

func TestFilterAccessLogFields_UnknownField(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	fields := []string{"method", "nonexistent_field"}
	attrs := FilterAccessLogFields(req, 200, 1024, 100*time.Millisecond, "test-origin", fields)

	// "nonexistent_field" is not in the all map, so only "method" should be included
	if len(attrs) != 1 {
		t.Errorf("expected 1 attr (unknown field skipped), got %d", len(attrs))
	}
}

func TestAccessLogConfig_Fields(t *testing.T) {
	cfg := AccessLogConfig{
		Enabled: true,
		Fields:  []string{"method", "path", "status_code"},
		Format:  "json",
	}
	if !cfg.Enabled {
		t.Error("expected config to be enabled")
	}
	if cfg.Format != "json" {
		t.Errorf("expected format json, got %s", cfg.Format)
	}
	if len(cfg.Fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(cfg.Fields))
	}
}
