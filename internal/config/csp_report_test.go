package config

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSPViolationReportHandler_ServeHTTP(t *testing.T) {
	cfg := &Config{ID: "test-config"}
	handler := NewCSPViolationReportHandler(cfg)

	tests := []struct {
		name           string
		method         string
		body           string
		wantStatus     int
		wantLog        bool
	}{
		{
			name: "valid violation report",
			method: http.MethodPost,
			body: `{
				"csp-report": {
					"document-uri": "https://example.com/page",
					"referrer": "https://example.com/",
					"violated-directive": "script-src 'self'",
					"effective-directive": "script-src",
					"original-policy": "default-src 'self'; script-src 'self'",
					"disposition": "enforce",
					"blocked-uri": "inline",
					"line-number": 42,
					"column-number": 10,
					"source-file": "https://example.com/page",
					"status-code": 200,
					"script-sample": "alert('test')"
				}
			}`,
			wantStatus: http.StatusNoContent,
			wantLog:    true,
		},
		{
			name:       "wrong method",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusMethodNotAllowed,
			wantLog:    false,
		},
		{
			name:       "invalid JSON",
			method:     http.MethodPost,
			body:       "invalid json",
			wantStatus: http.StatusBadRequest,
			wantLog:    false,
		},
		{
			name:       "empty body",
			method:     http.MethodPost,
			body:       "",
			wantStatus: http.StatusBadRequest,
			wantLog:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/csp-report", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestCSPViolationReportHandler_ParseReport(t *testing.T) {
	cfg := &Config{ID: "test-config"}
	handler := NewCSPViolationReportHandler(cfg)

	reportJSON := `{
		"csp-report": {
			"document-uri": "https://example.com/page",
			"referrer": "https://example.com/",
			"violated-directive": "script-src 'self'",
			"effective-directive": "script-src",
			"original-policy": "default-src 'self'; script-src 'self'",
			"disposition": "enforce",
			"blocked-uri": "inline",
			"line-number": 42,
			"column-number": 10,
			"source-file": "https://example.com/page",
			"status-code": 200,
			"script-sample": "alert('test')"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/csp-report", bytes.NewBufferString(reportJSON))
	req.Header.Set("Content-Type", "application/csp-report")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("ServeHTTP() status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHandleCSPViolationReport_Fallback(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{
			name:       "valid report",
			method:     http.MethodPost,
			body:       `{"csp-report": {"document-uri": "https://example.com", "violated-directive": "script-src"}}`,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "wrong method",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "invalid JSON",
			method:     http.MethodPost,
			body:       "invalid",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/csp-report", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()

			HandleCSPViolationReport(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("HandleCSPViolationReport() status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestCSPViolationReport_Unmarshal(t *testing.T) {
	reportJSON := `{
		"csp-report": {
			"document-uri": "https://example.com/page",
			"referrer": "https://example.com/",
			"violated-directive": "script-src 'self'",
			"effective-directive": "script-src",
			"original-policy": "default-src 'self'; script-src 'self'",
			"disposition": "enforce",
			"blocked-uri": "inline",
			"line-number": 42,
			"column-number": 10,
			"source-file": "https://example.com/page",
			"status-code": 200,
			"script-sample": "alert('test')"
		}
	}`

	var report CSPViolationReport
	err := json.Unmarshal([]byte(reportJSON), &report)
	if err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	if report.Body.DocumentURI != "https://example.com/page" {
		t.Errorf("DocumentURI = %q, want %q", report.Body.DocumentURI, "https://example.com/page")
	}
	if report.Body.ViolatedDirective != "script-src 'self'" {
		t.Errorf("ViolatedDirective = %q, want %q", report.Body.ViolatedDirective, "script-src 'self'")
	}
	if report.Body.LineNumber != 42 {
		t.Errorf("LineNumber = %d, want %d", report.Body.LineNumber, 42)
	}
	if report.Body.ScriptSample != "alert('test')" {
		t.Errorf("ScriptSample = %q, want %q", report.Body.ScriptSample, "alert('test')")
	}
}

func TestCSPReportHandler_RouteMatching(t *testing.T) {
	// Create a config with CSP report URI in policies
	configJSON := `{
		"id": "test-config",
		"hostname": "example.com",
		"action": {
			"type": "static",
			"body": "test"
		},
		"policies": [
			{
				"type": "security_headers",
				"content_security_policy": {
					"enabled": true,
					"policy": "default-src 'self'",
					"report_uri": "/csp-report"
				}
			}
		]
	}`

	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Test that CSPReportHandler matches the report URI
	req := httptest.NewRequest(http.MethodPost, "/csp-report", bytes.NewBufferString(`{"csp-report": {"document-uri": "https://example.com"}}`))
	rec := httptest.NewRecorder()

	handler := CSPReportHandler(&cfg)
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler(next).ServeHTTP(rec, req)

	// The handler should process the report and return 204, not call next
	if rec.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rec.Code)
	}
	if nextCalled {
		t.Error("Next handler should not be called for CSP report endpoint")
	}
}

