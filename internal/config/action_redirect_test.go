package config

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLoadRedirectConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid 301 redirect",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 301
			}`,
			expectError: false,
		},
		{
			name: "valid 302 redirect",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 302
			}`,
			expectError: false,
		},
		{
			name: "valid 303 redirect",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 303
			}`,
			expectError: false,
		},
		{
			name: "valid 307 redirect",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 307
			}`,
			expectError: false,
		},
		{
			name: "valid 308 redirect",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 308
			}`,
			expectError: false,
		},
		{
			name: "invalid status code 200",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 200
			}`,
			expectError: true,
			errorMsg:    "invalid redirect status code",
		},
		{
			name: "invalid status code 404",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 404
			}`,
			expectError: true,
			errorMsg:    "invalid redirect status code",
		},
		{
			name: "redirect with strip base path",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 302,
				"strip_base_path": true
			}`,
			expectError: false,
		},
		{
			name: "redirect with preserve query",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": 302,
				"preserve_query": true
			}`,
			expectError: false,
		},
		{
			name: "invalid json",
			input: `{
				"type": "redirect",
				"url": "https://example.com",
				"status_code": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadRedirectConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			if cfg.GetType() != TypeRedirect {
				t.Errorf("expected type %s, got %s", TypeRedirect, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}
		})
	}
}

func TestRedirectTransportFn(t *testing.T) {
	tests := []struct {
		name               string
		config             *RedirectConfig
		requestURL         string
		expectedLocation   string
		expectedStatusCode int
	}{
		{
			name: "simple redirect",
			config: &RedirectConfig{
				URL:        "https://newsite.com",
				StatusCode: 301,
			},
			requestURL:         "http://oldsite.com/test",
			expectedLocation:   "https://newsite.com",
			expectedStatusCode: 301,
		},
		{
			name: "redirect with strip base path",
			config: &RedirectConfig{
				URL:           "https://newsite.com",
				StatusCode:    302,
				StripBasePath: true,
			},
			requestURL:         "http://oldsite.com/some/path",
			expectedLocation:   "https://newsite.com/some/path",
			expectedStatusCode: 302,
		},
		{
			name: "redirect with preserve query",
			config: &RedirectConfig{
				URL:           "https://newsite.com",
				StatusCode:    302,
				PreserveQuery: true,
			},
			requestURL:         "http://oldsite.com/test?foo=bar&baz=qux",
			expectedLocation:   "https://newsite.com?foo=bar&baz=qux",
			expectedStatusCode: 302,
		},
		{
			name: "redirect with strip base path and query",
			config: &RedirectConfig{
				URL:           "https://newsite.com",
				StatusCode:    307,
				StripBasePath: true,
				PreserveQuery: true,
			},
			requestURL:         "http://oldsite.com/some/path?foo=bar",
			expectedLocation:   "https://newsite.com/some/path?foo=bar",
			expectedStatusCode: 307,
		},
		{
			name: "redirect with existing query in url",
			config: &RedirectConfig{
				URL:           "https://newsite.com?existing=param",
				StatusCode:    302,
				PreserveQuery: true,
			},
			requestURL:         "http://oldsite.com/test?foo=bar",
			expectedLocation:   "https://newsite.com?existing=param&foo=bar",
			expectedStatusCode: 302,
		},
		{
			name: "redirect with trailing slash handling",
			config: &RedirectConfig{
				URL:           "https://newsite.com/",
				StatusCode:    301,
				StripBasePath: true,
			},
			requestURL:         "http://oldsite.com/path",
			expectedLocation:   "https://newsite.com/path",
			expectedStatusCode: 301,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transportFn := RedirectTransportFn(tt.config)
			req, err := http.NewRequest("GET", tt.requestURL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := transportFn.RoundTrip(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.StatusCode != tt.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tt.expectedStatusCode, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != tt.expectedLocation {
				t.Errorf("expected Location %q, got %q", tt.expectedLocation, location)
			}

			// Verify response has HTML body with redirect link
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			resp.Body.Close()

			bodyStr := string(body)
			if !strings.Contains(bodyStr, "<!DOCTYPE html>") {
				t.Error("expected HTML body")
			}

			if !strings.Contains(bodyStr, "Redirecting") {
				t.Error("expected redirect message in body")
			}
		})
	}
}

