package config

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func TestLoadProxy(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid proxy config",
			input: `{
				"type": "proxy",
				"url": "https://backend.example.com"
			}`,
			expectError: false,
		},
		{
			name: "proxy with strip base path",
			input: `{
				"type": "proxy",
				"url": "https://backend.example.com/api",
				"strip_base_path": true
			}`,
			expectError: false,
		},
		{
			name: "proxy with preserve query",
			input: `{
				"type": "proxy",
				"url": "https://backend.example.com",
				"preserve_query": true
			}`,
			expectError: false,
		},
		{
			name: "proxy with alt hostname",
			input: `{
				"type": "proxy",
				"url": "https://backend.example.com",
				"alt_hostname": "different.example.com"
			}`,
			expectError: false,
		},
		{
			name: "proxy with connection settings",
			input: `{
				"type": "proxy",
				"url": "https://backend.example.com",
				"disable_compression": true,
				"skip_tls_verify_host": true,
				"http11_only": true,
				"max_redirects": 10,
				"timeout": 30000000000
			}`,
			expectError: false,
		},
		{
			name: "invalid url",
			input: `{
				"type": "proxy",
				"url": "not a valid url"
			}`,
			expectError: true,
			errorMsg:    "invalid",
		},
		{
			name: "invalid json",
			input: `{
				"type": "proxy",
				"url": 12345
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadProxy([]byte(tt.input))
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

			if cfg.GetType() != TypeProxy {
				t.Errorf("expected type %s, got %s", TypeProxy, cfg.GetType())
			}

			// Test transport is set
			if cfg.Transport() == nil {
				t.Error("expected transport to be set")
			}

			// Test rewrite is set
			if cfg.Rewrite() == nil {
				t.Error("expected rewrite to be set")
			}
		})
	}
}

func TestProxyRewrite(t *testing.T) {
	tests := []struct {
		name             string
		proxyURL         string
		altHostname      string
		stripBasePath    bool
		preserveQuery    bool
		requestURL       string
		expectedURL      string
		expectedHost     string
		disableCompress  bool
		expectEncoding   bool
	}{
		{
			name:          "basic proxy",
			proxyURL:      "https://backend.example.com",
			requestURL:    "http://frontend.com/test",
			expectedURL:   "https://backend.example.com/test",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with path appending",
			proxyURL:      "https://backend.example.com/api",
			stripBasePath: false,
			requestURL:    "http://frontend.com/users",
			expectedURL:   "https://backend.example.com/api/users",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with strip base path",
			proxyURL:      "https://backend.example.com/api",
			stripBasePath: true,
			requestURL:    "http://frontend.com/users",
			expectedURL:   "https://backend.example.com/users",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with query string",
			proxyURL:      "https://backend.example.com",
			requestURL:    "http://frontend.com/test?foo=bar&baz=qux",
			expectedURL:   "https://backend.example.com/test?foo=bar&baz=qux",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with existing query and new query (merge)",
			proxyURL:      "https://backend.example.com?existing=param",
			requestURL:    "http://frontend.com/test?new=value",
			expectedURL:   "https://backend.example.com/test?existing=param&new=value",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with preserve query (only incoming)",
			proxyURL:      "https://backend.example.com?existing=param",
			preserveQuery: true,
			requestURL:    "http://frontend.com/test?new=value",
			expectedURL:   "https://backend.example.com/test?new=value",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with preserve query and no incoming query",
			proxyURL:      "https://backend.example.com?existing=param",
			preserveQuery: true,
			requestURL:    "http://frontend.com/test",
			expectedURL:   "https://backend.example.com/test",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with strip base path and preserve query",
			proxyURL:      "https://backend.example.com/api?base=param",
			stripBasePath: true,
			preserveQuery: true,
			requestURL:    "http://frontend.com/users?page=1",
			expectedURL:   "https://backend.example.com/users?page=1",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with strip base path false and preserve query true",
			proxyURL:      "https://backend.example.com/api?base=param",
			stripBasePath: false,
			preserveQuery: true,
			requestURL:    "http://frontend.com/users?page=1",
			expectedURL:   "https://backend.example.com/api/users?page=1",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with strip base path true and preserve query false",
			proxyURL:      "https://backend.example.com/api?base=param",
			stripBasePath: true,
			preserveQuery: false,
			requestURL:    "http://frontend.com/users?page=1",
			expectedURL:   "https://backend.example.com/users?base=param&page=1",
			expectedHost:  "backend.example.com",
			expectEncoding: true,
		},
		{
			name:          "proxy with alt hostname",
			proxyURL:      "https://backend.example.com",
			altHostname:   "different.example.com",
			requestURL:    "http://frontend.com/test",
			expectedURL:   "https://backend.example.com/test",
			expectedHost:  "different.example.com",
			expectEncoding: true,
		},
		{
			name:            "proxy with compression disabled",
			proxyURL:        "https://backend.example.com",
			requestURL:      "http://frontend.com/test",
			disableCompress: true,
			expectedURL:     "https://backend.example.com/test",
			expectedHost:    "backend.example.com",
			expectEncoding:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &Proxy{
				ProxyConfig: ProxyConfig{
					URL:          tt.proxyURL,
					AltHostname:  tt.altHostname,
					StripBasePath: tt.stripBasePath,
					PreserveQuery: tt.preserveQuery,
					BaseConnection: BaseConnection{
						DisableCompression: tt.disableCompress,
					},
				},
			}

			// Parse the target URL
			var err error
			proxy.targetURL, err = url.Parse(tt.proxyURL)
			if err != nil {
				t.Fatalf("failed to parse proxy URL: %v", err)
			}

			reqIn := httptest.NewRequest("GET", tt.requestURL, nil)
			reqIn.Header.Set("Accept-Encoding", "gzip")
			
			// Create a fresh outgoing request with the target URL
			reqOut, err := http.NewRequest("GET", tt.proxyURL, nil)
			if err != nil {
				t.Fatalf("failed to create out request: %v", err)
			}
			reqOut.Header = reqIn.Header.Clone()

			rewriteFn := proxy.Rewrite()
			pr := &httputil.ProxyRequest{
				In:  reqIn,
				Out: reqOut,
			}
			rewriteFn(pr)

			// Compare URL components separately to avoid query param ordering issues
			expectedURL, err := url.Parse(tt.expectedURL)
			if err != nil {
				t.Fatalf("failed to parse expected URL: %v", err)
			}
			
			if pr.Out.URL.Scheme != expectedURL.Scheme {
				t.Errorf("expected scheme %q, got %q", expectedURL.Scheme, pr.Out.URL.Scheme)
			}
			if pr.Out.URL.Host != expectedURL.Host {
				t.Errorf("expected host %q, got %q", expectedURL.Host, pr.Out.URL.Host)
			}
			if pr.Out.URL.Path != expectedURL.Path {
				t.Errorf("expected path %q, got %q", expectedURL.Path, pr.Out.URL.Path)
			}
			
			// Compare query parameters as maps (order independent)
			expectedQuery := expectedURL.Query()
			actualQuery := pr.Out.URL.Query()
			for k, expectedVals := range expectedQuery {
				actualVals, ok := actualQuery[k]
				if !ok {
					t.Errorf("expected query param %q not found", k)
					continue
				}
				if len(actualVals) != len(expectedVals) {
					t.Errorf("query param %q: expected %d values, got %d", k, len(expectedVals), len(actualVals))
				}
				for i, expectedVal := range expectedVals {
					if i < len(actualVals) && actualVals[i] != expectedVal {
						t.Errorf("query param %q[%d]: expected %q, got %q", k, i, expectedVal, actualVals[i])
					}
				}
			}
			for k := range actualQuery {
				if _, ok := expectedQuery[k]; !ok {
					t.Errorf("unexpected query param %q", k)
				}
			}

			if pr.Out.Host != tt.expectedHost {
				t.Errorf("expected Host %q, got %q", tt.expectedHost, pr.Out.Host)
			}

			if pr.Out.Header.Get("Host") != tt.expectedHost {
				t.Errorf("expected Host header %q, got %q", tt.expectedHost, pr.Out.Header.Get("Host"))
			}

			// Check Accept-Encoding header
			acceptEncoding := pr.Out.Header.Get("Accept-Encoding")
			if tt.expectEncoding && acceptEncoding == "" {
				t.Error("expected Accept-Encoding header to be set")
			}
			if !tt.expectEncoding && acceptEncoding != "" {
				t.Error("expected Accept-Encoding header to be empty")
			}
		})
	}
}


