package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestResolve tests the template resolution function
func TestResolve(t *testing.T) {
	tests := []struct {
		name     string
		template string
		setupReq func(*http.Request)
		want     string
		wantErr  bool
	}{
		{
			name:     "simple variable substitution",
			template: "{{request.method}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "GET",
			wantErr: false,
		},
		{
			name:     "request path",
			template: "{{request.path}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "/test/path",
			wantErr: false,
		},
		{
			name:     "header access",
			template: "{{request.headers.user_agent}}",
			setupReq: func(r *http.Request) {
				r.Header.Set("User-Agent", "TestBrowser/1.0")
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "TestBrowser/1.0",
			wantErr: false,
		},
		{
			name:     "request ID",
			template: "{{request.id}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "unique-request-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "unique-request-id",
			wantErr: false,
		},
		{
			name:     "request data",
			template: "{{ctx.data.custom_key}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data: map[string]any{
						"custom_key": "custom_value",
					},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "custom_value",
			wantErr: false,
		},
		{
			name:     "static text",
			template: "Hello, World!",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "Hello, World!",
			wantErr: false,
		},
		{
			name:     "mixed template",
			template: "Method: {{request.method}}, Path: {{request.path}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "Method: GET, Path: /test/path",
			wantErr: false,
		},
		{
			name:     "no html escaping",
			template: "{{ctx.data.html_val}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data: map[string]any{
						"html_val": "<b>bold</b> & 'quoted'",
					},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "<b>bold</b> & 'quoted'",
			wantErr: false,
		},
		{
			name:     "missing variable produces empty string",
			template: "before{{request.headers.nonexistent}}after",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "beforeafter",
			wantErr: false,
		},
		{
			name:     "invalid template syntax",
			template: "{{#unclosed_section}}",
			setupReq: func(r *http.Request) {
				rd := &reqctx.RequestData{
					ID:           "test-id",
					DebugHeaders: make(map[string]string),
					Data:         make(map[string]any),
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				*r = *r.WithContext(ctx)
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test/path", nil)
			tt.setupReq(req)

			got, err := Resolve(tt.template, req)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestResolveWithContext tests template resolution with a context map
func TestResolveWithContext(t *testing.T) {
	tests := []struct {
		name     string
		template string
		ctx      map[string]any
		want     string
		wantErr  bool
	}{
		{
			name:     "simple variable",
			template: "Hello, {{name}}!",
			ctx:      map[string]any{"name": "World"},
			want:     "Hello, World!",
		},
		{
			name:     "nested access",
			template: "{{user.email}}",
			ctx: map[string]any{
				"user": map[string]any{"email": "test@example.com"},
			},
			want: "test@example.com",
		},
		{
			name:     "section iteration",
			template: "{{#items}}{{.}} {{/items}}",
			ctx:      map[string]any{"items": []string{"a", "b", "c"}},
			want:     "a b c ",
		},
		{
			name:     "inverted section for empty",
			template: "{{^items}}no items{{/items}}",
			ctx:      map[string]any{"items": []string{}},
			want:     "no items",
		},
		{
			name:     "truthy section",
			template: "{{#active}}yes{{/active}}",
			ctx:      map[string]any{"active": true},
			want:     "yes",
		},
		{
			name:     "falsy inverted section",
			template: "{{^active}}no{{/active}}",
			ctx:      map[string]any{"active": false},
			want:     "no",
		},
		{
			name:     "static text - no parsing",
			template: "just text",
			ctx:      map[string]any{},
			want:     "just text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveWithContext(tt.template, tt.ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("ResolveWithContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildContext tests context building from request
func TestBuildContext(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		ctx := BuildContext(nil)
		if len(ctx) != 0 {
			t.Error("expected empty context for nil request")
		}
	})

	t.Run("request without request data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := BuildContext(req)
		if len(ctx) != 0 {
			t.Error("expected empty context when request data is missing")
		}
	})

	t.Run("request with full data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test/path?foo=bar", nil)
		req.Header.Set("User-Agent", "TestBrowser")
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.168.1.1:12345"

		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data: map[string]any{
				"custom": "value",
			},
			StartTime: time.Now(),
			Secrets: map[string]string{
				"api_key": "secret123",
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		// Check request context
		reqCtx, ok := pongoCtx["request"].(map[string]any)
		if !ok {
			t.Fatal("request context should be a map")
		}

		if reqCtx["method"] != "GET" {
			t.Errorf("method = %v, want GET", reqCtx["method"])
		}

		if reqCtx["path"] != "/test/path" {
			t.Errorf("path = %v, want /test/path", reqCtx["path"])
		}

		if reqCtx["remote_addr"] != "192.168.1.1" {
			t.Errorf("remote_addr = %v, want 192.168.1.1", reqCtx["remote_addr"])
		}

		// Check headers are lowercase with underscores
		headers, ok := reqCtx["headers"].(map[string]string)
		if !ok {
			t.Fatal("headers should be a map[string]string")
		}

		if headers["user_agent"] != "TestBrowser" {
			t.Errorf("user_agent = %v, want TestBrowser", headers["user_agent"])
		}

		// Check ctx namespace has data
		ctxNs, ok := pongoCtx["ctx"].(map[string]any)
		if !ok {
			t.Fatal("ctx should be map[string]any in context")
		}
		if ctxNs["data"] == nil {
			t.Error("ctx.data should not be nil")
		}
	})

	t.Run("request with session data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			SessionData: &reqctx.SessionData{
				ID: "session-123",
				Data: map[string]any{
					"user_id": "user-456",
				},
				AuthData: &reqctx.AuthData{
					Type: "jwt",
					Data: map[string]any{
						"sub": "user-456",
					},
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		// Check session context
		sessionCtx, ok := pongoCtx["session"].(map[string]any)
		if !ok {
			t.Fatal("session context should be a map")
		}

		if sessionCtx["id"] != "session-123" {
			t.Errorf("session id = %v, want session-123", sessionCtx["id"])
		}

		// Check auth within session namespace
		authCtx, ok := sessionCtx["auth"].(map[string]any)
		if !ok {
			t.Fatal("session.auth should be a map")
		}

		if authCtx["type"] != "jwt" {
			t.Errorf("session.auth.type = %v, want jwt", authCtx["type"])
		}
	})

	t.Run("request with location data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			ClientCtx: &reqctx.ClientContext{
				IP: "192.168.1.1",
				Location: &reqctx.Location{
					Country:       "United States",
					CountryCode:   "US",
					Continent:     "North America",
					ContinentCode: "NA",
					ASN:           "15169",
					ASName:        "Google LLC",
					ASDomain:      "google.com",
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		clientCtx, ok := pongoCtx["client"].(map[string]any)
		if !ok {
			t.Fatal("client context should be a map")
		}

		locationCtx, ok := clientCtx["location"].(map[string]any)
		if !ok {
			t.Fatal("client.location should be a map")
		}

		if locationCtx["country"] != "United States" {
			t.Errorf("country = %v, want United States", locationCtx["country"])
		}

		if locationCtx["country_code"] != "US" {
			t.Errorf("country_code = %v, want US", locationCtx["country_code"])
		}
	})

	t.Run("request with user agent data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			ClientCtx: &reqctx.ClientContext{
				IP: "192.168.1.1",
				UserAgent: &reqctx.UserAgent{
					Family:       "Chrome",
					Major:        "120",
					Minor:        "0",
					OSFamily:     "Windows",
					OSMajor:      "10",
					DeviceFamily: "Desktop",
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		clientCtx, ok := pongoCtx["client"].(map[string]any)
		if !ok {
			t.Fatal("client context should be a map")
		}

		uaCtx, ok := clientCtx["user_agent"].(map[string]any)
		if !ok {
			t.Fatal("client.user_agent should be a map")
		}

		if uaCtx["family"] != "Chrome" {
			t.Errorf("family = %v, want Chrome", uaCtx["family"])
		}

		if uaCtx["os_family"] != "Windows" {
			t.Errorf("os_family = %v, want Windows", uaCtx["os_family"])
		}
	})

	t.Run("request with fingerprint data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			ClientCtx: &reqctx.ClientContext{
				IP: "192.168.1.1",
				Fingerprint: &reqctx.Fingerprint{
					Hash:          "abc123",
					Composite:     "composite-fp",
					IPHash:        "ip-hash",
					UserAgentHash: "ua-hash",
					HeaderPattern: "pattern",
					TLSHash:       "tls-hash",
					CookieCount:   5,
					Version:       "v1",
					ConnDuration:  100 * time.Millisecond,
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		clientCtx, ok := pongoCtx["client"].(map[string]any)
		if !ok {
			t.Fatal("client context should be a map")
		}

		fpCtx, ok := clientCtx["fingerprint"].(map[string]any)
		if !ok {
			t.Fatal("client.fingerprint should be a map")
		}

		if fpCtx["hash"] != "abc123" {
			t.Errorf("hash = %v, want abc123", fpCtx["hash"])
		}

		if fpCtx["cookie_count"] != 5 {
			t.Errorf("cookie_count = %v, want 5", fpCtx["cookie_count"])
		}
	})

	t.Run("request snapshot data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			Snapshot: &reqctx.RequestSnapshot{
				Method:      "POST",
				URL:         "https://example.com/api",
				Path:        "/api",
				ContentType: "application/json",
				IsJSON:      true,
				RemoteAddr:  "10.0.0.1",
				Headers:     map[string]string{"content_type": "application/json"},
				Query:       map[string][]string{"foo": {"bar"}},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		requestCtx, ok := pongoCtx["request"].(map[string]any)
		if !ok {
			t.Fatal("request context should be a map")
		}

		if requestCtx["method"] != "POST" {
			t.Errorf("method = %v, want POST", requestCtx["method"])
		}

		if requestCtx["is_json"] != true {
			t.Errorf("is_json = %v, want true", requestCtx["is_json"])
		}
	})
}

// TestHeadersToLowercaseMap tests header conversion
func TestHeadersToLowercaseMap(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    map[string]string
	}{
		{
			name:    "nil headers",
			headers: nil,
			want:    map[string]string{},
		},
		{
			name:    "empty headers",
			headers: http.Header{},
			want:    map[string]string{},
		},
		{
			name: "single header",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			want: map[string]string{
				"content_type": "application/json",
			},
		},
		{
			name: "multiple headers",
			headers: http.Header{
				"Content-Type":    []string{"application/json"},
				"User-Agent":      []string{"TestBrowser"},
				"X-Custom-Header": []string{"custom-value"},
			},
			want: map[string]string{
				"content_type":    "application/json",
				"user_agent":      "TestBrowser",
				"x_custom_header": "custom-value",
			},
		},
		{
			name: "header with multiple values takes first",
			headers: http.Header{
				"Accept": []string{"text/html", "application/json"},
			},
			want: map[string]string{
				"accept": "text/html",
			},
		},
		{
			name: "header with empty values",
			headers: http.Header{
				"Empty": []string{},
			},
			want: map[string]string{
				"empty": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := &reqctx.RequestData{}
			got := rd.GetLowercaseHeaders(tt.headers)

			if len(got) != len(tt.want) {
				t.Errorf("length mismatch: got %d, want %d", len(got), len(tt.want))
			}

			for key, wantValue := range tt.want {
				gotValue, ok := got[key]
				if !ok {
					t.Errorf("missing key %s", key)
					continue
				}
				if gotValue != wantValue {
					t.Errorf("got[%s] = %q, want %q", key, gotValue, wantValue)
				}
			}
		})
	}
}

// TestClearCache tests cache clearing
func TestClearCache(t *testing.T) {
	// First, populate the cache by resolving some templates
	req := httptest.NewRequest("GET", "/test", nil)
	rd := &reqctx.RequestData{
		ID:           "test-id",
		DebugHeaders: make(map[string]string),
		Data:         make(map[string]any),
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	_, err := Resolve("{{request.method}}", req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Clear the cache
	ClearCache()

	// Verify we can still resolve templates (cache should be rebuilt)
	result, err := Resolve("{{request.method}}", req)
	if err != nil {
		t.Fatalf("Resolve after ClearCache failed: %v", err)
	}

	if result != "GET" {
		t.Errorf("result = %q, want GET", result)
	}
}

// TestTemplateCaching tests that templates are cached
func TestTemplateCaching(t *testing.T) {
	r := newResolver()

	template := "{{request.method}}"

	// First call should compile and cache
	tpl1, err := r.getTemplate(template)
	if err != nil {
		t.Fatalf("first getTemplate failed: %v", err)
	}

	// Second call should return cached template
	tpl2, err := r.getTemplate(template)
	if err != nil {
		t.Fatalf("second getTemplate failed: %v", err)
	}

	// Both should be the same pointer
	if tpl1 != tpl2 {
		t.Error("expected cached template to be returned")
	}
}

// TestResolveWithCacheStatus tests cache status in template context
func TestResolveWithCacheStatus(t *testing.T) {
	tests := []struct {
		name              string
		responseCacheHit  bool
		signatureCacheHit bool
		wantStatus        string
	}{
		{
			name:              "cache miss",
			responseCacheHit:  false,
			signatureCacheHit: false,
			wantStatus:        "MISS",
		},
		{
			name:              "response cache hit",
			responseCacheHit:  true,
			signatureCacheHit: false,
			wantStatus:        "HIT",
		},
		{
			name:              "signature cache hit",
			responseCacheHit:  false,
			signatureCacheHit: true,
			wantStatus:        "SIG_HIT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)

			rd := &reqctx.RequestData{
				ID:               "test-id",
				DebugHeaders:     make(map[string]string),
				Data:             make(map[string]any),
				ResponseCacheHit: tt.responseCacheHit,
				SignatureCacheHit: tt.signatureCacheHit,
			}
			ctx := reqctx.SetRequestData(req.Context(), rd)
			req = req.WithContext(ctx)

			result, err := Resolve("{{request.cache_status}}", req)
			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}

			if result != tt.wantStatus {
				t.Errorf("cache_status = %q, want %q", result, tt.wantStatus)
			}
		})
	}
}

// BenchmarkResolve benchmarks template resolution
func BenchmarkResolve(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "/test/path", nil)
	req.Header.Set("User-Agent", "TestBrowser")
	req.Header.Set("Content-Type", "application/json")

	rd := &reqctx.RequestData{
		ID:           "test-id",
		DebugHeaders: make(map[string]string),
		Data: map[string]any{
			"key": "value",
		},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)
	req = req.WithContext(ctx)

	templates := []string{
		"{{request.method}}",
		"{{request.path}}",
		"{{request.headers.user_agent}}",
		"Method: {{request.method}}, Path: {{request.path}}",
	}

	for _, tmpl := range templates {
		b.Run(strings.ReplaceAll(tmpl, "{{", "")[0:10], func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = Resolve(tmpl, req)
			}
		})
	}
}

// TestResolveVariables tests template resolution with config-level variables
func TestResolveVariables(t *testing.T) {
	tests := []struct {
		name     string
		template string
		vars     map[string]any
		want     string
	}{
		{
			name:     "simple variable",
			template: "{{vars.api_url}}",
			vars:     map[string]any{"api_url": "https://api.example.com"},
			want:     "https://api.example.com",
		},
		{
			name:     "nested variable",
			template: "{{vars.endpoints.users}}",
			vars: map[string]any{
				"endpoints": map[string]any{
					"users": "/api/v2/users",
				},
			},
			want: "/api/v2/users",
		},
		{
			name:     "integer variable",
			template: "{{vars.max_retries}}",
			vars:     map[string]any{"max_retries": 3},
			want:     "3",
		},
		{
			name:     "boolean variable with section",
			template: "{{#vars.debug}}DEBUG{{/vars.debug}}{{^vars.debug}}PROD{{/vars.debug}}",
			vars:     map[string]any{"debug": true},
			want:     "DEBUG",
		},
		{
			name:     "mixed with request context",
			template: "{{request.method}} {{vars.api_url}}",
			vars:     map[string]any{"api_url": "https://api.example.com"},
			want:     "GET https://api.example.com",
		},
		{
			name:     "nil variables - no error",
			template: "hello",
			vars:     nil,
			want:     "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rd := &reqctx.RequestData{
				ID:           "test-id",
				DebugHeaders: make(map[string]string),
				Data:         make(map[string]any),
				Variables:    tt.vars,
			}
			ctx := reqctx.SetRequestData(req.Context(), rd)
			req = req.WithContext(ctx)

			got, err := Resolve(tt.template, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildContextVariables tests that variables appear in context
func TestBuildContextVariables(t *testing.T) {
	t.Run("variables in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			Variables: map[string]any{
				"api_url": "https://api.example.com",
				"nested": map[string]any{
					"key": "value",
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		vars, ok := pongoCtx["vars"].(map[string]any)
		if !ok {
			t.Fatal("vars should be map[string]any in context")
		}
		if vars["api_url"] != "https://api.example.com" {
			t.Errorf("var.api_url = %v, want https://api.example.com", vars["api_url"])
		}
	})

	t.Run("nil variables not in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		if _, exists := pongoCtx["vars"]; exists {
			t.Error("vars should not be in context when nil")
		}
	})
}

// TestUtilityVariables tests that utility template variables are present in context
func TestUtilityVariables(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	rd := &reqctx.RequestData{
		ID:           "test-request-id-123",
		DebugHeaders: make(map[string]string),
		Data:         make(map[string]any),
		StartTime:    time.Now(),
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	pongoCtx := BuildContext(req)

	// Check timestamp (Unix seconds)
	ts, ok := pongoCtx["timestamp"]
	if !ok {
		t.Error("expected 'timestamp' in context")
	}
	if _, ok := ts.(int64); !ok {
		t.Errorf("expected timestamp to be int64, got %T", ts)
	}

	// Check timestamp_ms (Unix milliseconds)
	tsMs, ok := pongoCtx["timestamp_ms"]
	if !ok {
		t.Error("expected 'timestamp_ms' in context")
	}
	if _, ok := tsMs.(int64); !ok {
		t.Errorf("expected timestamp_ms to be int64, got %T", tsMs)
	}

	// Check date (YYYY-MM-DD)
	date, ok := pongoCtx["date"]
	if !ok {
		t.Error("expected 'date' in context")
	}
	dateStr, ok := date.(string)
	if !ok {
		t.Errorf("expected date to be string, got %T", date)
	}
	if len(dateStr) != 10 {
		t.Errorf("expected date format YYYY-MM-DD (10 chars), got %q", dateStr)
	}

	// Check time (HH:MM:SS)
	timeVal, ok := pongoCtx["time"]
	if !ok {
		t.Error("expected 'time' in context")
	}
	timeStr, ok := timeVal.(string)
	if !ok {
		t.Errorf("expected time to be string, got %T", timeVal)
	}
	if len(timeStr) != 8 {
		t.Errorf("expected time format HH:MM:SS (8 chars), got %q", timeStr)
	}

	// Check datetime (RFC3339)
	dt, ok := pongoCtx["datetime"]
	if !ok {
		t.Error("expected 'datetime' in context")
	}
	dtStr, ok := dt.(string)
	if !ok {
		t.Errorf("expected datetime to be string, got %T", dt)
	}
	if _, err := time.Parse(time.RFC3339, dtStr); err != nil {
		t.Errorf("expected datetime to be RFC3339, got %q: %v", dtStr, err)
	}

	// Check year
	year, ok := pongoCtx["year"]
	if !ok {
		t.Error("expected 'year' in context")
	}
	if y, ok := year.(int); !ok || y < 2024 {
		t.Errorf("expected valid year, got %v", year)
	}

	// Check month
	month, ok := pongoCtx["month"]
	if !ok {
		t.Error("expected 'month' in context")
	}
	if m, ok := month.(int); !ok || m < 1 || m > 12 {
		t.Errorf("expected valid month (1-12), got %v", month)
	}

	// Check day
	day, ok := pongoCtx["day"]
	if !ok {
		t.Error("expected 'day' in context")
	}
	if d, ok := day.(int); !ok || d < 1 || d > 31 {
		t.Errorf("expected valid day (1-31), got %v", day)
	}

	// Check uuid (should be the request ID)
	uuid, ok := pongoCtx["uuid"]
	if !ok {
		t.Error("expected 'uuid' in context")
	}
	if uuid != "test-request-id-123" {
		t.Errorf("expected uuid = 'test-request-id-123', got %v", uuid)
	}

	// Check random
	random, ok := pongoCtx["random"]
	if !ok {
		t.Error("expected 'random' in context")
	}
	if r, ok := random.(int64); !ok || r < 0 {
		t.Errorf("expected random to be non-negative int64, got %v", random)
	}
}

// TestUtilityVariables_TemplateResolution tests that utility variables resolve correctly in templates
func TestUtilityVariables_TemplateResolution(t *testing.T) {
	tests := []struct {
		name     string
		template string
		checkFn  func(string) bool
	}{
		{
			name:     "timestamp resolves to number",
			template: "{{timestamp}}",
			checkFn: func(s string) bool {
				return len(s) >= 10 // Unix timestamp is at least 10 digits
			},
		},
		{
			name:     "date resolves to date format",
			template: "{{date}}",
			checkFn: func(s string) bool {
				_, err := time.Parse("2006-01-02", s)
				return err == nil
			},
		},
		{
			name:     "uuid resolves to request ID",
			template: "{{uuid}}",
			checkFn: func(s string) bool {
				return s == "util-test-id"
			},
		},
		{
			name:     "datetime resolves to RFC3339",
			template: "{{datetime}}",
			checkFn: func(s string) bool {
				_, err := time.Parse(time.RFC3339, s)
				return err == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rd := &reqctx.RequestData{
				ID:           "util-test-id",
				DebugHeaders: make(map[string]string),
				Data:         make(map[string]any),
				StartTime:    time.Now(),
			}
			ctx := reqctx.SetRequestData(req.Context(), rd)
			req = req.WithContext(ctx)

			result, err := Resolve(tt.template, req)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if !tt.checkFn(result) {
				t.Errorf("Resolve(%q) = %q, did not pass check", tt.template, result)
			}
		})
	}
}

// TestUtilityVariables_CoexistWithExisting tests that utility variables coexist with request context
func TestUtilityVariables_CoexistWithExisting(t *testing.T) {
	req := httptest.NewRequest("GET", "/hello?key=value", nil)
	req.Header.Set("X-Custom", "test-value")

	rd := &reqctx.RequestData{
		ID:           "coexist-test-id",
		DebugHeaders: make(map[string]string),
		Data:         make(map[string]any),
		StartTime:    time.Now(),
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	pongoCtx := BuildContext(req)

	// Verify utility variables exist
	if _, ok := pongoCtx["timestamp"]; !ok {
		t.Error("missing 'timestamp'")
	}
	if _, ok := pongoCtx["date"]; !ok {
		t.Error("missing 'date'")
	}

	// Verify request context still exists
	reqCtx, ok := pongoCtx["request"].(map[string]any)
	if !ok {
		t.Fatal("missing 'request' context")
	}
	if reqCtx["id"] != "coexist-test-id" {
		t.Errorf("expected request.id = 'coexist-test-id', got %v", reqCtx["id"])
	}
	if reqCtx["method"] != "GET" {
		t.Errorf("expected request.method = 'GET', got %v", reqCtx["method"])
	}
	if reqCtx["path"] != "/hello" {
		t.Errorf("expected request.path = '/hello', got %v", reqCtx["path"])
	}
}

// TestUrlencodeLambda tests the urlencode lambda helper
func TestUrlencodeLambda(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	rd := &reqctx.RequestData{
		ID:           "test-id",
		DebugHeaders: make(map[string]string),
		Data: map[string]any{
			"city": "New York",
		},
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	result, err := Resolve("city={{#urlencode}}{{ctx.data.city}}{{/urlencode}}", req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if result != "city=New+York" {
		t.Errorf("urlencode result = %q, want %q", result, "city=New+York")
	}
}

// TestPathencodeLambda tests the pathencode lambda helper
func TestPathencodeLambda(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	rd := &reqctx.RequestData{
		ID:           "test-id",
		DebugHeaders: make(map[string]string),
		Data: map[string]any{
			"name": "John Doe/Admin",
		},
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	result, err := Resolve("/users/{{#pathencode}}{{ctx.data.name}}{{/pathencode}}", req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// PathEscape: spaces become %20, slashes become %2F
	if result != "/users/John%20Doe%2FAdmin" {
		t.Errorf("pathencode result = %q, want %q", result, "/users/John%20Doe%2FAdmin")
	}
}

// TestResolveServerVariables tests that server variables are available in templates
func TestResolveServerVariables(t *testing.T) {
	// Set up server variables getter for testing
	testVars := map[string]any{
		"version":    "1.2.3",
		"hostname":   "test-host",
		"custom_var": "custom_value",
	}
	SetServerVarsGetter(func() map[string]any { return testVars })
	defer SetServerVarsGetter(nil)

	tests := []struct {
		name     string
		template string
		want     string
	}{
		{
			name:     "server version",
			template: "{{server.version}}",
			want:     "1.2.3",
		},
		{
			name:     "server hostname",
			template: "{{server.hostname}}",
			want:     "test-host",
		},
		{
			name:     "custom server variable",
			template: "{{server.custom_var}}",
			want:     "custom_value",
		},
		{
			name:     "mixed with request",
			template: "{{request.method}} on {{server.hostname}}",
			want:     "GET on test-host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rd := &reqctx.RequestData{
				ID:           "test-id",
				DebugHeaders: make(map[string]string),
				Data:         make(map[string]any),
			}
			ctx := reqctx.SetRequestData(req.Context(), rd)
			req = req.WithContext(ctx)

			got, err := Resolve(tt.template, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildContextServerVariables tests that server variables appear in the context map
func TestBuildContextServerVariables(t *testing.T) {
	testVars := map[string]any{
		"version":  "2.0.0",
		"hostname": "ctx-host",
	}
	SetServerVarsGetter(func() map[string]any { return testVars })
	defer SetServerVarsGetter(nil)

	req := httptest.NewRequest("GET", "/test", nil)
	rd := &reqctx.RequestData{
		ID:           "test-id",
		DebugHeaders: make(map[string]string),
		Data:         make(map[string]any),
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	pongoCtx := BuildContext(req)

	serverCtx, ok := pongoCtx["server"].(map[string]any)
	if !ok {
		t.Fatal("server should be map[string]any in context")
	}
	if serverCtx["version"] != "2.0.0" {
		t.Errorf("server.version = %v, want 2.0.0", serverCtx["version"])
	}
	if serverCtx["hostname"] != "ctx-host" {
		t.Errorf("server.hostname = %v, want ctx-host", serverCtx["hostname"])
	}
}

// TestResolveOriginVariables tests template resolution with origin identity fields
func TestResolveOriginVariables(t *testing.T) {
	tests := []struct {
		name      string
		template  string
		originCtx *reqctx.OriginContext
		want      string
	}{
		{
			name:     "origin id",
			template: "{{origin.id}}",
			originCtx: &reqctx.OriginContext{
				ID:          "org-123",
				WorkspaceID: "ws-456",
			},
			want: "org-123",
		},
		{
			name:     "workspace_id",
			template: "{{origin.workspace_id}}",
			originCtx: &reqctx.OriginContext{
				WorkspaceID: "ws-456",
			},
			want: "ws-456",
		},
		{
			name:     "hostname",
			template: "{{origin.hostname}}",
			originCtx: &reqctx.OriginContext{
				Hostname: "api.example.com",
			},
			want: "api.example.com",
		},
		{
			name:     "version",
			template: "v{{origin.version}}",
			originCtx: &reqctx.OriginContext{
				Version: "2.1.0",
			},
			want: "v2.1.0",
		},
		{
			name:     "environment",
			template: "{{origin.environment}}",
			originCtx: &reqctx.OriginContext{
				Environment: "prod",
			},
			want: "prod",
		},
		{
			name:     "origin name",
			template: "{{origin.name}}",
			originCtx: &reqctx.OriginContext{
				Name: "my-api",
			},
			want: "my-api",
		},
		{
			name:     "mixed with request context",
			template: "{{request.method}} {{origin.id}}",
			originCtx: &reqctx.OriginContext{
				ID: "org-789",
			},
			want: "GET org-789",
		},
		{
			name:      "nil origin - no error",
			template:  "hello",
			originCtx: nil,
			want:      "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rd := &reqctx.RequestData{
				ID:           "test-id",
				DebugHeaders: make(map[string]string),
				Data:         make(map[string]any),
				OriginCtx:    tt.originCtx,
			}
			ctx := reqctx.SetRequestData(req.Context(), rd)
			req = req.WithContext(ctx)

			got, err := Resolve(tt.template, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildContextOriginAndFeatures tests that origin and features namespaces appear in the context map
func TestBuildContextOriginAndFeatures(t *testing.T) {
	t.Run("origin in context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
			OriginCtx: &reqctx.OriginContext{
				ID:          "org-123",
				WorkspaceID: "ws-456",
				Hostname:    "api.example.com",
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		originCtx, ok := pongoCtx["origin"].(map[string]any)
		if !ok {
			t.Fatal("origin should be map[string]any in context")
		}
		if originCtx["id"] != "org-123" {
			t.Errorf("origin.id = %v, want org-123", originCtx["id"])
		}
		if originCtx["workspace_id"] != "ws-456" {
			t.Errorf("origin.workspace_id = %v, want ws-456", originCtx["workspace_id"])
		}
	})

	t.Run("features placeholder always present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rd := &reqctx.RequestData{
			ID:           "test-id",
			DebugHeaders: make(map[string]string),
			Data:         make(map[string]any),
		}
		ctx := reqctx.SetRequestData(req.Context(), rd)
		req = req.WithContext(ctx)

		pongoCtx := BuildContext(req)

		featuresCtx, ok := pongoCtx["features"].(map[string]any)
		if !ok {
			t.Fatal("features should be map[string]any in context")
		}
		if len(featuresCtx) != 0 {
			t.Errorf("features should be empty map, got %v", featuresCtx)
		}
	})
}

// BenchmarkBuildContext benchmarks context building
func BenchmarkBuildContext(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "/test/path", nil)
	req.Header.Set("User-Agent", "TestBrowser")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")

	rd := &reqctx.RequestData{
		ID:           "test-id",
		DebugHeaders: make(map[string]string),
		Data: map[string]any{
			"key": "value",
		},
		StartTime: time.Now(),
		SessionData: &reqctx.SessionData{
			ID: "session-123",
			Data: map[string]any{
				"user_id": "user-456",
			},
		},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)
	req = req.WithContext(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildContext(req)
	}
}
