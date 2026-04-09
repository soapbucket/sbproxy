package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExpressionPolicy_CEL(t *testing.T) {
	tests := []struct {
		name       string
		celExpr    string
		method     string
		path       string
		headers    map[string]string
		wantStatus int
		wantAllow  bool
	}{
		{
			name:       "allow GET requests",
			celExpr:    "request.method == 'GET'",
			method:     "GET",
			path:       "/test",
			wantStatus: http.StatusOK,
			wantAllow:  true,
		},
		{
			name:       "block POST requests",
			celExpr:    "request.method == 'GET'",
			method:     "POST",
			path:       "/test",
			wantStatus: http.StatusUnauthorized,
			wantAllow:  false,
		},
		{
			name:       "allow specific paths",
			celExpr:    "request.path.startsWith('/api/')",
			method:     "GET",
			path:       "/api/users",
			wantStatus: http.StatusOK,
			wantAllow:  true,
		},
		{
			name:       "block other paths",
			celExpr:    "request.path.startsWith('/api/')",
			method:     "GET",
			path:       "/admin/users",
			wantStatus: http.StatusUnauthorized,
			wantAllow:  false,
		},
		{
			name:    "require authorization header",
			celExpr: "'authorization' in request.headers",
			method:  "GET",
			path:    "/test",
			headers: map[string]string{
				"Authorization": "Bearer token123",
			},
			wantStatus: http.StatusOK,
			wantAllow:  true,
		},
		{
			name:       "block without authorization header",
			celExpr:    "'authorization' in request.headers",
			method:     "GET",
			path:       "/test",
			wantStatus: http.StatusUnauthorized,
			wantAllow:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create policy from JSON
			data := []byte(`{
				"type": "expression",
				"cel_expr": "` + tt.celExpr + `"
			}`)

			// Initialize policy
			policy, err := NewExpressionPolicy(data)
			if err != nil {
				t.Fatalf("Failed to create policy: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Create test response recorder
			rec := httptest.NewRecorder()

			// Create mock next handler
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Apply policy
			handler := policy.Apply(next)
			handler.ServeHTTP(rec, req)

			// Check if next was called correctly
			if tt.wantAllow && !nextCalled {
				t.Error("Expected next handler to be called, but it wasn't")
			}
			if !tt.wantAllow && nextCalled {
				t.Error("Expected next handler NOT to be called, but it was")
			}

			// Check status code
			if tt.wantAllow {
				if rec.Code != tt.wantStatus {
					t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
				}
			} else {
				if rec.Code != tt.wantStatus {
					t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
				}
			}
		})
	}
}

func TestExpressionPolicy_Lua(t *testing.T) {
	tests := []struct {
		name       string
		luaScript  string
		method     string
		path       string
		wantStatus int
		wantAllow  bool
	}{
		{
			name:       "allow GET requests",
			luaScript:  "return request.method == 'GET'",
			method:     "GET",
			path:       "/test",
			wantStatus: http.StatusOK,
			wantAllow:  true,
		},
		{
			name:       "block POST requests",
			luaScript:  "return request.method == 'GET'",
			method:     "POST",
			path:       "/test",
			wantStatus: http.StatusUnauthorized,
			wantAllow:  false,
		},
		{
			name:       "allow specific paths",
			luaScript:  "return string.match(request.path, '^/api/') ~= nil",
			method:     "GET",
			path:       "/api/users",
			wantStatus: http.StatusOK,
			wantAllow:  true,
		},
		{
			name:       "block other paths",
			luaScript:  "return string.match(request.path, '^/api/') ~= nil",
			method:     "GET",
			path:       "/admin/users",
			wantStatus: http.StatusUnauthorized,
			wantAllow:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create policy from JSON
			data := []byte(`{
				"type": "expression",
				"lua_script": "` + tt.luaScript + `"
			}`)

			// Initialize policy
			policy, err := NewExpressionPolicy(data)
			if err != nil {
				t.Fatalf("Failed to create policy: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(tt.method, tt.path, nil)

			// Create test response recorder
			rec := httptest.NewRecorder()

			// Create mock next handler
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Apply policy
			handler := policy.Apply(next)
			handler.ServeHTTP(rec, req)

			// Check if next was called correctly
			if tt.wantAllow && !nextCalled {
				t.Error("Expected next handler to be called, but it wasn't")
			}
			if !tt.wantAllow && nextCalled {
				t.Error("Expected next handler NOT to be called, but it was")
			}

			// Check status code
			if tt.wantAllow {
				if rec.Code != tt.wantStatus {
					t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
				}
			} else {
				if rec.Code != tt.wantStatus {
					t.Errorf("Expected status %d, got %d", tt.wantStatus, rec.Code)
				}
			}
		})
	}
}

func TestExpressionPolicy_Disabled(t *testing.T) {
	// Create policy from JSON with disabled flag
	data := []byte(`{
		"type": "expression",
		"disabled": true,
		"cel_expr": "false"
	}`)

	policy, err := NewExpressionPolicy(data)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := policy.Apply(next)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Expected next handler to be called when policy is disabled")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

