package modifier

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/data"
)

// TestRequestModifier_MustacheTemplates tests Mustache template resolution in modifiers
func TestRequestModifier_MustacheTemplates(t *testing.T) {
	tests := []struct {
		name            string
		headerValue     string
		setupContext    func(*http.Request) *http.Request
		expectedValue   string
		skipIfNoReqData bool
	}{
		{
			name:        "Simple variable substitution",
			headerValue: "Bearer {{secrets.api_key}}",
			setupContext: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("test-123", 0)
				rd.OriginCtx = &reqctx.OriginContext{
					Secrets: map[string]string{"api_key": "secret123"},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedValue: "Bearer secret123",
		},
		{
			name:        "Original request body_json access - object",
			headerValue: "X-User: {{request.body_json.user}}",
			setupContext: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Body:     []byte(`{"user": "john", "id": 42}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"user": "john", "id": float64(42)},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedValue: "X-User: john",
		},
		{
			name:        "Conditional logic with section",
			headerValue: "X-Auth: {{#session.auth.data.user}}authenticated{{/session.auth.data.user}}{{^session.auth.data.user}}guest{{/session.auth.data.user}}",
			setupContext: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("test-123", 0)
				rd.SessionData = &reqctx.SessionData{
					ID: "session123",
					AuthData: &reqctx.AuthData{
						Type: "jwt",
						Data: map[string]any{"user": "john"},
					},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedValue: "X-Auth: authenticated",
		},
		{
			name:        "Simple value access",
			headerValue: "X-User: {{request.data.name}}",
			setupContext: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Data = map[string]any{"name": "john"}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedValue: "X-User: john",
		},
		{
			name:        "Request without context (should fallback)",
			headerValue: "X-Static: {{missing.value}}",
			setupContext: func(r *http.Request) *http.Request {
				return r // No RequestData context
			},
			expectedValue:   "X-Static: ",
			skipIfNoReqData: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test request
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req = tt.setupContext(req)

			// Resolve template
			result := resolveTemplateVariables(tt.headerValue, req)

			if result != tt.expectedValue {
				t.Errorf("Expected '%s', got '%s'", tt.expectedValue, result)
			}
		})
	}
}

// TestRequestModifier_ApplyWithMustache tests full modifier application with Mustache
func TestRequestModifier_ApplyWithMustache(t *testing.T) {
	// Create request with context
	req := httptest.NewRequest("POST", "http://example.com/api?foo=bar", nil)

	rd := requestdata.NewRequestData("test-123", 0)
	rd.OriginCtx = &reqctx.OriginContext{
		Secrets: map[string]string{"api_key": "secret123"},
	}
	rd.Data = map[string]any{
		"on_request_1": map[string]any{
			"email": "john@example.com",
			"name":  "John Doe",
		},
	}
	rd.Snapshot = &reqctx.RequestSnapshot{
		Method:   "POST",
		Body:     []byte(`{"action": "create", "type": "user"}`),
		IsJSON:   true,
		BodyJSON: map[string]any{"action": "create", "type": "user"},
	}

	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	// Create modifier with Mustache templates
	modifier := &RequestModifier{
		Headers: &HeaderModifications{
			Set: map[string]string{
				"Authorization":     "Bearer {{secrets.api_key}}",
				"X-User-Email":      "{{request.data.on_request_1.email}}",
				"X-User-Name":       "{{request.data.on_request_1.name}}",
				"X-Original-Action": "{{request.body_json.action}}",
				"X-Conditional":     "{{#request.body_json.type}}has-type{{/request.body_json.type}}",
			},
		},
	}

	// Apply modifier
	err := modifier.Apply(req)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify headers
	if req.Header.Get("Authorization") != "Bearer secret123" {
		t.Errorf("Authorization header incorrect: %s", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-User-Email") != "john@example.com" {
		t.Errorf("X-User-Email header incorrect: %s", req.Header.Get("X-User-Email"))
	}
	if req.Header.Get("X-User-Name") != "John Doe" {
		t.Errorf("X-User-Name header incorrect: %s", req.Header.Get("X-User-Name"))
	}
	if req.Header.Get("X-Original-Action") != "create" {
		t.Errorf("X-Original-Action header incorrect: %s", req.Header.Get("X-Original-Action"))
	}
	if req.Header.Get("X-Conditional") != "has-type" {
		t.Errorf("X-Conditional header incorrect: %s", req.Header.Get("X-Conditional"))
	}
}

// Benchmark Mustache template resolution in modifiers
func BenchmarkResolveTemplateVariables(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com", nil)

	rd := requestdata.NewRequestData("test-123", 0)
	rd.OriginCtx = &reqctx.OriginContext{
		Secrets: map[string]string{"api_key": "secret123"},
	}
	rd.Data = map[string]any{"user": map[string]any{"name": "john"}}

	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	template := "Bearer {{secrets.api_key}}"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resolveTemplateVariables(template, req)
	}
}
