package rule

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/data"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestRequestRule_CELWithRequestVariable tests CEL expressions with request snapshot variable
func TestRequestRule_CELWithRequestVariable(t *testing.T) {
	tests := []struct {
		name         string
		celExpr      string
		setupRequest func() *http.Request
		shouldMatch  bool
	}{
		{
			name:    "Access request.method",
			celExpr: `request.method == "POST"`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{"action": "create"}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"action": "create"},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
		{
			name:    "Access request.body_json object",
			celExpr: `request.body_json.action == "create"`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{"action": "create", "user": "john"}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"action": "create", "user": "john"},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
		{
			name:    "Access request.is_json flag",
			celExpr: `request.is_json == true`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{"data": "test"}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"data": "test"},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
		{
			name:    "Check request body_json type",
			celExpr: `has(request.body_json) && has(request.body_json.user)`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{"user": "john", "id": 42}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"user": "john", "id": float64(42)},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &RequestRule{
				CELExpr: tt.celExpr,
			}

			// Unmarshal to initialize CEL expression
			jsonBytes, _ := json.Marshal(map[string]string{"cel_expr": tt.celExpr})
			err := rule.UnmarshalJSON(jsonBytes)
			if err != nil {
				t.Fatalf("Failed to unmarshal rule: %v", err)
			}

			req := tt.setupRequest()
			matched := rule.Match(req)

			if matched != tt.shouldMatch {
				t.Errorf("Expected match=%v, got=%v", tt.shouldMatch, matched)
			}
		})
	}
}

// TestRequestRule_LuaWithRequestVariable tests Lua scripts with request snapshot variable
func TestRequestRule_LuaWithRequestVariable(t *testing.T) {
	tests := []struct {
		name         string
		luaScript    string
		setupRequest func() *http.Request
		shouldMatch  bool
	}{
		{
			name:      "Access request.method",
			luaScript: `return request.method == "POST"`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{"action": "create"}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"action": "create"},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
		{
			name:      "Access request.body_json",
			luaScript: `return request.body_json ~= nil and request.body_json.action == "create"`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{"action": "create"}`),
					IsJSON:   true,
					BodyJSON: map[string]any{"action": "create"},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
		{
			name:      "Check request.is_json",
			luaScript: `return request.is_json == true`,
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "http://example.com", nil)
				rd := requestdata.NewRequestData("test-123", 0)
				rd.Snapshot = &reqctx.RequestSnapshot{
					Method:   "POST",
					Body:     []byte(`{}`),
					IsJSON:   true,
					BodyJSON: map[string]any{},
				}
				ctx := reqctx.SetRequestData(req.Context(), rd)
				return req.WithContext(ctx)
			},
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &RequestRule{
				LuaScript: tt.luaScript,
			}

			// Unmarshal to initialize Lua script
			jsonBytes, _ := json.Marshal(map[string]string{"lua_script": tt.luaScript})
			err := rule.UnmarshalJSON(jsonBytes)
			if err != nil {
				t.Fatalf("Failed to unmarshal rule: %v", err)
			}

			req := tt.setupRequest()
			matched := rule.Match(req)

			if matched != tt.shouldMatch {
				t.Errorf("Expected match=%v, got=%v", tt.shouldMatch, matched)
			}
		})
	}
}
