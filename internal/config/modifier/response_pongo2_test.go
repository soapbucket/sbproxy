package modifier

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/request/data"
)

// TestResponseModifier_Pongo2Templates tests Mustache template resolution in response modifiers
func TestResponseModifier_Pongo2Templates(t *testing.T) {
	tests := []struct {
		name          string
		statusText    string
		setupRequest  func(*http.Request) *http.Request
		expectedText  string
	}{
		{
			name:       "Simple variable in status text",
			statusText: "{{request.id}}",
			setupRequest: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("req-123", 0)
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedText: "req-123",
		},
		{
			name:       "Access on_request callback result",
			statusText: "{{request.data.on_request_1.status}}",
			setupRequest: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("req-123", 0)
				rd.Data = map[string]any{
					"on_request_1": map[string]any{
						"status": "processed",
					},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedText: "processed",
		},
		{
			name:       "Conditional in status text",
			statusText: "{{#session.auth.data.role}}authorized{{/session.auth.data.role}}{{^session.auth.data.role}}guest{{/session.auth.data.role}}",
			setupRequest: func(r *http.Request) *http.Request {
				rd := requestdata.NewRequestData("req-123", 0)
				rd.SessionData = &reqctx.SessionData{
					ID: "session-123",
					AuthData: &reqctx.AuthData{
						Type: "jwt",
						Data: map[string]any{"role": "admin"},
					},
				}
				ctx := reqctx.SetRequestData(r.Context(), rd)
				return r.WithContext(ctx)
			},
			expectedText: "authorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with context
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req = tt.setupRequest(req)

			// Create response
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("test body")),
				Request:    req,
			}

			// Create response modifier with Mustache template
			modifier := &ResponseModifier{
				Status: &StatusModifications{
					Text: tt.statusText,
				},
			}

			// Apply modifier
			err := modifier.Apply(resp)
			if err != nil {
				t.Fatalf("Apply failed: %v", err)
			}

			// Verify status text was resolved (includes status code prefix)
			if !strings.Contains(resp.Status, tt.expectedText) {
				t.Errorf("Expected status to contain '%s', got '%s'", tt.expectedText, resp.Status)
			}
		})
	}
}

// TestResponseModifier_BodyReplacePongo2 tests body replacement with Mustache templates
func TestResponseModifier_BodyReplacePongo2(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	
	rd := requestdata.NewRequestData("req-123", 0)
	rd.Data = map[string]any{
		"on_request_1": map[string]any{
			"message": "Hello from API",
		},
	}
	rd.Snapshot = &reqctx.RequestSnapshot{
		Method:   "POST",
		Body:     []byte(`{"user": "john"}`),
		IsJSON:   true,
		BodyJSON: map[string]any{"user": "john"},
	}

	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("original body")),
		Request:    req,
	}

	modifier := &ResponseModifier{
		Body: &BodyModifications{
			Replace: `{"result": "{{request.data.on_request_1.message}}", "original_user": "{{request.body_json.user}}"}`,
		},
	}

	err := modifier.Apply(resp)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Read and verify body
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	expectedBody := `{"result": "Hello from API", "original_user": "john"}`
	if bodyStr != expectedBody {
		t.Errorf("Expected body '%s', got '%s'", expectedBody, bodyStr)
	}
}

