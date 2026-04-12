package modifier

import (
	"io"
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestResponseModifier_TemplateVariables_Status(t *testing.T) {
	tests := []struct {
		name           string
		statusText     string
		requestData    *reqctx.RequestData
		expectedStatus string
	}{
		{
			name:       "Status text with request.id",
			statusText: "Error {{request.id}}",
			requestData: &reqctx.RequestData{
				ID: "req-123456",
			},
			expectedStatus: "500 Error req-123456",
		},
		{
			name:       "Status text with request.remote_addr",
			statusText: "Blocked {{request.remote_addr}}",
			requestData: &reqctx.RequestData{
				ID: "req-789",
			},
			expectedStatus: "403 Blocked 192.168.1.100",
		},
		{
			name:       "Status text with auth.data",
			statusText: "Unauthorized {{session.auth.data.user_id}}",
			requestData: &reqctx.RequestData{
				ID: "req-456",
				SessionData: &reqctx.SessionData{
					AuthData: &reqctx.AuthData{
						Data: map[string]any{
							"user_id": "user-123",
						},
					},
				},
			},
			expectedStatus: "401 Unauthorized user-123",
		},
		{
			name:       "Status text with session.data",
			statusText: "Session {{session.data.session_id}}",
			requestData: &reqctx.RequestData{
				ID: "req-789",
				SessionData: &reqctx.SessionData{
					Data: map[string]any{
						"session_id": "sess-abc",
					},
				},
			},
			expectedStatus: "200 Session sess-abc",
		},
		{
			name:       "Status text with config",
			statusText: "Config {{origin.params.app_version}}",
			requestData: &reqctx.RequestData{
				ID: "req-999",
				OriginCtx: &reqctx.OriginContext{
					Params: map[string]any{
						"app_version": "1.2.3",
					},
				},
			},
			expectedStatus: "200 Config 1.2.3",
		},
		{
			name:       "Status text with secrets",
			statusText: "Secret {{secrets.api_key}}",
			requestData: &reqctx.RequestData{
				ID: "req-111",
				OriginCtx: &reqctx.OriginContext{
					Secrets: map[string]string{
						"api_key": "key-xyz",
					},
				},
			},
			expectedStatus: "200 Secret key-xyz",
		},
		{
			name:       "Status text with multiple variables",
			statusText: "{{request.id}} - {{session.auth.data.user_id}}",
			requestData: &reqctx.RequestData{
				ID: "req-multi",
				SessionData: &reqctx.SessionData{
					AuthData: &reqctx.AuthData{
						Data: map[string]any{
							"user_id": "user-multi",
						},
					},
				},
			},
			expectedStatus: "200 req-multi - user-multi",
		},
		{
			name:       "Status text with missing variable",
			statusText: "Missing {{request.data.nonexistent}}",
			requestData: &reqctx.RequestData{
				ID: "req-missing",
			},
			expectedStatus: "200 Missing ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with RequestData in context
			req := &http.Request{}
			ctx := reqctx.SetRequestData(req.Context(), tt.requestData)
			req = req.WithContext(ctx)

			// Set RemoteAddr for remote_addr tests
			if tt.name == "Status text with request.remote_addr" {
				req.RemoteAddr = "192.168.1.100:8080"
			}

			// Create response with request
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Request:    req,
				Header:     make(http.Header),
			}

			// Create modifier with status text
			statusCode := 200
			if tt.name == "Status text with request.id" {
				statusCode = 500
			} else if tt.name == "Status text with request.remote_addr" {
				statusCode = 403
			} else if tt.name == "Status text with auth.data" {
				statusCode = 401
			}

			modifier := &ResponseModifier{
				Status: &StatusModifications{
					Code: statusCode,
					Text: tt.statusText,
				},
			}

			// Apply modifier
			err := modifier.Apply(resp)
			if err != nil {
				t.Fatalf("Apply error: %v", err)
			}

			// Check status
			if resp.Status != tt.expectedStatus {
				t.Errorf("Expected status %q, got %q", tt.expectedStatus, resp.Status)
			}
		})
	}
}

func TestResponseModifier_TemplateVariables_Headers(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		requestData    *reqctx.RequestData
		expectedHeader http.Header
	}{
		{
			name: "Headers with request.id",
			headers: map[string]string{
				"X-Request-ID": "{{request.id}}",
			},
			requestData: &reqctx.RequestData{
				ID: "req-header-123",
			},
			expectedHeader: http.Header{
				"X-Request-ID": []string{"req-header-123"},
			},
		},
		{
			name: "Headers with auth.data",
			headers: map[string]string{
				"X-User-ID": "{{session.auth.data.user_id}}",
			},
			requestData: &reqctx.RequestData{
				ID: "req-auth",
				SessionData: &reqctx.SessionData{
					AuthData: &reqctx.AuthData{
						Data: map[string]any{
							"user_id": "user-header-456",
						},
					},
				},
			},
			expectedHeader: http.Header{
				"X-User-ID": []string{"user-header-456"},
			},
		},
		{
			name: "Headers with session.data",
			headers: map[string]string{
				"X-Session-Theme": "{{session.data.theme}}",
			},
			requestData: &reqctx.RequestData{
				ID: "req-session",
				SessionData: &reqctx.SessionData{
					Data: map[string]any{
						"theme": "dark",
					},
				},
			},
			expectedHeader: http.Header{
				"X-Session-Theme": []string{"dark"},
			},
		},
		{
			name: "Headers with multiple variables",
			headers: map[string]string{
				"X-Request-ID": "{{request.id}}",
				"X-User-ID":    "{{session.auth.data.user_id}}",
				"X-Config-Env": "{{origin.params.environment}}",
			},
			requestData: &reqctx.RequestData{
				ID: "req-multi-header",
				SessionData: &reqctx.SessionData{
					AuthData: &reqctx.AuthData{
						Data: map[string]any{
							"user_id": "user-multi",
						},
					},
				},
				OriginCtx: &reqctx.OriginContext{
					Params: map[string]any{
						"environment": "production",
					},
				},
			},
			expectedHeader: http.Header{
				"X-Request-ID": []string{"req-multi-header"},
				"X-User-ID":    []string{"user-multi"},
				"X-Config-Env": []string{"production"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with RequestData in context
			req := &http.Request{}
			ctx := reqctx.SetRequestData(req.Context(), tt.requestData)
			req = req.WithContext(ctx)

			// Create response with request
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Request:    req,
				Header:     make(http.Header),
			}

			// Create modifier with headers
			modifier := &ResponseModifier{
				Headers: &HeaderModifications{
					Set: tt.headers,
				},
			}

			// Apply modifier
			err := modifier.Apply(resp)
			if err != nil {
				t.Fatalf("Apply error: %v", err)
			}

			// Check headers
			for key, expectedValues := range tt.expectedHeader {
				actualValues := resp.Header[key]
				if len(actualValues) == 0 {
					// Try canonical header name (HTTP headers are case-insensitive)
					actualValues = resp.Header[http.CanonicalHeaderKey(key)]
				}
				if len(actualValues) != len(expectedValues) {
					t.Errorf("Header %s: expected %d values, got %d. All headers: %v", key, len(expectedValues), len(actualValues), resp.Header)
					continue
				}
				if actualValues[0] != expectedValues[0] {
					t.Errorf("Header %s: expected %q, got %q", key, expectedValues[0], actualValues[0])
				}
			}
		})
	}
}

func TestResponseModifier_TemplateVariables_Body(t *testing.T) {
	tests := []struct {
		name         string
		bodyReplace  string
		requestData  *reqctx.RequestData
		expectedBody string
	}{
		{
			name:        "Body with request.id",
			bodyReplace: "Request ID: {{request.id}}",
			requestData: &reqctx.RequestData{
				ID: "req-body-123",
			},
			expectedBody: "Request ID: req-body-123",
		},
		{
			name:        "Body with auth.data",
			bodyReplace: "User: {{session.auth.data.user_id}}",
			requestData: &reqctx.RequestData{
				ID: "req-body-auth",
				SessionData: &reqctx.SessionData{
					AuthData: &reqctx.AuthData{
						Data: map[string]any{
							"user_id": "user-body-456",
						},
					},
				},
			},
			expectedBody: "User: user-body-456",
		},
		{
			name:        "Body with session.data",
			bodyReplace: "Session: {{session.data.session_id}}",
			requestData: &reqctx.RequestData{
				ID: "req-body-session",
				SessionData: &reqctx.SessionData{
					Data: map[string]any{
						"session_id": "sess-body-789",
					},
				},
			},
			expectedBody: "Session: sess-body-789",
		},
		{
			name:        "Body with config",
			bodyReplace: "Config: {{origin.params.app_version}}",
			requestData: &reqctx.RequestData{
				ID: "req-body-config",
				OriginCtx: &reqctx.OriginContext{
					Params: map[string]any{
						"app_version": "2.0.0",
					},
				},
			},
			expectedBody: "Config: 2.0.0",
		},
		{
			name:        "Body with secrets",
			bodyReplace: "Secret: {{secrets.api_key}}",
			requestData: &reqctx.RequestData{
				ID: "req-body-secret",
				OriginCtx: &reqctx.OriginContext{
					Secrets: map[string]string{
						"api_key": "aK7mR9pL2xQ4vN8",
					},
				},
			},
			expectedBody: "Secret: aK7mR9pL2xQ4vN8",
		},
		{
			name:        "Body with multiple variables",
			bodyReplace: "Request: {{request.id}}, User: {{session.auth.data.user_id}}, Config: {{origin.params.environment}}",
			requestData: &reqctx.RequestData{
				ID: "req-body-multi",
				SessionData: &reqctx.SessionData{
					AuthData: &reqctx.AuthData{
						Data: map[string]any{
							"user_id": "user-body-multi",
						},
					},
				},
				OriginCtx: &reqctx.OriginContext{
					Params: map[string]any{
						"environment": "staging",
					},
				},
			},
			expectedBody: "Request: req-body-multi, User: user-body-multi, Config: staging",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with RequestData in context
			req := &http.Request{}
			ctx := reqctx.SetRequestData(req.Context(), tt.requestData)
			req = req.WithContext(ctx)

			// Create response with request and body
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Request:    req,
				Header:     make(http.Header),
				Body:       nil, // Will be set by modifier
			}

			// Create modifier with body replacement
			modifier := &ResponseModifier{
				Body: &BodyModifications{
					Replace: tt.bodyReplace,
				},
			}

			// Apply modifier
			err := modifier.Apply(resp)
			if err != nil {
				t.Fatalf("Apply error: %v", err)
			}

			// Read body
			if resp.Body == nil {
				t.Fatal("Response body is nil")
			}
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}

			// Check body
			actualBody := string(bodyBytes)
			if actualBody != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, actualBody)
			}
		})
	}
}
