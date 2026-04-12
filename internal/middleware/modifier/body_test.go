package modifier

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/rule"
)

func TestRequestModifier_BodyModifications(t *testing.T) {
	tests := []struct {
		name         string
		modifier     RequestModifier
		req          *http.Request
		expectedBody string
		shouldModify bool
	}{
		{
			name: "Remove body",
			modifier: RequestModifier{
				Body: &BodyModifications{
					Remove: true,
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original body", t),
			expectedBody: "",
			shouldModify: true,
		},
		{
			name: "Replace body with string",
			modifier: RequestModifier{
				Body: &BodyModifications{
					Replace: "new body content",
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original body", t),
			expectedBody: "new body content",
			shouldModify: true,
		},
		{
			name: "Replace body with base64",
			modifier: RequestModifier{
				Body: &BodyModifications{
					ReplaceBase64: base64.StdEncoding.EncodeToString([]byte("base64 decoded content")),
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original body", t),
			expectedBody: "base64 decoded content",
			shouldModify: true,
		},
		{
			name: "Replace body with JSON",
			modifier: RequestModifier{
				Body: &BodyModifications{
					ReplaceJSON: json.RawMessage(`{"key":"value","number":42}`),
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original body", t),
			expectedBody: `{"key":"value","number":42}`,
			shouldModify: true,
		},
		{
			name: "Replace body with JSON validates",
			modifier: RequestModifier{
				Body: &BodyModifications{
					ReplaceJSON: json.RawMessage(`{"key": "value", "number": 42}`),
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original body", t),
			expectedBody: `{"key": "value", "number": 42}`, // RawMessage preserves original format
			shouldModify: true,
		},
		{
			name: "Body modification with matching rule",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/match"}}},
				Body: &BodyModifications{
					Replace: "matched",
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com/match", "original", t),
			expectedBody: "matched",
			shouldModify: true,
		},
		{
			name: "Body modification with non-matching rule",
			modifier: RequestModifier{
				Rules: rule.RequestRules{{URL: &rule.URLConditions{Exact: "https://example.com/match"}}},
				Body: &BodyModifications{
					Replace: "should not apply",
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com/no-match", "original", t),
			expectedBody: "original",
			shouldModify: false,
		},
		{
			name: "Replace takes precedence over Remove when both set",
			modifier: RequestModifier{
				Body: &BodyModifications{
					Remove:  true,
					Replace: "replaced content",
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original", t),
			expectedBody: "replaced content",
			shouldModify: true,
		},
		{
			name: "ReplaceBase64 takes precedence over ReplaceJSON when both set",
			modifier: RequestModifier{
				Body: &BodyModifications{
					ReplaceJSON:   json.RawMessage(`{"key":"value"}`),
					ReplaceBase64: base64.StdEncoding.EncodeToString([]byte("base64 content")),
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original", t),
			expectedBody: "base64 content",
			shouldModify: true,
		},
		{
			name: "ReplaceJSON takes precedence over Replace when both set",
			modifier: RequestModifier{
				Body: &BodyModifications{
					Replace:     "string content",
					ReplaceJSON: json.RawMessage(`{"key":"value"}`),
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "original", t),
			expectedBody: `{"key":"value"}`,
			shouldModify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalBody := readRequestBody(tt.req, t)
			err := tt.modifier.Apply(tt.req)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			resultBody := readRequestBody(tt.req, t)
			if resultBody != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, resultBody)
			}

			if tt.shouldModify && resultBody == originalBody {
				t.Errorf("Expected body to be modified, but it remained %q", originalBody)
			}
			if !tt.shouldModify && resultBody != originalBody {
				t.Errorf("Expected body to remain %q, but got %q", originalBody, resultBody)
			}

			// Verify Content-Length header
			if len(tt.expectedBody) > 0 {
				contentLength := tt.req.Header.Get("Content-Length")
				if contentLength != fmt.Sprintf("%d", len(tt.expectedBody)) {
					t.Errorf("Expected Content-Length %d, got %s", len(tt.expectedBody), contentLength)
				}
			}

			// Verify Content-Type header for JSON (only if JSON was actually applied)
			if tt.modifier.Body != nil && len(tt.modifier.Body.ReplaceJSON) > 0 {
				// Only check Content-Type if ReplaceJSON was actually used (not overridden by ReplaceBase64)
				if tt.modifier.Body.ReplaceBase64 == "" {
					contentType := tt.req.Header.Get("Content-Type")
					if contentType != "application/json" {
						t.Errorf("Expected Content-Type application/json, got %s", contentType)
					}
				}
			}
		})
	}
}

func TestRequestModifier_FormModifications(t *testing.T) {
	tests := []struct {
		name          string
		modifier      RequestModifier
		req           *http.Request
		expectedForm  map[string]string
		shouldModify  bool
		expectedError bool
	}{
		{
			name: "Set form parameter (overwrites specified keys)",
			modifier: RequestModifier{
				Form: &FormModifications{
					Set: map[string]string{"key2": "newvalue"},
				},
			},
			req: mustCreateFormRequest("POST", "https://example.com", "key1=value1&key2=oldvalue", t),
			expectedForm: map[string]string{
				"key1": "value1",
				"key2": "newvalue",
			},
			shouldModify: true,
		},
		{
			name: "Add form parameter",
			modifier: RequestModifier{
				Form: &FormModifications{
					Add: map[string]string{"newkey": "newvalue"},
				},
			},
			req: mustCreateFormRequest("POST", "https://example.com", "key1=value1", t),
			expectedForm: map[string]string{
				"key1":   "value1",
				"newkey": "newvalue",
			},
			shouldModify: true,
		},
		{
			name: "Delete form parameter",
			modifier: RequestModifier{
				Form: &FormModifications{
					Delete: []string{"key1"},
				},
			},
			req: mustCreateFormRequest("POST", "https://example.com", "key1=value1&key2=value2", t),
			expectedForm: map[string]string{
				"key2": "value2",
			},
			shouldModify: true,
		},
		{
			name: "Delete, Set, Add in correct order",
			modifier: RequestModifier{
				Form: &FormModifications{
					Delete: []string{"oldkey"},
					Set:    map[string]string{"setkey": "setvalue"},
					Add:    map[string]string{"addkey": "addvalue"},
				},
			},
			req: mustCreateFormRequest("POST", "https://example.com", "oldkey=oldvalue&setkey=oldset", t),
			expectedForm: map[string]string{
				"setkey": "setvalue",
				"addkey": "addvalue",
			},
			shouldModify: true,
		},
		{
			name: "Form modification with non-form content-type",
			modifier: RequestModifier{
				Form: &FormModifications{
					Set: map[string]string{"key": "value"},
				},
			},
			req:          mustCreateRequestWithBody("POST", "https://example.com", "", t),
			expectedForm: map[string]string{"key": "value"}, // Should still create form
			shouldModify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.modifier.Apply(tt.req)
			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Parse the form from body
			bodyBytes := readRequestBody(tt.req, t)
			if bodyBytes != "" {
				form, err := url.ParseQuery(bodyBytes)
				if err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}

				// Check expected form values
				for key, expectedValue := range tt.expectedForm {
					actualValues := form[key]
					if len(actualValues) == 0 {
						t.Errorf("Expected form parameter %s, but it was not present", key)
						continue
					}
					// Check if expected value is in the values (form can have multiple values)
					found := false
					for _, v := range actualValues {
						if v == expectedValue {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected form parameter %s=%s, got %v", key, expectedValue, actualValues)
					}
				}

				// Check no unexpected parameters
				for key := range form {
					if _, exists := tt.expectedForm[key]; !exists {
						t.Errorf("Unexpected form parameter present: %s", key)
					}
				}
			}
		})
	}
}

func TestResponseModifier_BodyModifications(t *testing.T) {
	tests := []struct {
		name         string
		modifier     ResponseModifier
		resp         *http.Response
		expectedBody string
		shouldModify bool
	}{
		{
			name: "Remove body",
			modifier: ResponseModifier{
				Body: &BodyModifications{
					Remove: true,
				},
			},
			resp:         mustCreateResponseWithBody(200, "original body", t),
			expectedBody: "",
			shouldModify: true,
		},
		{
			name: "Replace body with string",
			modifier: ResponseModifier{
				Body: &BodyModifications{
					Replace: "new body content",
				},
			},
			resp:         mustCreateResponseWithBody(200, "original body", t),
			expectedBody: "new body content",
			shouldModify: true,
		},
		{
			name: "Replace body with base64",
			modifier: ResponseModifier{
				Body: &BodyModifications{
					ReplaceBase64: base64.StdEncoding.EncodeToString([]byte("base64 decoded content")),
				},
			},
			resp:         mustCreateResponseWithBody(200, "original body", t),
			expectedBody: "base64 decoded content",
			shouldModify: true,
		},
		{
			name: "Replace body with JSON",
			modifier: ResponseModifier{
				Body: &BodyModifications{
					ReplaceJSON: json.RawMessage(`{"key":"value","number":42}`),
				},
			},
			resp:         mustCreateResponseWithBody(200, "original body", t),
			expectedBody: `{"key":"value","number":42}`,
			shouldModify: true,
		},
		{
			name: "Replace body with JSON validates",
			modifier: ResponseModifier{
				Body: &BodyModifications{
					ReplaceJSON: json.RawMessage(`{"key": "value", "number": 42}`),
				},
			},
			resp:         mustCreateResponseWithBody(200, "original body", t),
			expectedBody: `{"key": "value", "number": 42}`, // RawMessage preserves original format
			shouldModify: true,
		},
		{
			name: "Body modification with matching rule",
			modifier: ResponseModifier{
				Rules: rule.ResponseRules{{Status: &rule.StatusConditions{Code: 200}}},
				Body: &BodyModifications{
					Replace: "matched",
				},
			},
			resp:         mustCreateResponseWithBody(200, "original", t),
			expectedBody: "matched",
			shouldModify: true,
		},
		{
			name: "Body modification with non-matching rule",
			modifier: ResponseModifier{
				Rules: rule.ResponseRules{{Status: &rule.StatusConditions{Code: 200}}},
				Body: &BodyModifications{
					Replace: "should not apply",
				},
			},
			resp:         mustCreateResponseWithBody(404, "original", t),
			expectedBody: "original",
			shouldModify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalBody := readResponseBody(tt.resp, t)
			err := tt.modifier.Apply(tt.resp)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			resultBody := readResponseBody(tt.resp, t)
			if resultBody != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, resultBody)
			}

			if tt.shouldModify && resultBody == originalBody {
				t.Errorf("Expected body to be modified, but it remained %q", originalBody)
			}
			if !tt.shouldModify && resultBody != originalBody {
				t.Errorf("Expected body to remain %q, but got %q", originalBody, resultBody)
			}

			// Verify Content-Type header for JSON (only if JSON was actually applied)
			if tt.modifier.Body != nil && len(tt.modifier.Body.ReplaceJSON) > 0 {
				// Only check Content-Type if ReplaceJSON was actually used (not overridden by ReplaceBase64)
				if tt.modifier.Body.ReplaceBase64 == "" {
					contentType := tt.resp.Header.Get("Content-Type")
					if contentType != "application/json" {
						t.Errorf("Expected Content-Type application/json, got %s", contentType)
					}
				}
			}
		})
	}
}

func TestRequestModifier_BodyModifications_InvalidJSON(t *testing.T) {
	modifier := RequestModifier{
		Body: &BodyModifications{
			ReplaceJSON: json.RawMessage(`{"invalid": json}`),
		},
	}
	req := mustCreateRequestWithBody("POST", "https://example.com", "original", t)

	err := modifier.Apply(req)
	if err == nil {
		t.Error("Expected error for invalid JSON, but got none")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("Expected error about invalid JSON, got: %v", err)
	}
}

func TestResponseModifier_BodyModifications_InvalidJSON(t *testing.T) {
	modifier := ResponseModifier{
		Body: &BodyModifications{
			ReplaceJSON: json.RawMessage(`{"invalid": json}`),
		},
	}
	resp := mustCreateResponseWithBody(200, "original", t)

	err := modifier.Apply(resp)
	if err == nil {
		t.Error("Expected error for invalid JSON, but got none")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("Expected error about invalid JSON, got: %v", err)
	}
}

// Helper functions

func mustCreateRequestWithBody(method, rawURL, body string, t *testing.T) *http.Request {
	t.Helper()
	req := mustCreateRequest(method, rawURL, t)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return req
}

func mustCreateFormRequest(method, rawURL, formData string, t *testing.T) *http.Request {
	t.Helper()
	req := mustCreateRequest(method, rawURL, t)
	req.Body = io.NopCloser(strings.NewReader(formData))
	req.ContentLength = int64(len(formData))
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(formData)))
	return req
}

func mustCreateResponseWithBody(statusCode int, body string, t *testing.T) *http.Response {
	t.Helper()
	recorder := httptest.NewRecorder()
	recorder.WriteHeader(statusCode)
	recorder.WriteString(body)
	resp := recorder.Result()
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp
}

func readRequestBody(req *http.Request, t *testing.T) string {
	t.Helper()
	if req.Body == nil {
		return ""
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read request body: %v", err)
	}
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return string(bodyBytes)
}

func readResponseBody(resp *http.Response, t *testing.T) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return string(bodyBytes)
}
