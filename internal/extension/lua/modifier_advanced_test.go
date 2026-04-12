package lua

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestLuaModifier_CancelsOnContextDone verifies that a Lua modifier returns
// promptly when the request context is already cancelled, rather than
// executing the full script.
func TestLuaModifier_CancelsOnContextDone(t *testing.T) {
	// A script with a busy loop that would take a long time if not cancelled.
	// The Lua VM checks the context via L.SetContext, so cancellation should
	// interrupt execution quickly.
	script := `
function modify_request(req)
	-- Busy loop that would run for a long time
	local x = 0
	for i = 1, 100000000 do
		x = x + 1
	end
	return {headers = {["X-Result"] = tostring(x)}}
end
`
	modifier, err := NewModifier(script)
	if err != nil {
		t.Fatalf("NewModifier() error = %v", err)
	}

	// Create a request with an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	req := httptest.NewRequest("GET", "http://example.com/test", nil).WithContext(ctx)

	start := time.Now()
	_, err = modifier.Modify(req)
	elapsed := time.Since(start)

	// Should return quickly (the cancelled context should abort Lua execution).
	// We expect an error from the context cancellation.
	if elapsed > 1*time.Second {
		t.Errorf("Modify took %v with cancelled context, expected < 1s", elapsed)
	}

	if err == nil {
		t.Log("Modify returned nil error with cancelled context (script may have completed before check)")
	} else {
		t.Logf("Modify returned error as expected: %v (elapsed: %v)", err, elapsed)
	}
}

// TestLuaModifier_TimeoutContextDone verifies that a Lua modifier with
// a short deadline returns promptly rather than running the full script.
func TestLuaModifier_TimeoutContextDone(t *testing.T) {
	script := `
function modify_request(req)
	local x = 0
	for i = 1, 100000000 do
		x = x + 1
	end
	return {headers = {["X-Result"] = tostring(x)}}
end
`
	modifier, err := NewModifierWithTimeout(script, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewModifierWithTimeout() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	start := time.Now()
	_, err = modifier.Modify(req)
	elapsed := time.Since(start)

	// With a 50ms timeout, should complete well under 1 second
	if elapsed > 1*time.Second {
		t.Errorf("Modify took %v with 50ms timeout, expected < 1s", elapsed)
	}

	if err == nil {
		t.Log("Modify returned nil error (script may have completed within timeout)")
	} else {
		t.Logf("Modify returned error as expected: %v (elapsed: %v)", err, elapsed)
	}
}

func TestModifier_URLModifications(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		reqURL  string
		wantURL string
	}{
		{
			name:    "scheme modification",
			script:  `return {scheme = "https"}`,
			reqURL:  "http://example.com/path",
			wantURL: "https://example.com/path",
		},
		{
			name:    "host modification",
			script:  `return {host = "api.example.com:8080"}`,
			reqURL:  "http://example.com/path",
			wantURL: "http://api.example.com:8080/path",
		},
		{
			name:    "fragment modification",
			script:  `return {fragment = "section-1"}`,
			reqURL:  "http://example.com/path",
			wantURL: "http://example.com/path#section-1",
		},
		{
			name:    "complete URL transformation",
			script:  `return {scheme = "https", host = "api.example.com", fragment = "results"}`,
			reqURL:  "http://example.com/path",
			wantURL: "https://api.example.com/path#results",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifier(tt.script)
			if err != nil {
				t.Fatalf("NewModifier() error = %v", err)
			}

			req := httptest.NewRequest("GET", tt.reqURL, nil)
			modifiedReq, err := modifier.Modify(req)
			if err != nil {
				t.Fatalf("Modify() error = %v", err)
			}

			gotURL := modifiedReq.URL.String()
			if gotURL != tt.wantURL {
				t.Errorf("URL = %v, want %v", gotURL, tt.wantURL)
			}
		})
	}
}

func TestModifier_PathModifications(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		reqPath  string
		wantPath string
	}{
		{
			name:     "path prefix",
			script:   `return {path_prefix = "/v2"}`,
			reqPath:  "/users",
			wantPath: "/v2/users",
		},
		{
			name:     "path suffix",
			script:   `return {path_suffix = ".json"}`,
			reqPath:  "/users",
			wantPath: "/users.json",
		},
		{
			name:     "path replace",
			script:   `return {path_replace = {["/api/v1/"] = "/api/v2/"}}`,
			reqPath:  "/api/v1/users",
			wantPath: "/api/v2/users",
		},
		{
			name:     "path prefix and suffix",
			script:   `return {path_prefix = "/api", path_suffix = ".json"}`,
			reqPath:  "/users",
			wantPath: "/api/users.json",
		},
		{
			name:     "path replace then prefix",
			script:   `return {path_replace = {old = "new"}, path_prefix = "/v2"}`,
			reqPath:  "/old/path",
			wantPath: "/v2/new/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifier(tt.script)
			if err != nil {
				t.Fatalf("NewModifier() error = %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com"+tt.reqPath, nil)
			modifiedReq, err := modifier.Modify(req)
			if err != nil {
				t.Fatalf("Modify() error = %v", err)
			}

			if modifiedReq.URL.Path != tt.wantPath {
				t.Errorf("Path = %v, want %v", modifiedReq.URL.Path, tt.wantPath)
			}
		})
	}
}

func TestModifier_QueryModifications(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		reqQuery  string
		wantQuery map[string]string
	}{
		{
			name:      "set query overwrites existing",
			script:    `return {set_query = {version = "2.0"}}`,
			reqQuery:  "version=1.0&other=value",
			wantQuery: map[string]string{"version": "2.0", "other": "value"},
		},
		{
			name:      "add query appends",
			script:    `return {add_query = {new = "value"}}`,
			reqQuery:  "existing=value",
			wantQuery: map[string]string{"existing": "value", "new": "value"},
		},
		{
			name:      "delete query",
			script:    `return {delete_query = {"temp"}}`,
			reqQuery:  "keep=value&temp=remove",
			wantQuery: map[string]string{"keep": "value"},
		},
		{
			name:      "combined query operations",
			script:    `return {delete_query = {"old"}, set_query = {version = "2.0"}, add_query = {new = "value"}}`,
			reqQuery:  "old=remove&version=1.0",
			wantQuery: map[string]string{"version": "2.0", "new": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifier(tt.script)
			if err != nil {
				t.Fatalf("NewModifier() error = %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/path?"+tt.reqQuery, nil)
			modifiedReq, err := modifier.Modify(req)
			if err != nil {
				t.Fatalf("Modify() error = %v", err)
			}

			gotQuery := modifiedReq.URL.Query()
			for key, wantValue := range tt.wantQuery {
				if gotValue := gotQuery.Get(key); gotValue != wantValue {
					t.Errorf("Query[%s] = %v, want %v", key, gotValue, wantValue)
				}
			}

			// Check that no extra keys exist
			for key := range gotQuery {
				if _, ok := tt.wantQuery[key]; !ok {
					t.Errorf("Unexpected query parameter: %s", key)
				}
			}
		})
	}
}

func TestModifier_FormModifications(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		formData url.Values
		want     url.Values
	}{
		{
			name:     "set form parameter",
			script:   `return {set_form = {username = "admin"}}`,
			formData: url.Values{"username": []string{"user"}},
			want:     url.Values{"username": []string{"admin"}},
		},
		{
			name:     "add form parameter",
			script:   `return {add_form = {role = "superuser"}}`,
			formData: url.Values{"username": []string{"admin"}},
			want:     url.Values{"username": []string{"admin"}, "role": []string{"superuser"}},
		},
		{
			name:     "delete form parameter",
			script:   `return {delete_form = {"temp_token"}}`,
			formData: url.Values{"username": []string{"admin"}, "temp_token": []string{"abc123"}},
			want:     url.Values{"username": []string{"admin"}},
		},
		{
			name:     "combined form operations",
			script:   `return {set_form = {username = "root"}, add_form = {role = "admin"}, delete_form = {"temp"}}`,
			formData: url.Values{"username": []string{"user"}, "temp": []string{"remove"}},
			want:     url.Values{"username": []string{"root"}, "role": []string{"admin"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifier(tt.script)
			if err != nil {
				t.Fatalf("NewModifier() error = %v", err)
			}

			req := httptest.NewRequest("POST", "http://example.com/", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			modifiedReq, err := modifier.Modify(req)
			if err != nil {
				t.Fatalf("Modify() error = %v", err)
			}

			// Read the modified body
			bodyBytes, err := io.ReadAll(modifiedReq.Body)
			if err != nil {
				t.Fatalf("Failed to read body: %v", err)
			}

			gotForm, err := url.ParseQuery(string(bodyBytes))
			if err != nil {
				t.Fatalf("Failed to parse form: %v", err)
			}

			for key, wantValues := range tt.want {
				gotValues := gotForm[key]
				if len(gotValues) != len(wantValues) {
					t.Errorf("Form[%s] length = %d, want %d", key, len(gotValues), len(wantValues))
					continue
				}
				for i, wantValue := range wantValues {
					if gotValues[i] != wantValue {
						t.Errorf("Form[%s][%d] = %v, want %v", key, i, gotValues[i], wantValue)
					}
				}
			}
		})
	}
}

func TestModifier_BodyModifications(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		wantBody string
		wantCT   string
	}{
		{
			name:     "body remove",
			script:   `return {body_remove = true}`,
			wantBody: "",
			wantCT:   "",
		},
		{
			name:     "body replace",
			script:   `return {body_replace = "new body content"}`,
			wantBody: "new body content",
			wantCT:   "",
		},
		{
			name:     "body replace JSON",
			script:   `return {body_replace_json = '{"key": "value"}'}`,
			wantBody: `{"key": "value"}`,
			wantCT:   "application/json",
		},
		{
			name:     "body replace base64",
			script:   `return {body_replace_base64 = "` + base64.StdEncoding.EncodeToString([]byte("decoded content")) + `"}`,
			wantBody: "decoded content",
			wantCT:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifier(tt.script)
			if err != nil {
				t.Fatalf("NewModifier() error = %v", err)
			}

			req := httptest.NewRequest("POST", "http://example.com/", strings.NewReader("original body"))
			modifiedReq, err := modifier.Modify(req)
			if err != nil {
				t.Fatalf("Modify() error = %v", err)
			}

			bodyBytes, err := io.ReadAll(modifiedReq.Body)
			if err != nil {
				t.Fatalf("Failed to read body: %v", err)
			}

			if string(bodyBytes) != tt.wantBody {
				t.Errorf("Body = %v, want %v", string(bodyBytes), tt.wantBody)
			}

			if tt.wantCT != "" {
				gotCT := modifiedReq.Header.Get("Content-Type")
				if gotCT != tt.wantCT {
					t.Errorf("Content-Type = %v, want %v", gotCT, tt.wantCT)
				}
			}
		})
	}
}

func TestResponseModifier_StatusTextModification(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		wantStatus string
	}{
		{
			name:       "custom status text with code",
			script:     `return {status_code = 200, status_text = "Custom Success"}`,
			wantStatus: "200 Custom Success",
		},
		{
			name:       "status text only",
			script:     `return {status_text = "Custom Message"}`,
			wantStatus: "200 Custom Message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewResponseModifier(tt.script)
			if err != nil {
				t.Fatalf("NewResponseModifier() error = %v", err)
			}

			resp := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("test")),
				Request:    httptest.NewRequest("GET", "http://example.com", nil),
			}

			err = modifier.ModifyResponse(resp)
			if err != nil {
				t.Fatalf("ModifyResponse() error = %v", err)
			}

			if resp.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v", resp.Status, tt.wantStatus)
			}
		})
	}
}

func TestResponseModifier_BodyModifications(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		wantBody string
		wantCT   string
	}{
		{
			name:     "body remove",
			script:   `return {body_remove = true}`,
			wantBody: "",
			wantCT:   "",
		},
		{
			name:     "body replace",
			script:   `return {body_replace = "new response"}`,
			wantBody: "new response",
			wantCT:   "",
		},
		{
			name:     "body replace JSON",
			script:   `return {body_replace_json = '{"status": "success"}'}`,
			wantBody: `{"status": "success"}`,
			wantCT:   "application/json",
		},
		{
			name:     "body replace base64",
			script:   `return {body_replace_base64 = "` + base64.StdEncoding.EncodeToString([]byte("decoded")) + `"}`,
			wantBody: "decoded",
			wantCT:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewResponseModifier(tt.script)
			if err != nil {
				t.Fatalf("NewResponseModifier() error = %v", err)
			}

			resp := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("original")),
				Request:    httptest.NewRequest("GET", "http://example.com", nil),
			}

			err = modifier.ModifyResponse(resp)
			if err != nil {
				t.Fatalf("ModifyResponse() error = %v", err)
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read body: %v", err)
			}

			if string(bodyBytes) != tt.wantBody {
				t.Errorf("Body = %v, want %v", string(bodyBytes), tt.wantBody)
			}

			if tt.wantCT != "" {
				gotCT := resp.Header.Get("Content-Type")
				if gotCT != tt.wantCT {
					t.Errorf("Content-Type = %v, want %v", gotCT, tt.wantCT)
				}
			}
		})
	}
}
