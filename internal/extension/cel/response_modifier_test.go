package cel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestNewResponseModifier(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name: "add headers",
			expr: `{
				"add_headers": {
					"X-Custom": "value"
				}
			}`,
			wantErr: false,
		},
		{
			name: "set headers",
			expr: `{
				"set_headers": {
					"X-Custom": "value"
				}
			}`,
			wantErr: false,
		},
		{
			name: "delete headers",
			expr: `{
				"delete_headers": ["X-Old-Header"]
			}`,
			wantErr: false,
		},
		{
			name: "set status code",
			expr: `{
				"status_code": 200
			}`,
			wantErr: false,
		},
		{
			name: "set body",
			expr: `{
				"body": "new body"
			}`,
			wantErr: false,
		},
		{
			name: "syntax error",
			expr: `{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewResponseModifier(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewResponseModifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResponseModifierAddHeaders(t *testing.T) {
	expr := `{
		"add_headers": {
			"X-Custom-1": "value1",
			"X-Custom-2": "value2"
		}
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.Header.Get("X-Custom-1") != "value1" {
		t.Errorf("Expected X-Custom-1 = value1, got %s", resp.Header.Get("X-Custom-1"))
	}

	if resp.Header.Get("X-Custom-2") != "value2" {
		t.Errorf("Expected X-Custom-2 = value2, got %s", resp.Header.Get("X-Custom-2"))
	}
}

func TestResponseModifierSetHeaders(t *testing.T) {
	expr := `{
		"set_headers": {
			"Content-Type": "application/json"
		}
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "text/html")

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type = application/json, got %s", resp.Header.Get("Content-Type"))
	}
}

func TestResponseModifierDeleteHeaders(t *testing.T) {
	expr := `{
		"delete_headers": ["X-Remove-Me"]
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}
	resp.Header.Set("X-Remove-Me", "value")
	resp.Header.Set("X-Keep-Me", "value")

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.Header.Get("X-Remove-Me") != "" {
		t.Errorf("Expected X-Remove-Me to be deleted")
	}

	if resp.Header.Get("X-Keep-Me") != "value" {
		t.Errorf("Expected X-Keep-Me to remain")
	}
}

func TestResponseModifierStatusCode(t *testing.T) {
	expr := `{
		"status_code": 404
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.StatusCode != 404 {
		t.Errorf("Expected status code = 404, got %d", resp.StatusCode)
	}
}

func TestResponseModifierBody(t *testing.T) {
	expr := `{
		"body": "new body content"
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("old body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if string(bodyBytes) != "new body content" {
		t.Errorf("Expected body = 'new body content', got '%s'", string(bodyBytes))
	}

	if resp.ContentLength != int64(len("new body content")) {
		t.Errorf("Expected ContentLength = %d, got %d", len("new body content"), resp.ContentLength)
	}
}

func TestResponseModifierWithRequestContext(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			CountryCode: "US",
		},
		UserAgent: &reqctx.UserAgent{
			Family: "Chrome",
		},
	}

	expr := `{
		"add_headers": {
			"X-Request-Country": size(client.location) > 0 ? client.location['country_code'] : "UNKNOWN",
			"X-Request-Browser": size(client.user_agent) > 0 ? client.user_agent['family'] : "UNKNOWN"
		}
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.Header.Get("X-Request-Country") != "US" {
		t.Errorf("Expected X-Request-Country = US, got %s", resp.Header.Get("X-Request-Country"))
	}

	if resp.Header.Get("X-Request-Browser") != "Chrome" {
		t.Errorf("Expected X-Request-Browser = Chrome, got %s", resp.Header.Get("X-Request-Browser"))
	}
}

func TestResponseModifierAppendToBody(t *testing.T) {
	expr := `{
		"body": response.body + " [modified]"
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("original body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	expected := "original body [modified]"
	if string(bodyBytes) != expected {
		t.Errorf("Expected body = '%s', got '%s'", expected, string(bodyBytes))
	}
}

func TestResponseModifierConditionalStatusCode(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			CountryCode: "CN",
		},
	}

	expr := `{
		"status_code": size(client.location) > 0 && client.location['country_code'] == 'US' ? 200 : 403
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.StatusCode != 403 {
		t.Errorf("Expected status code = 403, got %d", resp.StatusCode)
	}
}

func TestResponseModifierCombined(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			CountryCode: "US",
		},
	}

	expr := `{
		"add_headers": {
			"X-Country": size(client.location) > 0 ? client.location['country_code'] : "UNKNOWN"
		},
		"set_headers": {
			"Content-Type": "application/json"
		},
		"delete_headers": ["X-Old-Header"],
		"status_code": 200,
		"body": "{\"status\": \"success\"}"
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 500,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("error")),
		Request:    req,
	}
	resp.Header.Set("X-Old-Header", "old_value")

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	// Check headers
	if resp.Header.Get("X-Country") != "US" {
		t.Errorf("Expected X-Country = US")
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type = application/json")
	}
	if resp.Header.Get("X-Old-Header") != "" {
		t.Errorf("Expected X-Old-Header to be deleted")
	}

	// Check status code
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code = 200, got %d", resp.StatusCode)
	}

	// Check body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	expected := "{\"status\": \"success\"}"
	if string(bodyBytes) != expected {
		t.Errorf("Expected body = '%s', got '%s'", expected, string(bodyBytes))
	}
}

func TestResponseModifierAccessRequestFields(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/api/users", nil)
	req.Header.Set("Content-Type", "application/json")

	expr := `{
		"add_headers": {
			"X-Request-Method": request.method,
			"X-Request-Path": request.path,
			"X-Request-Content-Type": request.headers['content-type']
		}
	}`

	modifier, err := NewResponseModifier(expr)
	if err != nil {
		t.Fatalf("NewResponseModifier() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("test body")),
		Request:    req,
	}

	err = modifier.ModifyResponse(resp)
	if err != nil {
		t.Fatalf("ModifyResponse() error = %v", err)
	}

	if resp.Header.Get("X-Request-Method") != "POST" {
		t.Errorf("Expected X-Request-Method = POST, got %s", resp.Header.Get("X-Request-Method"))
	}

	if resp.Header.Get("X-Request-Path") != "/api/users" {
		t.Errorf("Expected X-Request-Path = /api/users, got %s", resp.Header.Get("X-Request-Path"))
	}

	if resp.Header.Get("X-Request-Content-Type") != "application/json" {
		t.Errorf("Expected X-Request-Content-Type = application/json, got %s", resp.Header.Get("X-Request-Content-Type"))
	}
}

