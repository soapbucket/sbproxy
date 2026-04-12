package httputil

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleError_JSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/data?key=val", nil)
	r.Header.Set("Content-Type", "application/json")

	HandleError(http.StatusBadRequest, errors.New("invalid request"), w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", ct)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if body["status"] != float64(400) {
		t.Errorf("Expected status=400 in body, got %v", body["status"])
	}
	if body["error"] != "invalid request" {
		t.Errorf("Expected error='invalid request', got %v", body["error"])
	}

	reqObj, ok := body["request"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'request' object in response")
	}
	if reqObj["method"] != "GET" {
		t.Errorf("Expected method=GET, got %v", reqObj["method"])
	}
	if !strings.Contains(reqObj["url"].(string), "/api/data") {
		t.Errorf("Expected URL containing /api/data, got %v", reqObj["url"])
	}
}

func TestHandleError_HTMLResponse(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/form/submit", strings.NewReader("field=value"))
	r.Header.Set("Content-Type", "text/html")

	HandleError(http.StatusInternalServerError, errors.New("server error"), w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/html" {
		t.Errorf("Expected Content-Type text/html, got %s", ct)
	}

	bodyBytes := w.Body.String()

	if !strings.Contains(bodyBytes, "<html>") {
		t.Error("HTML response should contain <html> tag")
	}
	if !strings.Contains(bodyBytes, "server error") {
		t.Error("HTML response should contain the error message")
	}
	if !strings.Contains(bodyBytes, "POST") {
		t.Error("HTML response should contain the request method")
	}
	if !strings.Contains(bodyBytes, "/form/submit") {
		t.Error("HTML response should contain the request URL")
	}
	if !strings.Contains(bodyBytes, "<script>") {
		t.Error("HTML response should contain embedded script with JSON data")
	}
}

func TestHandleError_CacheHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Content-Type", "application/json")

	HandleError(http.StatusNotFound, errors.New("not found"), w, r)

	resp := w.Result()

	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("Expected Cache-Control 'no-cache, no-store, must-revalidate', got '%s'", cc)
	}
	if pragma := resp.Header.Get("Pragma"); pragma != "no-cache" {
		t.Errorf("Expected Pragma 'no-cache', got '%s'", pragma)
	}
	if expires := resp.Header.Get("Expires"); expires != "0" {
		t.Errorf("Expected Expires '0', got '%s'", expires)
	}
}

func TestHandleError_DifferentStatusCodes(t *testing.T) {
	codes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}

	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/test", nil)
			r.Header.Set("Content-Type", "application/json")

			HandleError(code, errors.New("test error"), w, r)

			if w.Code != code {
				t.Errorf("Expected status %d, got %d", code, w.Code)
			}
		})
	}
}

func TestHandleError_RequestHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Custom-Header", "custom-value")
	r.Header.Set("Authorization", "Bearer token123")

	HandleError(http.StatusBadRequest, errors.New("bad"), w, r)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	reqObj := body["request"].(map[string]interface{})
	headers, ok := reqObj["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected headers in request object")
	}

	// Headers are normalized: lowercase, dashes replaced with underscores
	if _, exists := headers["x_custom_header"]; !exists {
		t.Error("Expected normalized header 'x_custom_header'")
	}
	if _, exists := headers["authorization"]; !exists {
		t.Error("Expected normalized header 'authorization'")
	}
}

func TestHandleError_RequestBody(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/test", strings.NewReader(`{"input": "data"}`))
	r.Header.Set("Content-Type", "application/json")

	HandleError(http.StatusBadRequest, errors.New("bad request"), w, r)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	reqObj := body["request"].(map[string]interface{})
	if reqBody, ok := reqObj["body"].(string); !ok || reqBody == "" {
		t.Error("Expected request body to be captured")
	}
}

func TestHandleError_NoBody(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Content-Type", "application/json")

	HandleError(http.StatusNotFound, errors.New("not found"), w, r)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	reqObj := body["request"].(map[string]interface{})
	if _, exists := reqObj["body"]; exists {
		t.Error("Expected no body field when request has no body")
	}
}

func TestHandleError_DefaultContentType(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	// No Content-Type set — should default to HTML

	HandleError(http.StatusInternalServerError, errors.New("error"), w, r)

	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "text/html" {
		t.Errorf("Expected default Content-Type text/html, got %s", ct)
	}
}
