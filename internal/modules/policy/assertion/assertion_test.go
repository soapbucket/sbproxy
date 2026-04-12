package assertion

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// backendHandler returns a handler that writes a fixed status and body.
func backendHandler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})
}

func TestNew_Valid(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [
			{
				"name": "must-be-200",
				"cel_expr": "response.status_code == 200",
				"action": "block"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if p.Type() != "response_assertion" {
		t.Errorf("Type() = %q, want %q", p.Type(), "response_assertion")
	}
}

func TestNew_NoAssertions(t *testing.T) {
	raw := json.RawMessage(`{"type": "response_assertion", "assertions": []}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("expected error for empty assertions")
	}
}

func TestNew_MissingExpr(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{"name": "empty", "action": "block"}]
	}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("expected error for assertion without cel_expr or lua_script")
	}
}

func TestNew_InvalidAction(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "bad",
			"cel_expr": "response.status_code == 200",
			"action": "invalid"
		}]
	}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestNew_InvalidCEL(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "bad-cel",
			"cel_expr": "this is garbage!!!",
			"action": "block"
		}]
	}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("expected error for invalid CEL expression")
	}
}

func TestEnforce_Disabled(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"disabled": true,
		"assertions": [{
			"name": "must-be-200",
			"cel_expr": "response.status_code == 200",
			"action": "block"
		}]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Backend returns 500, but policy is disabled so it passes through
	handler := p.Enforce(backendHandler(500, `{"error":"internal"}`))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 500 {
		t.Errorf("disabled policy should pass through, got status %d", rr.Code)
	}
}

func TestEnforce_Block_OnFailedAssertion(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "must-be-200",
			"cel_expr": "response.status_code == 200",
			"action": "block",
			"status_code": 502,
			"message": "Backend returned non-200"
		}]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Backend returns 500, assertion fails, block
	handler := p.Enforce(backendHandler(500, `{"error":"oops"}`))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 502 {
		t.Errorf("expected 502, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != "Backend returned non-200" {
		t.Errorf("expected custom message, got %q", body)
	}
}

func TestEnforce_Pass(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "must-be-200",
			"cel_expr": "response.status_code == 200",
			"action": "block"
		}]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Backend returns 200, assertion passes
	handler := p.Enforce(backendHandler(200, `{"ok":true}`))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestEnforce_Flag_DoesNotBlock(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "warn-slow",
			"cel_expr": "response.status_code < 400",
			"action": "flag",
			"message": "Backend error detected"
		}]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Backend returns 500, assertion fails, but flag does not block
	handler := p.Enforce(backendHandler(500, `{"error":"oops"}`))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 500 {
		t.Errorf("flag should forward original response, got status %d", rr.Code)
	}
}

func TestEnforce_DefaultStatusAndMessage(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "check-ok",
			"cel_expr": "response.status_code == 200",
			"action": "block"
		}]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(backendHandler(404, `not found`))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Default status is 403
	if rr.Code != 403 {
		t.Errorf("expected default 403, got %d", rr.Code)
	}
	// Default message should contain assertion name
	body := rr.Body.String()
	if body == "" {
		t.Error("expected non-empty error body")
	}
}

func TestEnforce_MultipleAssertions_FirstBlockWins(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [
			{
				"name": "flag-only",
				"cel_expr": "response.status_code < 500",
				"action": "flag",
				"message": "5xx detected"
			},
			{
				"name": "block-errors",
				"cel_expr": "response.status_code < 400",
				"action": "block",
				"status_code": 503,
				"message": "Backend error"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// 500: first assertion (flag) triggers but does not block,
	// second assertion (block) also triggers and blocks
	handler := p.Enforce(backendHandler(500, `error`))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 503 {
		t.Errorf("expected 503 from blocking assertion, got %d", rr.Code)
	}
}

func TestEnforce_BodyForwarded(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "response_assertion",
		"assertions": [{
			"name": "always-pass",
			"cel_expr": "true",
			"action": "block"
		}]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	expectedBody := `{"data":"hello world"}`
	handler := p.Enforce(backendHandler(200, expectedBody))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, body)
	}
}

func TestBufferedResponseWriter(t *testing.T) {
	rec := &bufferedResponseWriter{
		header: make(http.Header),
	}
	rec.Header().Set("X-Test", "value")
	rec.WriteHeader(201)
	rec.Write([]byte("created"))

	resp := rec.toHTTPResponse(httptest.NewRequest(http.MethodGet, "/", nil))
	if resp.StatusCode != 201 {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Test") != "value" {
		t.Error("expected X-Test header to be preserved")
	}
}

func TestFormatFlaggedAssertions(t *testing.T) {
	result := formatFlaggedAssertions([]string{"a", "b", "c"})
	if result != "a, b, c" {
		t.Errorf("expected 'a, b, c', got %q", result)
	}
}
