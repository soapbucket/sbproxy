package expression

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func TestNew_LegacyCEL(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"cel_expr": "request.method == 'GET'"
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if p.Type() != "expression" {
		t.Errorf("Type() = %q, want %q", p.Type(), "expression")
	}
}

func TestNew_LegacyLua(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"lua_script": "return request.method == 'GET'"
	}`)
	_, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNew_NoExpressionOrAssertion(t *testing.T) {
	raw := json.RawMessage(`{"type": "expression"}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("New() expected error for empty config")
	}
}

func TestNew_AssertionsOnly(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "must-be-get",
				"cel_expr": "request.method == 'GET'"
			}
		]
	}`)
	_, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNew_AssertionMissingExpr(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{"name": "empty"}
		]
	}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("New() expected error for assertion without cel_expr or lua_script")
	}
}

func TestNew_AssertionBadCEL(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "bad-cel",
				"cel_expr": "this is not valid CEL!!!"
			}
		]
	}`)
	_, err := New(raw)
	if err == nil {
		t.Fatal("New() expected error for invalid CEL")
	}
}

func TestEnforce_Disabled(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"disabled": true,
		"cel_expr": "request.method == 'POST'"
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("disabled policy should pass, got status %d", rr.Code)
	}
}

func TestEnforce_LegacyCEL_Allow(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"cel_expr": "request.method == 'GET'"
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestEnforce_LegacyCEL_Block(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"cel_expr": "request.method == 'POST'",
		"status_code": 403
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestEnforce_Assertion_Block(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "require-post",
				"cel_expr": "request.method == 'POST'",
				"action": "block",
				"status_code": 429,
				"message": "Only POST allowed"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 429 {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

func TestEnforce_Assertion_Flag(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "warn-delete",
				"cel_expr": "request.method != 'DELETE'",
				"action": "flag",
				"message": "DELETE method detected"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	// Send a DELETE request - assertion fails but action=flag, so request continues
	req := httptest.NewRequest(http.MethodDelete, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("flag assertion should not block, got status %d", rr.Code)
	}
}

func TestEnforce_Assertion_DefaultAction(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "require-get",
				"cel_expr": "request.method == 'GET'"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Default action is block, default status is 403
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 (default block), got %d", rr.Code)
	}
}

func TestEnforce_Assertion_DefaultMessage(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "require-get",
				"cel_expr": "request.method == 'GET'"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Default message should contain the assertion name
	body := rr.Body.String()
	if body == "" {
		t.Error("expected error body, got empty")
	}
}

func TestEnforce_MultipleAssertions_ShortCircuit(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "first-blocks",
				"cel_expr": "request.method == 'POST'",
				"status_code": 400,
				"message": "first assertion failed"
			},
			{
				"name": "second-blocks",
				"cel_expr": "request.method == 'PUT'",
				"status_code": 500,
				"message": "second assertion failed"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// First assertion should short-circuit with its status code
	if rr.Code != 400 {
		t.Errorf("expected 400 from first assertion, got %d", rr.Code)
	}
}

func TestEnforce_LegacyThenAssertions(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"cel_expr": "request.method == 'GET'",
		"assertions": [
			{
				"name": "require-header",
				"cel_expr": "request.headers['x-api-key'] != ''",
				"status_code": 401,
				"message": "API key required"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())

	// GET without header: passes legacy CEL but fails assertion
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 401 {
		t.Errorf("expected 401 from assertion, got %d", rr.Code)
	}

	// POST: fails at legacy CEL level
	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 from legacy CEL, got %d", rr2.Code)
	}
}

func TestEnforce_AllAssertionsPass(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "expression",
		"assertions": [
			{
				"name": "is-get",
				"cel_expr": "request.method == 'GET'"
			},
			{
				"name": "has-path",
				"cel_expr": "request.path.startsWith('/api')"
			}
		]
	}`)
	p, err := New(raw)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := p.Enforce(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("all assertions pass, expected 200, got %d", rr.Code)
	}
}
