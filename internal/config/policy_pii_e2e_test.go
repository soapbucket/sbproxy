package config

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPIIPolicy_BlockMode_Request(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "request",
		"detectors": {"ssn": true, "credit_card": true, "email": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	handler := policy.Apply(next)

	tests := []struct {
		name       string
		body       string
		expectCode int
	}{
		{"SSN blocked", `{"ssn":"123-45-6789"}`, http.StatusForbidden},
		{"credit card blocked", `{"card":"4111111111111111"}`, http.StatusForbidden},
		{"email blocked", `{"email":"user@example.com"}`, http.StatusForbidden},
		{"clean body passes", `{"name":"John","age":30}`, http.StatusOK},
		{"empty body passes", ``, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewReader([]byte(tt.body))
			}
			req := httptest.NewRequest("POST", "/api/data", body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectCode {
				t.Errorf("got status %d, want %d", w.Code, tt.expectCode)
			}
		})
	}
}

func TestPIIPolicy_BlockMode_Response(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "response",
		"status_code": 502,
		"detectors": {"ssn": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	// Upstream returns PII in the response
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"SSN is 456-78-9012"}`))
	})
	handler := policy.Apply(next)

	req := httptest.NewRequest("GET", "/api/data", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 502 {
		t.Errorf("got status %d, want 502", w.Code)
	}
}

func TestPIIPolicy_RedactMode_Request(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "redact",
		"direction": "request",
		"detectors": {"ssn": true, "email": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	var capturedBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	handler := policy.Apply(next)

	body := `{"ssn":"567-89-0123","email":"test@example.com"}`
	req := httptest.NewRequest("POST", "/api/data", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", w.Code)
	}

	// Check that the original PII is no longer in the body
	if bytes.Contains(capturedBody, []byte("567-89-0123")) {
		t.Error("SSN should be redacted in forwarded request")
	}
	if bytes.Contains(capturedBody, []byte("test@example.com")) {
		t.Error("email should be redacted in forwarded request")
	}
}

func TestPIIPolicy_RedactMode_Response(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "redact",
		"direction": "response",
		"detectors": {"credit_card": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"card":"4111111111111111"}`))
	})
	handler := policy.Apply(next)

	req := httptest.NewRequest("GET", "/api/data", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", w.Code)
	}

	respBody := w.Body.String()
	if bytes.Contains([]byte(respBody), []byte("4111111111111111")) {
		t.Error("credit card should be redacted in response")
	}
}

func TestPIIPolicy_WarnMode(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "warn",
		"direction": "response",
		"detectors": {"email": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"email":"warn@example.com"}`))
	})
	handler := policy.Apply(next)

	req := httptest.NewRequest("GET", "/api/data", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("warn mode should pass through, got status %d", w.Code)
	}

	if w.Header().Get("X-PII-Warning") == "" {
		t.Error("expected X-PII-Warning header in warn mode")
	}

	// Body should be unmodified
	if !bytes.Contains(w.Body.Bytes(), []byte("warn@example.com")) {
		t.Error("warn mode should not modify the response body")
	}
}

func TestPIIPolicy_Allowlist(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "request",
		"detectors": {"email": true},
		"allowlist": [
			{"field_path": "user.email", "detector_type": "email", "path_prefix": "/api/login"}
		]
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := policy.Apply(next)

	// Allowed: email in user.email field at /api/login
	body := `{"user":{"email":"login@example.com"}}`
	req := httptest.NewRequest("POST", "/api/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("allowlisted email at /api/login should pass, got %d", w.Code)
	}

	// Not allowed: email at /api/other
	req2 := httptest.NewRequest("POST", "/api/other", bytes.NewReader([]byte(body)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("email at /api/other should be blocked, got %d", w2.Code)
	}
}

func TestPIIPolicy_BinaryContentTypeSkipped(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "request",
		"detectors": {"ssn": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := policy.Apply(next)

	// Binary content type should be skipped
	body := "SSN: 123-45-6789"
	req := httptest.NewRequest("POST", "/upload", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "image/png")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("binary content should be skipped, got %d", w.Code)
	}
}

func TestPIIPolicy_Disabled(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "request",
		"disabled": true,
		"detectors": {"ssn": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := policy.Apply(next)

	body := `{"ssn":"123-45-6789"}`
	req := httptest.NewRequest("POST", "/api/data", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("disabled policy should pass through, got %d", w.Code)
	}
}

func TestPIIPolicy_BothDirections(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "both",
		"detectors": {"ssn": true}
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	// Clean request but upstream returns PII in response
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ssn":"789-01-2345"}`))
	})
	handler := policy.Apply(next)

	req := httptest.NewRequest("POST", "/api/data", bytes.NewReader([]byte(`{"name":"clean"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Request passes (clean), but response should be blocked
	if w.Code != http.StatusForbidden {
		t.Errorf("response with PII should be blocked, got %d", w.Code)
	}
}

func TestPIIPolicy_CustomLuaDetector(t *testing.T) {
	policyJSON := `{
		"type": "pii",
		"mode": "block",
		"direction": "request",
		"detectors": {},
		"custom_detectors": [
			{
				"name": "employee_id",
				"lua_script": "function detect_pii(text, field_path)\n  if string.find(text, 'EMP%-[0-9]+') then\n    return {type='employee_id', value='match'}\n  end\n  return nil\nend"
			}
		]
	}`

	policy, err := NewPIIPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to create PII policy: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := policy.Apply(next)

	// Should be blocked by custom Lua detector
	body := `{"id":"EMP-12345"}`
	req := httptest.NewRequest("POST", "/api/data", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("custom Lua detector should block, got %d", w.Code)
	}

	// Clean body should pass
	body2 := `{"id":"DEPT-12345"}`
	req2 := httptest.NewRequest("POST", "/api/data", bytes.NewReader([]byte(body2)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("clean body should pass custom detector, got %d", w2.Code)
	}
}

func TestPIIPolicy_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"invalid mode", `{"type":"pii","mode":"invalid","detectors":{"ssn":true}}`},
		{"no detectors", `{"type":"pii","mode":"block","detectors":{"ssn":false,"credit_card":false,"email":false,"phone":false,"api_key":false,"jwt":false}}`},
		{"bad JSON", `{"type":"pii",`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPIIPolicy([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}
