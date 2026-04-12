package sri

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNew_ValidConfig verifies that valid configs create an enforcer.
func TestNew_ValidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "default algorithm",
			json: `{"type":"sri"}`,
		},
		{
			name: "sha256 algorithm",
			json: `{"type":"sri","algorithm":"sha256"}`,
		},
		{
			name: "sha384 algorithm",
			json: `{"type":"sri","algorithm":"sha384"}`,
		},
		{
			name: "sha512 algorithm",
			json: `{"type":"sri","algorithm":"sha512"}`,
		},
		{
			name: "with known hashes",
			json: `{"type":"sri","known_hashes":{"https://cdn.example.com/app.js":["sha384-abc123"]}}`,
		},
		{
			name: "disabled",
			json: `{"type":"sri","disabled":true}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforcer, err := New(json.RawMessage(tc.json))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if enforcer == nil {
				t.Fatal("expected non-nil enforcer")
			}
		})
	}
}

// TestNew_InvalidJSON verifies that invalid JSON returns an error.
func TestNew_InvalidJSON(t *testing.T) {
	_, err := New(json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestNew_InvalidAlgorithm verifies that an unsupported algorithm returns an error.
func TestNew_InvalidAlgorithm(t *testing.T) {
	_, err := New(json.RawMessage(`{"type":"sri","algorithm":"md5"}`))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

// TestType verifies the Type() method returns the correct string.
func TestType(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"sri"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sp := enforcer.(*sriPolicy)
	if sp.Type() != "sri" {
		t.Errorf("expected type 'sri', got %q", sp.Type())
	}
}

// TestEnforce_Disabled verifies that disabled policy passes through.
func TestEnforce_Disabled(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"sri","disabled":true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called when policy is disabled")
	}
}

// TestEnforce_PassesThrough verifies that requests pass through without validation.
func TestEnforce_PassesThrough(t *testing.T) {
	enforcer, err := New(json.RawMessage(`{"type":"sri"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := enforcer.Enforce(next)

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected next handler to be called")
	}
}
