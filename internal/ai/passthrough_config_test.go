package ai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPassThroughRouter_RoutesToTarget(t *testing.T) {
	// Create a mock upstream server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": "ok"}`))
	}))
	defer upstream.Close()

	ep := PassThroughEndpoint{
		Path:      "/v1/custom/test",
		TargetURL: upstream.URL,
		Methods:   []string{"POST"},
	}

	router := NewPassThroughRouter([]PassThroughEndpoint{ep})
	handler := router.HandlerFor(ep)

	req := httptest.NewRequest(http.MethodPost, "/v1/custom/test", strings.NewReader(`{"input": "hello"}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Upstream") != "true" {
		t.Error("expected X-Upstream header from upstream")
	}
	body, _ := io.ReadAll(w.Body)
	if string(body) != `{"result": "ok"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestPassThroughRouter_AuthHeaderInjection(t *testing.T) {
	t.Setenv("TEST_API_KEY", "aK7mR9pL2xQ4nB3")

	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ep := PassThroughEndpoint{
		Path:      "/v1/custom/auth",
		TargetURL: upstream.URL,
		Headers: map[string]string{
			"Authorization": "Bearer ${TEST_API_KEY}",
		},
	}

	router := NewPassThroughRouter([]PassThroughEndpoint{ep})
	handler := router.HandlerFor(ep)

	req := httptest.NewRequest(http.MethodPost, "/v1/custom/auth", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedAuth != "Bearer aK7mR9pL2xQ4nB3" {
		t.Errorf("expected 'Bearer aK7mR9pL2xQ4nB3', got %q", capturedAuth)
	}
}

func TestPassThroughRouter_MethodRestriction(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ep := PassThroughEndpoint{
		Path:      "/v1/custom/post-only",
		TargetURL: upstream.URL,
		Methods:   []string{"POST"},
	}

	router := NewPassThroughRouter([]PassThroughEndpoint{ep})
	handler := router.HandlerFor(ep)

	// GET should be rejected.
	req := httptest.NewRequest(http.MethodGet, "/v1/custom/post-only", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}

	// POST should succeed.
	req = httptest.NewRequest(http.MethodPost, "/v1/custom/post-only", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for POST, got %d", w.Code)
	}
}

func TestResolveVars(t *testing.T) {
	t.Setenv("MY_TOKEN", "abc123")
	t.Setenv("REGION", "us-east-1")

	tests := []struct {
		input string
		want  string
	}{
		{"Bearer ${MY_TOKEN}", "Bearer abc123"},
		{"${REGION}", "us-east-1"},
		{"no-vars", "no-vars"},
		{"${UNSET_VAR}", ""},
		{"prefix-${MY_TOKEN}-suffix", "prefix-abc123-suffix"},
	}

	for _, tt := range tests {
		got := resolveVars(tt.input)
		if got != tt.want {
			t.Errorf("resolveVars(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidatePassThroughEndpoints(t *testing.T) {
	valid := []PassThroughEndpoint{
		{Path: "/v1/test", TargetURL: "https://example.com"},
	}
	if err := ValidatePassThroughEndpoints(valid); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	missingPath := []PassThroughEndpoint{
		{TargetURL: "https://example.com"},
	}
	if err := ValidatePassThroughEndpoints(missingPath); err == nil {
		t.Error("expected error for missing path")
	}

	missingTarget := []PassThroughEndpoint{
		{Path: "/v1/test"},
	}
	if err := ValidatePassThroughEndpoints(missingTarget); err == nil {
		t.Error("expected error for missing target_url")
	}
}

func TestPassThroughRouter_Routes(t *testing.T) {
	eps := []PassThroughEndpoint{
		{Path: "/a", TargetURL: "https://a.com"},
		{Path: "/b", TargetURL: "https://b.com"},
	}
	router := NewPassThroughRouter(eps)
	routes := router.Routes()
	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}
}
