package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestThreatProtection_E2E_JSONDepth25Blocked verifies that a POST with JSON
// nested to depth 25 is rejected when the default max depth is 20.
func TestThreatProtection_E2E_JSONDepth25Blocked(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	mw := ThreatProtectionMiddleware(config)

	var sb strings.Builder
	for i := 0; i < 25; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < 25; i++ {
		sb.WriteString(`}`)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be reached for depth-25 JSON")
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mw(backend))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/data", "application/json", strings.NewReader(sb.String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestThreatProtection_E2E_JSONDepth15Passes verifies that a POST with JSON
// nested to depth 15 passes through (below the default max depth of 20) and
// the body is intact for the handler.
func TestThreatProtection_E2E_JSONDepth15Passes(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	mw := ThreatProtectionMiddleware(config)

	var sb strings.Builder
	for i := 0; i < 15; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < 15; i++ {
		sb.WriteString(`}`)
	}
	payload := sb.String()

	var bodySeenByHandler string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("handler failed to read body: %v", err)
		}
		bodySeenByHandler = string(b)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mw(backend))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/data", "application/json", strings.NewReader(payload))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, payload, bodySeenByHandler, "body should be preserved for the handler")
}

// TestThreatProtection_E2E_XMLEntityExpansionBlocked verifies that a POST with
// XML containing ENTITY declarations is rejected as a billion-laughs defense.
func TestThreatProtection_E2E_XMLEntityExpansionBlocked(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	mw := ThreatProtectionMiddleware(config)

	xmlPayload := `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;">
]>
<root>&lol2;</root>`

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be reached for XML entity attack")
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mw(backend))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/data", "application/xml", strings.NewReader(xmlPayload))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestThreatProtection_E2E_GETBypasses verifies that GET requests bypass body
// validation entirely, even if Content-Type is set.
func TestThreatProtection_E2E_GETBypasses(t *testing.T) {
	config := DefaultThreatProtectionConfig()
	mw := ThreatProtectionMiddleware(config)

	reached := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mw(backend))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/data", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, reached, "GET should bypass threat protection and reach handler")
}

// TestThreatProtection_E2E_DisabledPassesEverything verifies that when the
// config is disabled, even deeply nested JSON passes through.
func TestThreatProtection_E2E_DisabledPassesEverything(t *testing.T) {
	config := &ThreatProtectionConfig{Enabled: false}
	mw := ThreatProtectionMiddleware(config)

	// Build depth-100 JSON that would normally be blocked
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < 100; i++ {
		sb.WriteString(`}`)
	}

	reached := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mw(backend))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api", "application/json", strings.NewReader(sb.String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, reached, "disabled config should pass everything through")
}

// BenchmarkThreatProtection_ValidJSON measures the processing time for a valid
// 1KB JSON body through the threat protection middleware.
func BenchmarkThreatProtection_ValidJSON(b *testing.B) {
	config := DefaultThreatProtectionConfig()
	mw := ThreatProtectionMiddleware(config)

	// Build a ~1KB JSON payload with realistic structure
	var sb strings.Builder
	sb.WriteString(`{"users":[`)
	for i := 0; i < 10; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":`)
		sb.WriteString(strings.Repeat("1", 5))
		sb.WriteString(`,"name":"user_`)
		sb.WriteString(strings.Repeat("x", 30))
		sb.WriteString(`","email":"user@example.com","active":true}`)
	}
	sb.WriteString(`]}`)
	payload := sb.String()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rr.Code)
		}
	}
}
