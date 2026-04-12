package cors_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/middleware/cors"
)

// --- ApplyHeaders tests ---

func TestApplyHeaders_WildcardWithCredentials_ReflectsOrigin(t *testing.T) {
	// When AllowOrigins is ["*"] and AllowCredentials is true, the response
	// must reflect the actual request origin (not literal "*"), because
	// browsers reject "Access-Control-Allow-Origin: *" with credentials.
	cfg := &cors.Config{
		Enable:           true,
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	got := rec.Header().Get("Access-Control-Allow-Origin")
	if got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://app.example.com")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestApplyHeaders_WildcardWithoutCredentials_ReturnsLiteralStar(t *testing.T) {
	// When AllowOrigins is ["*"] without credentials, literal "*" is returned.
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"*"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	got := rec.Header().Get("Access-Control-Allow-Origin")
	if got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("credentials header should not be set when AllowCredentials is false")
	}
}

func TestApplyHeaders_UnknownOriginRejected(t *testing.T) {
	// When specific origins are configured, an unknown origin should get no CORS headers.
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"https://trusted.example.com"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin should be empty for rejected origin, got %q", got)
	}
}

func TestApplyHeaders_VaryHeaderSetForSpecificOrigin(t *testing.T) {
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"https://trusted.example.com"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://trusted.example.com")
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	vary := rec.Header().Get("Vary")
	if vary != "Origin" {
		t.Errorf("Vary = %q, want %q", vary, "Origin")
	}
}

func TestApplyHeaders_VaryHeaderNotSetForWildcardWithoutCredentials(t *testing.T) {
	// When AllowOrigins is ["*"] without credentials, Vary: Origin is not needed
	// because the response is the same for all origins.
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"*"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://any.example.com")
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	vary := rec.Header().Get("Vary")
	if vary != "" {
		t.Errorf("Vary should be empty for wildcard without credentials, got %q", vary)
	}
}

func TestApplyHeaders_VaryHeaderSetForWildcardWithCredentials(t *testing.T) {
	// When AllowOrigins is ["*"] with credentials, the origin is reflected,
	// so Vary: Origin must be set (response varies by request origin).
	cfg := &cors.Config{
		Enable:           true,
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://any.example.com")
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	vary := rec.Header().Get("Vary")
	if vary != "Origin" {
		t.Errorf("Vary = %q, want %q for wildcard with credentials", vary, "Origin")
	}
}

func TestApplyHeaders_NoOriginHeader_NoHeaders(t *testing.T) {
	// Requests without an Origin header should not get any CORS headers.
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"*"},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	cors.ApplyHeaders(rec, req, cfg)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("should not set CORS headers without Origin, got %q", got)
	}
}

// --- HandlePreflight tests ---

func TestHandlePreflight_MissingRequestMethod(t *testing.T) {
	// A preflight OPTIONS request without Access-Control-Request-Method
	// should not be treated as a CORS preflight.
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"*"},
	}

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	// Deliberately omit Access-Control-Request-Method
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, cfg)

	if handled {
		t.Error("preflight should not be handled when Access-Control-Request-Method is missing")
	}
}

func TestHandlePreflight_WildcardWithCredentials_ReflectsOrigin(t *testing.T) {
	cfg := &cors.Config{
		Enable:           true,
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, cfg)

	if !handled {
		t.Fatal("expected preflight to be handled")
	}
	got := rec.Header().Get("Access-Control-Allow-Origin")
	if got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want reflected origin", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected credentials header on preflight")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestHandlePreflight_UnknownOriginForbidden(t *testing.T) {
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"https://trusted.example.com"},
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, cfg)

	if !handled {
		t.Fatal("expected preflight to be handled (rejected)")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandlePreflight_VaryHeaders(t *testing.T) {
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"https://trusted.example.com"},
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
	req.Header.Set("Origin", "https://trusted.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, cfg)

	if !handled {
		t.Fatal("expected preflight to be handled")
	}

	varyValues := rec.Header().Values("Vary")
	wantVary := map[string]bool{
		"Origin":                         true,
		"Access-Control-Request-Method":  true,
		"Access-Control-Request-Headers": true,
	}

	for _, v := range varyValues {
		delete(wantVary, v)
	}
	for missing := range wantVary {
		t.Errorf("missing Vary value: %s", missing)
	}
}

func TestHandlePreflight_DisabledConfig(t *testing.T) {
	cfg := &cors.Config{
		Enable: false,
	}

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, cfg)

	if handled {
		t.Error("preflight should not be handled when CORS is disabled")
	}
}

func TestHandlePreflight_NilConfig(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, nil)

	if handled {
		t.Error("preflight should not be handled with nil config")
	}
}

func TestHandlePreflight_OriginCaseInsensitive(t *testing.T) {
	cfg := &cors.Config{
		Enable:       true,
		AllowOrigins: []string{"https://Trusted.Example.COM"},
	}

	req := httptest.NewRequest(http.MethodOptions, "/api", nil)
	req.Header.Set("Origin", "https://trusted.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()

	handled := cors.HandlePreflight(rec, req, cfg)

	if !handled {
		t.Fatal("expected preflight to be handled")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d (origin matching should be case-insensitive)", rec.Code, http.StatusNoContent)
	}
}
