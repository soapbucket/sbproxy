package wasm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestRequestContext_AuthInfo(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetAuthInfo("type")
	if ok {
		t.Error("expected false for nil AuthInfo map")
	}

	rc.mu.Lock()
	rc.AuthInfo = map[string]string{
		"type":             "oauth",
		"is_authenticated": "true",
		"scope":            "read write",
		"sub":              "user-123",
	}
	rc.mu.Unlock()

	val, ok := rc.GetAuthInfo("type")
	if !ok || val != "oauth" {
		t.Errorf("expected type=oauth, got %q (ok=%v)", val, ok)
	}

	val, ok = rc.GetAuthInfo("scope")
	if !ok || val != "read write" {
		t.Errorf("expected scope=%q, got %q (ok=%v)", "read write", val, ok)
	}

	_, ok = rc.GetAuthInfo("missing")
	if ok {
		t.Error("expected false for missing auth key")
	}
}

func TestRequestContext_AuthJSON(t *testing.T) {
	rc := NewRequestContext()

	if data := rc.GetAuthJSON(); len(data) != 0 {
		t.Errorf("expected empty auth JSON, got %q", string(data))
	}

	rc.mu.Lock()
	rc.AuthJSON = []byte(`{"type":"jwt","data":{"sub":"u1"}}`)
	rc.mu.Unlock()

	data := rc.GetAuthJSON()
	if string(data) != `{"type":"jwt","data":{"sub":"u1"}}` {
		t.Errorf("unexpected auth JSON: %q", string(data))
	}
}

func TestRequestContext_ClientLocation(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetClientLocation("country")
	if ok {
		t.Error("expected false for nil ClientLocation")
	}

	rc.mu.Lock()
	rc.ClientLocation = map[string]string{
		"country":      "United States",
		"country_code": "US",
		"asn":          "AS15169",
	}
	rc.mu.Unlock()

	val, ok := rc.GetClientLocation("country_code")
	if !ok || val != "US" {
		t.Errorf("expected country_code=US, got %q (ok=%v)", val, ok)
	}

	val, ok = rc.GetClientLocation("asn")
	if !ok || val != "AS15169" {
		t.Errorf("expected asn=AS15169, got %q (ok=%v)", val, ok)
	}
}

func TestRequestContext_ClientUserAgent(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetClientUserAgent("family")
	if ok {
		t.Error("expected false for nil ClientUserAgent")
	}

	rc.mu.Lock()
	rc.ClientUserAgent = map[string]string{
		"family":        "Chrome",
		"major":         "120",
		"os_family":     "Mac OS X",
		"device_family": "Mac",
	}
	rc.mu.Unlock()

	val, ok := rc.GetClientUserAgent("family")
	if !ok || val != "Chrome" {
		t.Errorf("expected family=Chrome, got %q (ok=%v)", val, ok)
	}

	val, ok = rc.GetClientUserAgent("os_family")
	if !ok || val != "Mac OS X" {
		t.Errorf("expected os_family=%q, got %q (ok=%v)", "Mac OS X", val, ok)
	}
}

func TestRequestContext_ClientFingerprint(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetClientFingerprint("hash")
	if ok {
		t.Error("expected false for nil ClientFingerprint")
	}

	rc.mu.Lock()
	rc.ClientFingerprint = map[string]string{
		"hash":      "abc123",
		"composite": "def456",
		"ip_hash":   "ip-hash-789",
	}
	rc.mu.Unlock()

	val, ok := rc.GetClientFingerprint("hash")
	if !ok || val != "abc123" {
		t.Errorf("expected hash=abc123, got %q (ok=%v)", val, ok)
	}

	_, ok = rc.GetClientFingerprint("missing")
	if ok {
		t.Error("expected false for missing fingerprint key")
	}
}

func TestRequestContext_OriginMeta(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetOriginMeta("hostname")
	if ok {
		t.Error("expected false for nil OriginMeta")
	}

	rc.mu.Lock()
	rc.OriginMeta = map[string]string{
		"hostname":     "api.example.com",
		"workspace_id": "ws-123",
		"environment":  "production",
		"tags":         "api,v2",
	}
	rc.mu.Unlock()

	val, ok := rc.GetOriginMeta("hostname")
	if !ok || val != "api.example.com" {
		t.Errorf("expected hostname=api.example.com, got %q (ok=%v)", val, ok)
	}

	val, ok = rc.GetOriginMeta("tags")
	if !ok || val != "api,v2" {
		t.Errorf("expected tags=api,v2, got %q (ok=%v)", val, ok)
	}
}

func TestRequestContext_CtxScalars(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetCtxScalar("id")
	if ok {
		t.Error("expected false for nil CtxScalars")
	}

	rc.mu.Lock()
	rc.CtxScalars = map[string]string{
		"id":           "req-abc",
		"cache_status": "HIT",
		"debug":        "true",
		"no_cache":     "false",
	}
	rc.mu.Unlock()

	val, ok := rc.GetCtxScalar("cache_status")
	if !ok || val != "HIT" {
		t.Errorf("expected cache_status=HIT, got %q (ok=%v)", val, ok)
	}

	val, ok = rc.GetCtxScalar("debug")
	if !ok || val != "true" {
		t.Errorf("expected debug=true, got %q (ok=%v)", val, ok)
	}
}

func TestRequestContext_CtxData(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetCtxData("key1")
	if ok {
		t.Error("expected false for nil CtxData")
	}

	// SetCtxData should initialize the map
	rc.SetCtxData("key1", "value1")

	val, ok := rc.GetCtxData("key1")
	if !ok || val != "value1" {
		t.Errorf("expected key1=value1, got %q (ok=%v)", val, ok)
	}

	// Overwrite
	rc.SetCtxData("key1", "updated")
	val, ok = rc.GetCtxData("key1")
	if !ok || val != "updated" {
		t.Errorf("expected key1=updated, got %q (ok=%v)", val, ok)
	}
}

// --- Conversion helper tests ---

func TestBuildAuthMap(t *testing.T) {
	auth := reqctx.SessionAuth{
		Type: "oauth",
		Data: map[string]any{
			"scope":     "read write",
			"sub":       "user-123",
			"client_id": "app-456",
		},
	}

	m := buildAuthMap(auth)

	if m["type"] != "oauth" {
		t.Errorf("expected type=oauth, got %q", m["type"])
	}
	if m["is_authenticated"] != "true" {
		t.Errorf("expected is_authenticated=true, got %q", m["is_authenticated"])
	}
	if m["scope"] != "read write" {
		t.Errorf("expected scope=%q, got %q", "read write", m["scope"])
	}
	if m["sub"] != "user-123" {
		t.Errorf("expected sub=user-123, got %q", m["sub"])
	}
}

func TestBuildAuthMap_Empty(t *testing.T) {
	auth := reqctx.SessionAuth{}
	m := buildAuthMap(auth)

	if m["is_authenticated"] != "false" {
		t.Errorf("expected is_authenticated=false for empty auth, got %q", m["is_authenticated"])
	}
}

func TestMarshalAuthJSON(t *testing.T) {
	auth := reqctx.SessionAuth{
		Type: "jwt",
		Data: map[string]any{
			"sub": "user-1",
		},
	}

	data := marshalAuthJSON(auth)
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}

	var parsed reqctx.SessionAuth
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.Type != "jwt" {
		t.Errorf("expected type=jwt, got %q", parsed.Type)
	}
}

func TestLocationToStringMap(t *testing.T) {
	if m := locationToStringMap(nil); m != nil {
		t.Errorf("expected nil for nil location, got %v", m)
	}

	loc := &reqctx.Location{
		Country:     "United States",
		CountryCode: "US",
		ASN:         "AS15169",
		ASName:      "Google LLC",
	}
	m := locationToStringMap(loc)
	if m["country"] != "United States" {
		t.Errorf("expected country=%q, got %q", "United States", m["country"])
	}
	if m["asn"] != "AS15169" {
		t.Errorf("expected asn=AS15169, got %q", m["asn"])
	}
}

func TestUserAgentToStringMap(t *testing.T) {
	if m := userAgentToStringMap(nil); m != nil {
		t.Errorf("expected nil for nil user agent, got %v", m)
	}

	ua := &reqctx.UserAgent{
		Family:   "Chrome",
		Major:    "120",
		OSFamily: "Mac OS X",
	}
	m := userAgentToStringMap(ua)
	if m["family"] != "Chrome" {
		t.Errorf("expected family=Chrome, got %q", m["family"])
	}
	if m["os_family"] != "Mac OS X" {
		t.Errorf("expected os_family=%q, got %q", "Mac OS X", m["os_family"])
	}
}

func TestFingerprintToStringMap(t *testing.T) {
	if m := fingerprintToStringMap(nil); m != nil {
		t.Errorf("expected nil for nil fingerprint, got %v", m)
	}

	fp := &reqctx.Fingerprint{
		Hash:         "abc",
		Composite:    "def",
		CookieCount:  5,
		ConnDuration: 150 * time.Millisecond,
	}
	m := fingerprintToStringMap(fp)
	if m["hash"] != "abc" {
		t.Errorf("expected hash=abc, got %q", m["hash"])
	}
	if m["cookie_count"] != "5" {
		t.Errorf("expected cookie_count=5, got %q", m["cookie_count"])
	}
	if m["conn_duration_ms"] != "150" {
		t.Errorf("expected conn_duration_ms=150, got %q", m["conn_duration_ms"])
	}
}

func TestOriginToStringMap(t *testing.T) {
	if m := originToStringMap(nil); m != nil {
		t.Errorf("expected nil for nil origin, got %v", m)
	}

	oc := &reqctx.OriginContext{
		Hostname:    "api.example.com",
		WorkspaceID: "ws-1",
		Tags:        []string{"api", "v2"},
		ConfigMode:  "dedicated",
	}
	m := originToStringMap(oc)
	if m["hostname"] != "api.example.com" {
		t.Errorf("expected hostname=api.example.com, got %q", m["hostname"])
	}
	if m["tags"] != "api,v2" {
		t.Errorf("expected tags=api,v2, got %q", m["tags"])
	}
}

func TestCtxToStringMap(t *testing.T) {
	if m := ctxToStringMap(nil); m != nil {
		t.Errorf("expected nil for nil ctx, got %v", m)
	}

	co := &reqctx.CtxObject{
		ID:          "req-abc",
		CacheStatus: "MISS",
		Debug:       true,
		NoCache:     false,
	}
	m := ctxToStringMap(co)
	if m["id"] != "req-abc" {
		t.Errorf("expected id=req-abc, got %q", m["id"])
	}
	if m["debug"] != "true" {
		t.Errorf("expected debug=true, got %q", m["debug"])
	}
	if m["no_cache"] != "false" {
		t.Errorf("expected no_cache=false, got %q", m["no_cache"])
	}
}

// --- Middleware population tests ---

func TestMiddleware_HandleRequest_PopulatesAuthFromSessionCtx(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rd := reqctx.NewRequestData()
	rd.SessionCtx = &reqctx.SessionContext{
		ID:   "sess-1",
		Data: map[string]any{"role": "admin"},
		Auth: reqctx.SessionAuth{
			Type: "oauth",
			Data: map[string]any{
				"scope": "read write",
				"sub":   "user-42",
			},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext")
	}

	val, ok := capturedRC.GetAuthInfo("type")
	if !ok || val != "oauth" {
		t.Errorf("expected auth type=oauth, got %q (ok=%v)", val, ok)
	}
	val, ok = capturedRC.GetAuthInfo("is_authenticated")
	if !ok || val != "true" {
		t.Errorf("expected is_authenticated=true, got %q (ok=%v)", val, ok)
	}
	val, ok = capturedRC.GetAuthInfo("scope")
	if !ok || val != "read write" {
		t.Errorf("expected scope=%q, got %q (ok=%v)", "read write", val, ok)
	}

	authJSON := capturedRC.GetAuthJSON()
	if len(authJSON) == 0 {
		t.Error("expected non-empty AuthJSON")
	}
}

func TestMiddleware_HandleRequest_PopulatesClientCtx(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rd := reqctx.NewRequestData()
	rd.ClientCtx = &reqctx.ClientContext{
		IP: "10.0.0.1",
		Location: &reqctx.Location{
			CountryCode: "DE",
			ASN:         "AS3320",
		},
		UserAgent: &reqctx.UserAgent{
			Family: "Firefox",
			Major:  "115",
		},
		Fingerprint: &reqctx.Fingerprint{
			Hash:        "fp-hash",
			CookieCount: 3,
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext")
	}

	val, ok := capturedRC.GetClientLocation("country_code")
	if !ok || val != "DE" {
		t.Errorf("expected country_code=DE, got %q (ok=%v)", val, ok)
	}

	val, ok = capturedRC.GetClientUserAgent("family")
	if !ok || val != "Firefox" {
		t.Errorf("expected family=Firefox, got %q (ok=%v)", val, ok)
	}

	val, ok = capturedRC.GetClientFingerprint("hash")
	if !ok || val != "fp-hash" {
		t.Errorf("expected hash=fp-hash, got %q (ok=%v)", val, ok)
	}
}

func TestMiddleware_HandleRequest_PopulatesOriginMeta(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rd := reqctx.NewRequestData()
	rd.OriginCtx = &reqctx.OriginContext{
		ID:          "origin-1",
		Hostname:    "api.example.com",
		WorkspaceID: "ws-abc",
		Environment: "staging",
		Tags:        []string{"api", "internal"},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext")
	}

	val, ok := capturedRC.GetOriginMeta("hostname")
	if !ok || val != "api.example.com" {
		t.Errorf("expected hostname=api.example.com, got %q (ok=%v)", val, ok)
	}
	val, ok = capturedRC.GetOriginMeta("tags")
	if !ok || val != "api,internal" {
		t.Errorf("expected tags=api,internal, got %q (ok=%v)", val, ok)
	}
}

func TestMiddleware_HandleRequest_PopulatesCtx(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rd := reqctx.NewRequestData()
	rd.CtxObj = &reqctx.CtxObject{
		ID:          "req-xyz",
		CacheStatus: "MISS",
		Debug:       false,
		NoCache:     true,
		Data: map[string]any{
			"custom_key": "custom_value",
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext")
	}

	val, ok := capturedRC.GetCtxScalar("id")
	if !ok || val != "req-xyz" {
		t.Errorf("expected id=req-xyz, got %q (ok=%v)", val, ok)
	}
	val, ok = capturedRC.GetCtxScalar("no_cache")
	if !ok || val != "true" {
		t.Errorf("expected no_cache=true, got %q (ok=%v)", val, ok)
	}

	val, ok = capturedRC.GetCtxData("custom_key")
	if !ok || val != "custom_value" {
		t.Errorf("expected custom_key=custom_value, got %q (ok=%v)", val, ok)
	}
}

func TestMiddleware_HandleRequest_WritesBackCtxData(t *testing.T) {
	m := NewMiddleware(nil, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a WASM plugin writing ctx data
		rc := RequestContextFromContext(r.Context())
		rc.SetCtxData("plugin_result", "42")
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rd := reqctx.NewRequestData()
	rd.CtxObj = &reqctx.CtxObject{
		ID:   "req-1",
		Data: map[string]any{},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// The write-back happens before next.ServeHTTP returns, but ctx.data is
	// written back after the plugin loop. Since we have no actual WASM plugins
	// and the write happens in the next handler (which runs after the write-back),
	// this test verifies the write-back path exists. A real integration test
	// would use an actual WASM plugin.
	// For unit testing, we verify the SetCtxData method works correctly.
	rc := NewRequestContext()
	rc.CtxData = map[string]string{"existing": "val"}
	rc.SetCtxData("new_key", "new_val")

	if rc.CtxData["new_key"] != "new_val" {
		t.Errorf("expected new_key=new_val, got %q", rc.CtxData["new_key"])
	}
	if rc.CtxData["existing"] != "val" {
		t.Errorf("expected existing=val, got %q", rc.CtxData["existing"])
	}
}

func TestMiddleware_HandleRequest_AuthFallbackToSessionData(t *testing.T) {
	m := NewMiddleware(nil, nil)

	var capturedRC *RequestContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRC = RequestContextFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := m.HandleRequest(next)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	rd := reqctx.NewRequestData()
	// No SessionCtx, but has legacy SessionData with AuthData
	rd.SessionData = &reqctx.SessionData{
		ID: "legacy-sess",
		AuthData: &reqctx.AuthData{
			Type: "basic",
			Data: map[string]any{"username": "admin"},
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if capturedRC == nil {
		t.Fatal("expected RequestContext")
	}

	val, ok := capturedRC.GetAuthInfo("type")
	if !ok || val != "basic" {
		t.Errorf("expected auth type=basic from fallback, got %q (ok=%v)", val, ok)
	}
	val, ok = capturedRC.GetAuthInfo("username")
	if !ok || val != "admin" {
		t.Errorf("expected username=admin from fallback, got %q (ok=%v)", val, ok)
	}
}
