package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testEchoAction is a minimal action that writes "echo" with status 200.
type testEchoAction struct{}

func (testEchoAction) Type() string                                    { return "test_echo" }
func (testEchoAction) ServeHTTP(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("echo")) }

// testAuth records that it was called and delegates to next.
type testAuth struct {
	called *atomic.Bool
}

func (a *testAuth) Type() string { return "test_auth" }
func (a *testAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.called.Store(true)
		next.ServeHTTP(w, r)
	})
}

// testPolicy records that it was called and delegates to next.
type testPolicy struct {
	called *atomic.Bool
}

func (p *testPolicy) Type() string { return "test_policy" }
func (p *testPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.called.Store(true)
		next.ServeHTTP(w, r)
	})
}

// testProvisionableAction records that Provision was called and captures the context.
type testProvisionableAction struct {
	testEchoAction
	provisioned *atomic.Bool
	capturedCtx plugin.PluginContext
}

func (a *testProvisionableAction) Provision(ctx plugin.PluginContext) error {
	a.provisioned.Store(true)
	a.capturedCtx = ctx
	return nil
}

// testCleanableAction records that Cleanup was called.
type testCleanableAction struct {
	testEchoAction
	cleanedUp *atomic.Bool
}

func (a *testCleanableAction) Cleanup() error {
	a.cleanedUp.Store(true)
	return nil
}

// noopServiceProvider satisfies plugin.ServiceProvider with no-op implementations.
type noopServiceProvider struct{}

func (noopServiceProvider) KVStore() plugin.KVStore             { return noopKV{} }
func (noopServiceProvider) Cache() plugin.CacheStore            { return noopCache{} }
func (noopServiceProvider) Events() plugin.EventEmitter         { return noopEvents{} }
func (noopServiceProvider) Logger() *slog.Logger                { return slog.Default() }
func (noopServiceProvider) Metrics() plugin.Observer            { return plugin.NoopObserver() }
func (noopServiceProvider) TransportFor(plugin.TransportConfig) http.RoundTripper {
	return http.DefaultTransport
}
func (noopServiceProvider) ResolveOriginHandler(string) (http.Handler, error)           { return nil, nil }
func (noopServiceProvider) ResolveEmbeddedOriginHandler(json.RawMessage) (http.Handler, error) {
	return nil, nil
}
func (noopServiceProvider) ResponseCache() plugin.ResponseCache         { return nil }
func (noopServiceProvider) Sessions() plugin.SessionProvider            { return nil }
func (noopServiceProvider) HealthStatus(string) plugin.HealthState      { return plugin.HealthState{} }
func (noopServiceProvider) SetHealthStatus(string, plugin.HealthState)  {}

type noopKV struct{}

func (noopKV) Get(context.Context, string) ([]byte, error)              { return nil, nil }
func (noopKV) Set(context.Context, string, []byte, time.Duration) error { return nil }
func (noopKV) Delete(context.Context, string) error                     { return nil }
func (noopKV) Increment(context.Context, string, int64) (int64, error)  { return 0, nil }

type noopCache struct{}

func (noopCache) Get(context.Context, string) (interface{}, bool)              { return nil, false }
func (noopCache) Set(context.Context, string, interface{}, time.Duration)      {}

type noopEvents struct{}

func (noopEvents) Emit(context.Context, string, map[string]any) error { return nil }
func (noopEvents) Enabled(string) bool                                { return false }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCompileOrigin_BasicAction(t *testing.T) {
	// Register a test action factory.
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil) // cleanup registry

	raw := &RawOrigin{
		ID:       "o1",
		Hostname: "example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

func TestCompileOrigin_WithAuthAndPolicy(t *testing.T) {
	authCalled := &atomic.Bool{}
	policyCalled := &atomic.Bool{}

	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	plugin.RegisterAuth("test_auth", func(cfg json.RawMessage) (plugin.AuthProvider, error) {
		return &testAuth{called: authCalled}, nil
	})
	plugin.RegisterPolicy("test_policy", func(cfg json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &testPolicy{called: policyCalled}, nil
	})
	defer func() {
		plugin.RegisterAction("test_echo", nil)
		plugin.RegisterAuth("test_auth", nil)
		plugin.RegisterPolicy("test_policy", nil)
	}()

	raw := &RawOrigin{
		ID:       "o2",
		Hostname: "auth.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		Auth:     json.RawMessage(`{"type":"test_auth"}`),
		Policies: []json.RawMessage{
			json.RawMessage(`{"type":"test_policy"}`),
		},
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if !policyCalled.Load() {
		t.Error("policy was not called")
	}
	if !authCalled.Load() {
		t.Error("auth was not called")
	}
	if rec.Code != 200 {
		t.Error("expected 200 after policy + auth + action")
	}
	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

func TestCompileOrigin_InvalidAction(t *testing.T) {
	raw := &RawOrigin{
		ID:       "o3",
		Hostname: "bad.example.com",
		Action:   json.RawMessage(`{"type":"nonexistent_action_xyz"}`),
	}

	_, err := CompileOrigin(raw, noopServiceProvider{})
	if err == nil {
		t.Fatal("expected error for unknown action type, got nil")
	}
}

func TestCompileOrigin_MissingHostname(t *testing.T) {
	raw := &RawOrigin{
		Action: json.RawMessage(`{"type":"proxy"}`),
	}

	_, err := CompileOrigin(raw, noopServiceProvider{})
	if err == nil {
		t.Fatal("expected error for missing hostname, got nil")
	}
}

func TestCompileOrigin_Provisioning(t *testing.T) {
	provisioned := &atomic.Bool{}
	var capturedAction *testProvisionableAction

	plugin.RegisterAction("test_provisionable", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		a := &testProvisionableAction{provisioned: provisioned}
		capturedAction = a
		return a, nil
	})
	defer plugin.RegisterAction("test_provisionable", nil)

	raw := &RawOrigin{
		ID:          "o5",
		Hostname:    "prov.example.com",
		WorkspaceID: "ws-42",
		Version:     "v3",
		Action:      json.RawMessage(`{"type":"test_provisionable"}`),
	}

	_, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	if !provisioned.Load() {
		t.Error("Provision was not called")
	}
	if capturedAction.capturedCtx.OriginID != "o5" {
		t.Errorf("OriginID = %q, want %q", capturedAction.capturedCtx.OriginID, "o5")
	}
	if capturedAction.capturedCtx.WorkspaceID != "ws-42" {
		t.Errorf("WorkspaceID = %q, want %q", capturedAction.capturedCtx.WorkspaceID, "ws-42")
	}
	if capturedAction.capturedCtx.Hostname != "prov.example.com" {
		t.Errorf("Hostname = %q, want %q", capturedAction.capturedCtx.Hostname, "prov.example.com")
	}
}

func TestCompileOrigin_Cleanup(t *testing.T) {
	cleanedUp := &atomic.Bool{}

	plugin.RegisterAction("test_cleanable", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return &testCleanableAction{cleanedUp: cleanedUp}, nil
	})
	defer plugin.RegisterAction("test_cleanable", nil)

	raw := &RawOrigin{
		ID:       "o6",
		Hostname: "cleanup.example.com",
		Action:   json.RawMessage(`{"type":"test_cleanable"}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	compiled.Cleanup()

	if !cleanedUp.Load() {
		t.Error("Cleanup was not called")
	}
}

// ---------------------------------------------------------------------------
// Middleware wrapper tests
// ---------------------------------------------------------------------------

func TestCompileOrigin_Compression(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "comp1",
		Hostname: "compress.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		Compression: json.RawMessage(`{
			"enable": true,
			"algorithms": ["gzip"],
			"min_size": 1
		}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	// Request with Accept-Encoding: gzip should get compressed response.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", enc, "gzip")
	}

	// Request without Accept-Encoding should get uncompressed response.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec2, req2)

	if enc := rec2.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("expected no Content-Encoding without Accept-Encoding, got %q", enc)
	}
	if rec2.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec2.Body.String(), "echo")
	}
}

func TestCompileOrigin_CompressionDisabled(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "comp2",
		Hostname: "nocompress.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		Compression: json.RawMessage(`{"enable": false}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	compiled.ServeHTTP(rec, req)

	// Should not compress when disabled.
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("expected no Content-Encoding when disabled, got %q", enc)
	}
	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

func TestCompileOrigin_CORS_Preflight(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "cors1",
		Hostname: "cors.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		CORS: json.RawMessage(`{
			"enable": true,
			"allow_origins": ["https://app.example.com"],
			"allow_methods": ["GET", "POST"],
			"allow_headers": ["Content-Type", "Authorization"],
			"max_age": 3600
		}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	// Preflight request should be handled.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/api/data", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	compiled.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if acao := rec.Header().Get("Access-Control-Allow-Origin"); acao != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", acao, "https://app.example.com")
	}
	if acam := rec.Header().Get("Access-Control-Allow-Methods"); acam != "GET, POST" {
		t.Errorf("Access-Control-Allow-Methods = %q, want %q", acam, "GET, POST")
	}
}

func TestCompileOrigin_CORS_NormalRequest(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "cors2",
		Hostname: "cors2.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		CORS: json.RawMessage(`{
			"enable": true,
			"allow_origins": ["*"]
		}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://any.example.com")
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if acao := rec.Header().Get("Access-Control-Allow-Origin"); acao != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", acao, "*")
	}
	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

func TestCompileOrigin_HSTS(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "hsts1",
		Hostname: "hsts.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		HSTS: json.RawMessage(`{
			"enabled": true,
			"max_age": 31536000,
			"include_subdomains": true,
			"preload": true
		}`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	// HTTPS request should get HSTS header.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://hsts.example.com/", nil)
	req.TLS = &tls.ConnectionState{} // simulate HTTPS
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	sts := rec.Header().Get("Strict-Transport-Security")
	if sts == "" {
		t.Fatal("expected Strict-Transport-Security header on HTTPS request")
	}
	if !strings.Contains(sts, "max-age=31536000") {
		t.Errorf("HSTS header missing max-age: %q", sts)
	}
	if !strings.Contains(sts, "includeSubDomains") {
		t.Errorf("HSTS header missing includeSubDomains: %q", sts)
	}
	if !strings.Contains(sts, "preload") {
		t.Errorf("HSTS header missing preload: %q", sts)
	}

	// HTTP request should NOT get HSTS header.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "http://hsts.example.com/", nil)
	compiled.ServeHTTP(rec2, req2)
	if sts2 := rec2.Header().Get("Strict-Transport-Security"); sts2 != "" {
		t.Errorf("expected no HSTS header on HTTP request, got %q", sts2)
	}
}

func TestCompileOrigin_ForceSSL(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "ssl1",
		Hostname: "ssl.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		ForceSSL: true,
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	// HTTP request should be redirected.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://ssl.example.com/path?q=1", nil)
	req.Host = "ssl.example.com"
	compiled.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://ssl.example.com/path") {
		t.Errorf("Location = %q, want https redirect", loc)
	}
	if !strings.Contains(loc, "q=1") {
		t.Errorf("Location = %q, missing query string", loc)
	}

	// HTTPS request should pass through.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "https://ssl.example.com/path", nil)
	req2.TLS = &tls.ConnectionState{}
	compiled.ServeHTTP(rec2, req2)

	if rec2.Code != 200 {
		t.Errorf("HTTPS status = %d, want 200", rec2.Code)
	}
	if rec2.Body.String() != "echo" {
		t.Errorf("HTTPS body = %q, want %q", rec2.Body.String(), "echo")
	}
}

func TestCompileOrigin_AllowedMethods(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:             "methods1",
		Hostname:       "methods.example.com",
		Action:         json.RawMessage(`{"type":"test_echo"}`),
		AllowedMethods: []string{"GET", "POST"},
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	tests := []struct {
		method     string
		wantStatus int
	}{
		{"GET", 200},
		{"POST", 200},
		{"PUT", http.StatusMethodNotAllowed},
		{"DELETE", http.StatusMethodNotAllowed},
		{"OPTIONS", http.StatusNoContent}, // always allowed
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, "/", nil)
			compiled.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("%s status = %d, want %d", tt.method, rec.Code, tt.wantStatus)
			}
		})
	}

	// Check Allow header on 405 response.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/", nil)
	compiled.ServeHTTP(rec, req)
	if allow := rec.Header().Get("Allow"); allow != "GET, POST" {
		t.Errorf("Allow header = %q, want %q", allow, "GET, POST")
	}
}

// ---------------------------------------------------------------------------
// Transform tests
// ---------------------------------------------------------------------------

// testJSONInjectTransform adds a field to JSON response bodies.
type testJSONInjectTransform struct {
	field string
	value string
}

func (t *testJSONInjectTransform) Type() string { return "test_json_inject" }

func (t *testJSONInjectTransform) Apply(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return err
	}
	m[t.field] = t.value
	modified, err := json.Marshal(m)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(modified))
	resp.ContentLength = int64(len(modified))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(modified)))
	return nil
}

// testJSONAction writes a static JSON response.
type testJSONAction struct {
	body string
}

func (a *testJSONAction) Type() string { return "test_json" }
func (a *testJSONAction) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(a.body))
}

func TestCompileOrigin_TransformApplied(t *testing.T) {
	plugin.RegisterAction("test_json", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return &testJSONAction{body: `{"greeting":"hello"}`}, nil
	})
	plugin.RegisterTransform("test_json_inject", func(cfg json.RawMessage) (plugin.TransformHandler, error) {
		return &testJSONInjectTransform{field: "added", value: "yes"}, nil
	})
	defer func() {
		plugin.RegisterAction("test_json", nil)
		plugin.RegisterTransform("test_json_inject", nil)
	}()

	raw := &RawOrigin{
		ID:       "t1",
		Hostname: "transform.example.com",
		Action:   json.RawMessage(`{"type":"test_json"}`),
		Transforms: []json.RawMessage{
			json.RawMessage(`{"type":"test_json_inject"}`),
		},
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response body as JSON: %v (body=%q)", err, rec.Body.String())
	}

	if result["greeting"] != "hello" {
		t.Errorf("greeting = %v, want %q", result["greeting"], "hello")
	}
	if result["added"] != "yes" {
		t.Errorf("added = %v, want %q", result["added"], "yes")
	}
}

func TestWrapTransform_DefaultStatusCode(t *testing.T) {
	// Action that writes body without calling WriteHeader explicitly.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"key":"val"}`))
	})

	transform := &testJSONInjectTransform{field: "extra", value: "data"}
	handler := wrapTransform(inner, transform)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if result["extra"] != "data" {
		t.Errorf("extra = %v, want %q", result["extra"], "data")
	}
}

func TestWrapTransform_PreservesStatusCode(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"123"}`))
	})

	transform := &testJSONInjectTransform{field: "status", value: "created"}
	handler := wrapTransform(inner, transform)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if result["status"] != "created" {
		t.Errorf("status field = %v, want %q", result["status"], "created")
	}
}

// testHeaderEchoAction writes the value of X-Custom header as the response body.
type testHeaderEchoAction struct{}

func (testHeaderEchoAction) Type() string { return "test_header_echo" }
func (testHeaderEchoAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.Header.Get("X-Custom")))
}

func TestCompileOrigin_RequestModifiers(t *testing.T) {
	plugin.RegisterAction("test_header_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testHeaderEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_header_echo", nil)

	raw := &RawOrigin{
		ID:       "rm1",
		Hostname: "reqmod.example.com",
		Action:   json.RawMessage(`{"type":"test_header_echo"}`),
		Modifiers: json.RawMessage(`[{"headers":{"set":{"X-Custom":"injected-value"}}}]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Body.String() != "injected-value" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "injected-value")
	}
}

func TestCompileOrigin_RequestModifiers_Empty(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "rm2",
		Hostname: "reqmod-empty.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		Modifiers: json.RawMessage(`[]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

// ---------------------------------------------------------------------------
// Response modifier tests
// ---------------------------------------------------------------------------

// testResponseHeaderAction writes a response with a known header and body.
type testResponseHeaderAction struct{}

func (testResponseHeaderAction) Type() string { return "test_resp_header" }
func (testResponseHeaderAction) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-Original", "present")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("original-body"))
}

func TestCompileOrigin_ResponseModifiers(t *testing.T) {
	plugin.RegisterAction("test_resp_header", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testResponseHeaderAction{}, nil
	})
	defer plugin.RegisterAction("test_resp_header", nil)

	raw := &RawOrigin{
		ID:       "respmod1",
		Hostname: "respmod.example.com",
		Action:   json.RawMessage(`{"type":"test_resp_header"}`),
		ResponseModifiers: json.RawMessage(`[{"headers":{"set":{"X-Modified":"true"}}}]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Modified"); got != "true" {
		t.Errorf("X-Modified = %q, want %q", got, "true")
	}
	if got := rec.Header().Get("X-Original"); got != "present" {
		t.Errorf("X-Original = %q, want %q (should be preserved)", got, "present")
	}
	if rec.Body.String() != "original-body" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "original-body")
	}
}

func TestCompileOrigin_ResponseModifiers_StatusOverride(t *testing.T) {
	plugin.RegisterAction("test_resp_header", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testResponseHeaderAction{}, nil
	})
	defer plugin.RegisterAction("test_resp_header", nil)

	raw := &RawOrigin{
		ID:       "respmod2",
		Hostname: "respmod2.example.com",
		Action:   json.RawMessage(`{"type":"test_resp_header"}`),
		ResponseModifiers: json.RawMessage(`[{"status":{"code":201},"headers":{"set":{"X-Modified":"yes"}}}]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("X-Modified"); got != "yes" {
		t.Errorf("X-Modified = %q, want %q", got, "yes")
	}
}

func TestCompileOrigin_ResponseModifiers_Empty(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:                "respmod3",
		Hostname:          "respmod-empty.example.com",
		Action:            json.RawMessage(`{"type":"test_echo"}`),
		ResponseModifiers: json.RawMessage(`[]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

func TestCompileOrigin_ResponseModifiers_Nil(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "respmod4",
		Hostname: "respmod-nil.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		// ResponseModifiers not set (nil)
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Body.String() != "echo" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "echo")
	}
}

// ---------------------------------------------------------------------------
// On-request callback tests
// ---------------------------------------------------------------------------

func TestWrapOnRequest_NilConfig(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// nil config should return the same handler (no-op).
	got := wrapOnRequest(inner, nil)
	if fmt.Sprintf("%p", got) != fmt.Sprintf("%p", inner) {
		t.Error("wrapOnRequest(nil) should return the original handler")
	}
}

func TestWrapOnRequest_EmptyConfig(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Empty JSON array should return the original handler.
	got := wrapOnRequest(inner, json.RawMessage(`[]`))
	if fmt.Sprintf("%p", got) != fmt.Sprintf("%p", inner) {
		t.Error("wrapOnRequest([]) should return the original handler")
	}

	// "null" should return the original handler.
	got2 := wrapOnRequest(inner, json.RawMessage(`null`))
	if fmt.Sprintf("%p", got2) != fmt.Sprintf("%p", inner) {
		t.Error("wrapOnRequest(null) should return the original handler")
	}
}

func TestWrapOnRequest_InvalidConfig(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Invalid JSON should log a warning and return the original handler.
	got := wrapOnRequest(inner, json.RawMessage(`{invalid`))
	if fmt.Sprintf("%p", got) != fmt.Sprintf("%p", inner) {
		t.Error("wrapOnRequest(invalid JSON) should return the original handler")
	}
}

func TestCompileOrigin_OnRequestField(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	// CompileOrigin should accept a config with on_request without error,
	// even if the callback URL is unreachable (callbacks run at request time).
	raw := &RawOrigin{
		ID:       "onreq1",
		Hostname: "onreq.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		OnRequest: json.RawMessage(`[{
			"url": "https://unreachable.example.com/webhook",
			"method": "POST",
			"timeout": "2s"
		}]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin with on_request should not fail: %v", err)
	}

	// The handler should still serve requests (callback failure is non-fatal).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCompileOrigin_AllowedMethodsCaseInsensitive(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:             "methods2",
		Hostname:       "methods2.example.com",
		Action:         json.RawMessage(`{"type":"test_echo"}`),
		AllowedMethods: []string{"get", "post"},
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("GET status = %d, want 200 (case-insensitive match)", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Error pages tests
// ---------------------------------------------------------------------------

// test404Action writes a 404 response.
type test404Action struct{}

func (test404Action) Type() string { return "test_404" }
func (test404Action) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("default not found"))
}

func TestCompileOrigin_ErrorPages_CustomBody(t *testing.T) {
	plugin.RegisterAction("test_404", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return test404Action{}, nil
	})
	defer plugin.RegisterAction("test_404", nil)

	raw := &RawOrigin{
		ID:       "ep1",
		Hostname: "errorpages.example.com",
		Action:   json.RawMessage(`{"type":"test_404"}`),
		ErrorPages: json.RawMessage(`[
			{
				"status": [404],
				"content_type": "text/plain",
				"body": "Custom 404 page"
			}
		]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/missing", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if body := rec.Body.String(); body != "Custom 404 page" {
		t.Errorf("body = %q, want %q", body, "Custom 404 page")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
}

func TestCompileOrigin_ErrorPages_Template(t *testing.T) {
	plugin.RegisterAction("test_404", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return test404Action{}, nil
	})
	defer plugin.RegisterAction("test_404", nil)

	raw := &RawOrigin{
		ID:       "ep2",
		Hostname: "errorpages-tpl.example.com",
		Action:   json.RawMessage(`{"type":"test_404"}`),
		ErrorPages: json.RawMessage(`[
			{
				"status": [404],
				"content_type": "text/plain",
				"template": true,
				"body": "Error {{ status_code }}: {{ error }} at {{ request.path }}"
			}
		]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/missing-page", nil)
	compiled.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	want := "Error 404: Not Found at /missing-page"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestCompileOrigin_ErrorPages_NoMatchPassThrough(t *testing.T) {
	plugin.RegisterAction("test_404", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return test404Action{}, nil
	})
	defer plugin.RegisterAction("test_404", nil)

	raw := &RawOrigin{
		ID:       "ep3",
		Hostname: "errorpages-nomatch.example.com",
		Action:   json.RawMessage(`{"type":"test_404"}`),
		ErrorPages: json.RawMessage(`[
			{
				"status": [500],
				"body": "Server Error"
			}
		]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	// 404 should pass through since only 500 is configured.
	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if body := rec.Body.String(); body != "default not found" {
		t.Errorf("body = %q, want %q", body, "default not found")
	}
}

func TestCompileOrigin_ErrorPages_SuccessPassThrough(t *testing.T) {
	plugin.RegisterAction("test_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_echo", nil)

	raw := &RawOrigin{
		ID:       "ep4",
		Hostname: "errorpages-success.example.com",
		Action:   json.RawMessage(`{"type":"test_echo"}`),
		ErrorPages: json.RawMessage(`[
			{
				"status": [404],
				"body": "Not Found"
			}
		]`),
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	// 200 should pass through unmodified.
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "echo" {
		t.Errorf("body = %q, want %q", body, "echo")
	}
}
