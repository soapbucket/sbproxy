// compiler_smoke_test.go provides fast smoke tests for the compiled handler chain.
// These tests verify that each feature compiles and serves a basic request correctly.
// Run with: go test ./internal/config/ -run TestSmoke -v
// Target: < 2 seconds total.
package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// --- Smoke Test Helpers ---

// smokeAction returns a JSON response with a "smoke" field.
type smokeAction struct{}

func (smokeAction) Type() string { return "smoke_action" }
func (smokeAction) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"smoke":"ok"}`))
}

func init() {
	plugin.RegisterAction("smoke_action", func(_ json.RawMessage) (plugin.ActionHandler, error) {
		return smokeAction{}, nil
	})
}

// smokeCompile compiles a RawOrigin and sends a GET request, returning the recorder.
func smokeCompile(t *testing.T, raw *RawOrigin) *httptest.ResponseRecorder {
	t.Helper()
	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin failed: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)
	return rec
}

// --- Smoke Tests ---

func TestSmoke_BasicAction(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-1", Hostname: "smoke.test",
		Action: json.RawMessage(`{"type":"smoke_action"}`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_Auth(t *testing.T) {
	plugin.RegisterAuth("smoke_auth", func(_ json.RawMessage) (plugin.AuthProvider, error) {
		return &testAuth{called: &atomic.Bool{}}, nil
	})
	defer plugin.RegisterAuth("smoke_auth", nil)

	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-2", Hostname: "smoke-auth.test",
		Action: json.RawMessage(`{"type":"smoke_action"}`),
		Auth:   json.RawMessage(`{"type":"smoke_auth"}`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_Policy(t *testing.T) {
	plugin.RegisterPolicy("smoke_policy", func(_ json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &testPolicy{called: &atomic.Bool{}}, nil
	})
	defer plugin.RegisterPolicy("smoke_policy", nil)

	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-3", Hostname: "smoke-policy.test",
		Action:   json.RawMessage(`{"type":"smoke_action"}`),
		Policies: []json.RawMessage{json.RawMessage(`{"type":"smoke_policy"}`)},
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_RequestModifiers(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-4", Hostname: "smoke-reqmod.test",
		Action:    json.RawMessage(`{"type":"smoke_action"}`),
		Modifiers: json.RawMessage(`[{"headers":{"set":{"X-Smoke":"yes"}}}]`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_ResponseModifiers(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-5", Hostname: "smoke-respmod.test",
		Action:            json.RawMessage(`{"type":"smoke_action"}`),
		ResponseModifiers: json.RawMessage(`[{"headers":{"set":{"X-Resp-Smoke":"yes"}}}]`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Resp-Smoke") != "yes" {
		t.Errorf("missing response modifier header")
	}
}

func TestSmoke_Compression(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-6", Hostname: "smoke-compress.test",
		Action:      json.RawMessage(`{"type":"smoke_action"}`),
		Compression: json.RawMessage(`{"enable":true,"algorithms":["gzip"],"min_size":1}`),
	})
	// Without Accept-Encoding, no compression applied
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_CORS(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-7", Hostname: "smoke-cors.test",
		Action: json.RawMessage(`{"type":"smoke_action"}`),
		CORS:   json.RawMessage(`{"enable":true,"allow_origins":["*"]}`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_HSTS(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-8", Hostname: "smoke-hsts.test",
		Action: json.RawMessage(`{"type":"smoke_action"}`),
		HSTS:   json.RawMessage(`{"enabled":true,"max_age":31536000}`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_ErrorPages(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-9", Hostname: "smoke-errorpages.test",
		Action:     json.RawMessage(`{"type":"smoke_action"}`),
		ErrorPages: json.RawMessage(`[{"status":[404],"body":"not found"}]`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_AllowedMethods(t *testing.T) {
	compiled, err := CompileOrigin(&RawOrigin{
		ID: "smoke-10", Hostname: "smoke-methods.test",
		Action:         json.RawMessage(`{"type":"smoke_action"}`),
		AllowedMethods: []string{"GET", "POST"},
	}, noopServiceProvider{})
	if err != nil {
		t.Fatal(err)
	}

	// GET should work
	rec := httptest.NewRecorder()
	compiled.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Errorf("GET status = %d, want 200", rec.Code)
	}

	// DELETE should be blocked
	rec2 := httptest.NewRecorder()
	compiled.ServeHTTP(rec2, httptest.NewRequest("DELETE", "/", nil))
	if rec2.Code != 405 {
		t.Errorf("DELETE status = %d, want 405", rec2.Code)
	}
}

func TestSmoke_ForceSSL(t *testing.T) {
	compiled, err := CompileOrigin(&RawOrigin{
		ID: "smoke-11", Hostname: "smoke-ssl.test",
		Action:   json.RawMessage(`{"type":"smoke_action"}`),
		ForceSSL: true,
	}, noopServiceProvider{})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	compiled.ServeHTTP(rec, httptest.NewRequest("GET", "http://smoke-ssl.test/", nil))
	if rec.Code != 301 {
		t.Errorf("HTTP status = %d, want 301 redirect", rec.Code)
	}
}

func TestSmoke_Transform(t *testing.T) {
	plugin.RegisterTransform("smoke_transform", func(_ json.RawMessage) (plugin.TransformHandler, error) {
		return &testJSONInjectTransform{field: "transformed", value: "yes"}, nil
	})
	defer plugin.RegisterTransform("smoke_transform", nil)

	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-12", Hostname: "smoke-transform.test",
		Action:     json.RawMessage(`{"type":"smoke_action"}`),
		Transforms: []json.RawMessage{json.RawMessage(`{"type":"smoke_transform"}`)},
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "transformed") {
		t.Errorf("transform not applied: body = %s", rec.Body.String())
	}
}

func TestSmoke_OnRequest(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-13", Hostname: "smoke-onreq.test",
		Action:    json.RawMessage(`{"type":"smoke_action"}`),
		OnRequest: json.RawMessage(`[]`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_ResponseCache(t *testing.T) {
	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-14", Hostname: "smoke-cache.test",
		Action: json.RawMessage(`{"type":"smoke_action"}`),
		Cache:  json.RawMessage(`{"enabled":true,"ttl":"60s"}`),
	})
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestSmoke_FullPipeline(t *testing.T) {
	// Compile with ALL features enabled to verify no panics or conflicts
	plugin.RegisterAuth("smoke_auth_fp", func(_ json.RawMessage) (plugin.AuthProvider, error) {
		return &testAuth{called: &atomic.Bool{}}, nil
	})
	plugin.RegisterPolicy("smoke_policy_fp", func(_ json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &testPolicy{called: &atomic.Bool{}}, nil
	})
	defer func() {
		plugin.RegisterAuth("smoke_auth_fp", nil)
		plugin.RegisterPolicy("smoke_policy_fp", nil)
	}()

	rec := smokeCompile(t, &RawOrigin{
		ID: "smoke-full", Hostname: "smoke-full.test",
		Action:            json.RawMessage(`{"type":"smoke_action"}`),
		Auth:              json.RawMessage(`{"type":"smoke_auth_fp"}`),
		Policies:          []json.RawMessage{json.RawMessage(`{"type":"smoke_policy_fp"}`)},
		Modifiers:         json.RawMessage(`[{"headers":{"set":{"X-Req":"1"}}}]`),
		ResponseModifiers: json.RawMessage(`[{"headers":{"set":{"X-Resp":"1"}}}]`),
		Compression:       json.RawMessage(`{"enable":true,"algorithms":["gzip"],"min_size":1}`),
		CORS:              json.RawMessage(`{"enable":true,"allow_origins":["*"]}`),
		HSTS:              json.RawMessage(`{"enabled":true,"max_age":31536000}`),
		ErrorPages:        json.RawMessage(`[{"status":[404],"body":"nope"}]`),
		OnRequest:         json.RawMessage(`[]`),
		Cache:             json.RawMessage(`{"enabled":true,"ttl":"60s"}`),
		AllowedMethods:    []string{"GET", "POST"},
	})
	if rec.Code != 200 {
		t.Errorf("full pipeline status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Resp") != "1" {
		t.Error("response modifier not applied in full pipeline")
	}
}
