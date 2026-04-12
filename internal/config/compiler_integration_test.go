package config

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// ---------------------------------------------------------------------------
// Full pipeline integration test
// ---------------------------------------------------------------------------

func TestCompileOrigin_FullPipeline(t *testing.T) {
	authCalled := &atomic.Bool{}
	policyCalled := &atomic.Bool{}

	// Register test plugins for the full pipeline.
	plugin.RegisterAction("test_json", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return &testJSONAction{body: `{"greeting":"hello"}`}, nil
	})
	plugin.RegisterAuth("test_auth", func(cfg json.RawMessage) (plugin.AuthProvider, error) {
		return &testAuth{called: authCalled}, nil
	})
	plugin.RegisterPolicy("test_policy", func(cfg json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &testPolicy{called: policyCalled}, nil
	})
	plugin.RegisterTransform("test_json_inject", func(cfg json.RawMessage) (plugin.TransformHandler, error) {
		return &testJSONInjectTransform{field: "injected", value: "yes"}, nil
	})
	defer func() {
		plugin.RegisterAction("test_json", nil)
		plugin.RegisterAuth("test_auth", nil)
		plugin.RegisterPolicy("test_policy", nil)
		plugin.RegisterTransform("test_json_inject", nil)
	}()

	raw := &RawOrigin{
		ID:       "full-pipeline",
		Hostname: "full.example.com",
		Action:   json.RawMessage(`{"type":"test_json"}`),
		Auth:     json.RawMessage(`{"type":"test_auth"}`),
		Policies: []json.RawMessage{
			json.RawMessage(`{"type":"test_policy"}`),
		},
		Modifiers:         json.RawMessage(`[{"headers":{"set":{"X-Request-Modified":"true"}}}]`),
		ResponseModifiers: json.RawMessage(`[{"headers":{"set":{"X-Response-Modified":"true"}}}]`),
		Transforms: []json.RawMessage{
			json.RawMessage(`{"type":"test_json_inject"}`),
		},
		ErrorPages:  json.RawMessage(`[{"status":[404],"content_type":"text/plain","body":"custom 404"}]`),
		Compression: json.RawMessage(`{"enable":true,"algorithms":["gzip"],"min_size":1}`),
		CORS:        json.RawMessage(`{"enable":true,"allow_origins":["*"]}`),
		HSTS:        json.RawMessage(`{"enabled":true,"max_age":31536000}`),
		OnRequest:   json.RawMessage(`[]`),
		AllowedMethods: []string{"GET", "POST"},
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin with full pipeline: %v", err)
	}

	// Test 1: Normal GET request goes through the full pipeline.
	t.Run("normal_GET_full_pipeline", func(t *testing.T) {
		authCalled.Store(false)
		policyCalled.Store(false)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{} // simulate HTTPS for HSTS
		req.Header.Set("Origin", "https://app.example.com")
		compiled.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		// Verify auth was called.
		if !authCalled.Load() {
			t.Error("auth was not called in full pipeline")
		}

		// Verify policy was called.
		if !policyCalled.Load() {
			t.Error("policy was not called in full pipeline")
		}

		// Verify response modifier added header.
		if rec.Header().Get("X-Response-Modified") != "true" {
			t.Error("response modifier did not add X-Response-Modified header")
		}

		// Verify HSTS header (only on HTTPS).
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Error("HSTS header missing on HTTPS request")
		}

		// Verify CORS header.
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("CORS Access-Control-Allow-Origin header missing or wrong")
		}

		// Verify transform injected a field into the JSON body.
		var result map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse response JSON: %v (body=%q)", err, rec.Body.String())
		}
		if result["greeting"] != "hello" {
			t.Errorf("greeting = %v, want %q", result["greeting"], "hello")
		}
		if result["injected"] != "yes" {
			t.Errorf("injected = %v, want %q", result["injected"], "yes")
		}
	})

	// Test 2: Disallowed method returns 405.
	t.Run("disallowed_method_405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/", nil)
		compiled.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE should be 405, got %d", rec.Code)
		}
	})

	// Test 3: OPTIONS is always allowed (CORS preflight support).
	t.Run("options_always_allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		compiled.ServeHTTP(rec, req)

		// OPTIONS should get 204 (NoContent) from allowed methods handler.
		if rec.Code != http.StatusNoContent {
			t.Errorf("OPTIONS status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})

	// Test 4: HSTS header absent on plain HTTP.
	t.Run("hsts_absent_on_http", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		// No TLS set - plain HTTP.
		compiled.ServeHTTP(rec, req)

		if rec.Header().Get("Strict-Transport-Security") != "" {
			t.Error("HSTS header should not be set on plain HTTP")
		}
	})
}

// ---------------------------------------------------------------------------
// Execution order test
// ---------------------------------------------------------------------------

// orderAction records its execution and writes a response.
type orderAction struct {
	record func(string)
}

func (a orderAction) Type() string { return "order_action" }
func (a orderAction) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	a.record("action")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}

// orderAuth records its execution and delegates to next.
type orderAuth struct {
	record func(string)
}

func (a *orderAuth) Type() string { return "order_auth" }
func (a *orderAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.record("auth")
		next.ServeHTTP(w, r)
	})
}

// orderPolicy records its execution and delegates to next.
type orderPolicy struct {
	record func(string)
}

func (p *orderPolicy) Type() string { return "order_policy" }
func (p *orderPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record("policy")
		next.ServeHTTP(w, r)
	})
}

// orderTransform records its execution.
type orderTransform struct {
	record func(string)
}

func (t *orderTransform) Type() string { return "order_transform" }
func (t *orderTransform) Apply(resp *http.Response) error {
	t.record("transform")
	return nil
}

func TestCompileOrigin_ExecutionOrder(t *testing.T) {
	var order []string
	var mu sync.Mutex

	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}

	// Register plugins that record their execution.
	plugin.RegisterAction("order_action", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return orderAction{record: record}, nil
	})
	plugin.RegisterAuth("order_auth", func(cfg json.RawMessage) (plugin.AuthProvider, error) {
		return &orderAuth{record: record}, nil
	})
	plugin.RegisterPolicy("order_policy", func(cfg json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &orderPolicy{record: record}, nil
	})
	plugin.RegisterTransform("order_transform", func(cfg json.RawMessage) (plugin.TransformHandler, error) {
		return &orderTransform{record: record}, nil
	})
	defer func() {
		plugin.RegisterAction("order_action", nil)
		plugin.RegisterAuth("order_auth", nil)
		plugin.RegisterPolicy("order_policy", nil)
		plugin.RegisterTransform("order_transform", nil)
	}()

	raw := &RawOrigin{
		ID:       "order-test",
		Hostname: "order.example.com",
		Action:   json.RawMessage(`{"type":"order_action"}`),
		Auth:     json.RawMessage(`{"type":"order_auth"}`),
		Policies: []json.RawMessage{json.RawMessage(`{"type":"order_policy"}`)},
		Transforms: []json.RawMessage{json.RawMessage(`{"type":"order_transform"}`)},
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

	// The handler chain is built inside-out:
	//   action (innermost) -> transforms -> auth -> policies (outermost)
	//
	// So on an incoming request the execution order is:
	//   policy -> auth -> action -> transform (applied to response)
	expected := []string{"policy", "auth", "action", "transform"}

	if len(order) != len(expected) {
		t.Fatalf("execution order length = %d, want %d; got %v", len(order), len(expected), order)
	}
	for i, want := range expected {
		if order[i] != want {
			t.Errorf("execution order[%d] = %q, want %q; full order: %v", i, order[i], want, order)
		}
	}
}

// ---------------------------------------------------------------------------
// Multiple policies ordering test
// ---------------------------------------------------------------------------

func TestCompileOrigin_MultiplePoliciesOrder(t *testing.T) {
	var order []string
	var mu sync.Mutex

	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}

	// Register the action.
	plugin.RegisterAction("order_action", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return orderAction{record: record}, nil
	})

	// Register two distinct policies that record different names.
	plugin.RegisterPolicy("policy_first", func(cfg json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &orderPolicy{record: func(s string) { record("policy_first") }}, nil
	})
	plugin.RegisterPolicy("policy_second", func(cfg json.RawMessage) (plugin.PolicyEnforcer, error) {
		return &orderPolicy{record: func(s string) { record("policy_second") }}, nil
	})
	defer func() {
		plugin.RegisterAction("order_action", nil)
		plugin.RegisterPolicy("policy_first", nil)
		plugin.RegisterPolicy("policy_second", nil)
	}()

	raw := &RawOrigin{
		ID:       "multi-policy",
		Hostname: "multi-policy.example.com",
		Action:   json.RawMessage(`{"type":"order_action"}`),
		Policies: []json.RawMessage{
			json.RawMessage(`{"type":"policy_first"}`),
			json.RawMessage(`{"type":"policy_second"}`),
		},
	}

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	// Policies are wrapped in reverse order so policies[0] is outermost.
	// Execution order: policy_first -> policy_second -> action.
	expected := []string{"policy_first", "policy_second", "action"}

	if len(order) != len(expected) {
		t.Fatalf("execution order length = %d, want %d; got %v", len(order), len(expected), order)
	}
	for i, want := range expected {
		if order[i] != want {
			t.Errorf("execution order[%d] = %q, want %q; full order: %v", i, order[i], want, order)
		}
	}
}

// ---------------------------------------------------------------------------
// Request modifier + action integration test
// ---------------------------------------------------------------------------

func TestCompileOrigin_RequestModifierReachesAction(t *testing.T) {
	// Verify that request modifiers are applied before the action sees the request.
	plugin.RegisterAction("test_header_echo", func(cfg json.RawMessage) (plugin.ActionHandler, error) {
		return testHeaderEchoAction{}, nil
	})
	defer plugin.RegisterAction("test_header_echo", nil)

	raw := &RawOrigin{
		ID:       "reqmod-pipeline",
		Hostname: "reqmod-pipeline.example.com",
		Action:   json.RawMessage(`{"type":"test_header_echo"}`),
		Auth:     json.RawMessage(`{"type":"test_auth"}`),
		Modifiers: json.RawMessage(`[{"headers":{"set":{"X-Custom":"from-modifier"}}}]`),
	}

	// Register auth that passes through.
	authCalled := &atomic.Bool{}
	plugin.RegisterAuth("test_auth", func(cfg json.RawMessage) (plugin.AuthProvider, error) {
		return &testAuth{called: authCalled}, nil
	})
	defer plugin.RegisterAuth("test_auth", nil)

	compiled, err := CompileOrigin(raw, noopServiceProvider{})
	if err != nil {
		t.Fatalf("CompileOrigin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	compiled.ServeHTTP(rec, req)

	// The action echoes X-Custom header value as the body.
	if got := strings.TrimSpace(rec.Body.String()); got != "from-modifier" {
		t.Errorf("body = %q, want %q (request modifier should have set X-Custom)", got, "from-modifier")
	}
	if !authCalled.Load() {
		t.Error("auth was not called")
	}
}
