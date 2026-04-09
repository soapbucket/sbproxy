package k8s

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// memoryStore is an in-memory ConfigStore for testing.
type memoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemoryStore() *memoryStore {
	return &memoryStore{data: make(map[string][]byte)}
}

func (m *memoryStore) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *memoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memoryStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *memoryStore) get(key string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	return v, ok
}

const testController = "soapbucket.io/proxy"

// setupReconciler creates a reconciler with an accepted GatewayClass and a programmed Gateway.
func setupReconciler(t *testing.T) (*DefaultReconciler, *memoryStore) {
	t.Helper()
	store := newMemoryStore()
	r := NewReconciler(store, testController)

	ctx := context.Background()

	if err := r.ReconcileGatewayClass(ctx, GatewayClass{
		Name:           "soapbucket",
		ControllerName: testController,
		Description:    "SoapBucket proxy class",
	}); err != nil {
		t.Fatalf("setup GatewayClass: %v", err)
	}

	if err := r.ReconcileGateway(ctx, Gateway{
		Name:      "main-gw",
		Namespace: "default",
		Class:     "soapbucket",
		Listeners: []GatewayListener{
			{Name: "http", Port: 80, Protocol: "HTTP"},
		},
	}); err != nil {
		t.Fatalf("setup Gateway: %v", err)
	}

	return r, store
}

func TestReconcileGatewayClass(t *testing.T) {
	store := newMemoryStore()
	r := NewReconciler(store, testController)
	ctx := context.Background()

	t.Run("accepts matching controller", func(t *testing.T) {
		gc := GatewayClass{
			Name:           "soapbucket",
			ControllerName: testController,
			Description:    "SoapBucket proxy class",
		}
		if err := r.ReconcileGatewayClass(ctx, gc); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		r.mu.RLock()
		stored, ok := r.gatewayClasses["soapbucket"]
		r.mu.RUnlock()

		if !ok {
			t.Fatal("GatewayClass not stored")
		}
		if !stored.Status.Accepted {
			t.Error("GatewayClass should be accepted")
		}
		if !stored.Status.Programmed {
			t.Error("GatewayClass should be programmed")
		}
	})

	t.Run("ignores non-matching controller", func(t *testing.T) {
		gc := GatewayClass{
			Name:           "other",
			ControllerName: "other.io/controller",
		}
		if err := r.ReconcileGatewayClass(ctx, gc); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		r.mu.RLock()
		_, ok := r.gatewayClasses["other"]
		r.mu.RUnlock()

		if ok {
			t.Error("non-matching GatewayClass should not be stored")
		}
	})
}

func TestReconcileGateway(t *testing.T) {
	store := newMemoryStore()
	r := NewReconciler(store, testController)
	ctx := context.Background()

	// Setup class first.
	if err := r.ReconcileGatewayClass(ctx, GatewayClass{
		Name:           "soapbucket",
		ControllerName: testController,
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	t.Run("rejects unknown class", func(t *testing.T) {
		gw := Gateway{Name: "gw", Class: "nonexistent", Listeners: []GatewayListener{{Name: "http", Port: 80, Protocol: "HTTP"}}}
		if err := r.ReconcileGateway(ctx, gw); err == nil {
			t.Error("expected error for unknown class")
		}
	})

	t.Run("rejects gateway with no listeners", func(t *testing.T) {
		gw := Gateway{Name: "gw", Class: "soapbucket"}
		if err := r.ReconcileGateway(ctx, gw); err == nil {
			t.Error("expected error for no listeners")
		}
	})

	t.Run("accepts valid gateway", func(t *testing.T) {
		gw := Gateway{
			Name:      "main-gw",
			Namespace: "default",
			Class:     "soapbucket",
			Listeners: []GatewayListener{
				{Name: "http", Port: 80, Protocol: "HTTP"},
				{Name: "https", Port: 443, Protocol: "HTTPS", TLS: &GatewayTLSConfig{Mode: "Terminate", CertificateRef: "my-cert"}},
			},
		}
		if err := r.ReconcileGateway(ctx, gw); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		r.mu.RLock()
		stored, ok := r.gateways["default/main-gw"]
		r.mu.RUnlock()

		if !ok {
			t.Fatal("Gateway not stored")
		}
		if len(stored.Status.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(stored.Status.Conditions))
		}
		if stored.Status.Conditions[0].Status != "True" {
			t.Error("expected Accepted condition to be True")
		}
	})
}

func TestReconcileHTTPRoute(t *testing.T) {
	r, store := setupReconciler(t)
	ctx := context.Background()

	route := HTTPRoute{
		Name:      "api-route",
		Namespace: "default",
		Hostnames: []string{"api.example.com"},
		ParentRef: "default/main-gw",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{Path: &PathMatch{Type: "PathPrefix", Value: "/v1/"}},
				},
				BackendRefs: []BackendRef{
					{Name: "api-svc", Namespace: "default", Port: 8080},
				},
				Timeouts: &RouteTimeouts{Request: "30s", BackendRequest: "10s"},
			},
		},
	}

	if err := r.ReconcileHTTPRoute(ctx, route); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, ok := store.get("httproute/default/api-route/rule/0")
	if !ok {
		t.Fatal("origin config not stored")
	}

	var origin OriginConfig
	if err := json.Unmarshal(data, &origin); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if origin.ID != "default-api-route-rule-0" {
		t.Errorf("unexpected ID: %s", origin.ID)
	}

	if len(origin.Hosts) != 1 || origin.Hosts[0] != "api.example.com" {
		t.Errorf("unexpected hosts: %v", origin.Hosts)
	}

	if len(origin.Paths) != 1 || origin.Paths[0] != "/v1/" {
		t.Errorf("unexpected paths: %v", origin.Paths)
	}

	if origin.Action["type"] != "proxy" {
		t.Errorf("unexpected action type: %v", origin.Action["type"])
	}

	if origin.Action["url"] != "http://api-svc.default:8080" {
		t.Errorf("unexpected action url: %v", origin.Action["url"])
	}

	if origin.Action["timeout"] != "30s" {
		t.Errorf("unexpected timeout: %v", origin.Action["timeout"])
	}

	if origin.Action["backend_timeout"] != "10s" {
		t.Errorf("unexpected backend_timeout: %v", origin.Action["backend_timeout"])
	}
}

func TestReconcileHTTPRoute_WeightedBackends(t *testing.T) {
	r, store := setupReconciler(t)
	ctx := context.Background()

	route := HTTPRoute{
		Name:      "canary-route",
		Namespace: "default",
		Hostnames: []string{"app.example.com"},
		ParentRef: "default/main-gw",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{Path: &PathMatch{Type: "PathPrefix", Value: "/"}},
				},
				BackendRefs: []BackendRef{
					{Name: "stable", Namespace: "default", Port: 8080, Weight: 90},
					{Name: "canary", Namespace: "default", Port: 8080, Weight: 10},
				},
			},
		},
	}

	if err := r.ReconcileHTTPRoute(ctx, route); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, ok := store.get("httproute/default/canary-route/rule/0")
	if !ok {
		t.Fatal("origin config not stored")
	}

	var origin OriginConfig
	if err := json.Unmarshal(data, &origin); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if origin.Action["type"] != "loadbalancer" {
		t.Fatalf("expected loadbalancer action, got: %v", origin.Action["type"])
	}

	targets, ok := origin.Action["targets"].([]any)
	if !ok {
		t.Fatalf("expected targets array, got: %T", origin.Action["targets"])
	}

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	t0 := targets[0].(map[string]any)
	t1 := targets[1].(map[string]any)

	if t0["url"] != "http://stable.default:8080" {
		t.Errorf("unexpected first target url: %v", t0["url"])
	}
	if t0["weight"] != float64(90) {
		t.Errorf("unexpected first target weight: %v", t0["weight"])
	}

	if t1["url"] != "http://canary.default:8080" {
		t.Errorf("unexpected second target url: %v", t1["url"])
	}
	if t1["weight"] != float64(10) {
		t.Errorf("unexpected second target weight: %v", t1["weight"])
	}
}

func TestReconcileHTTPRoute_Filters(t *testing.T) {
	r, store := setupReconciler(t)
	ctx := context.Background()

	route := HTTPRoute{
		Name:      "filtered-route",
		Namespace: "default",
		Hostnames: []string{"web.example.com"},
		ParentRef: "default/main-gw",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{Path: &PathMatch{Type: "PathPrefix", Value: "/app"}},
				},
				Filters: []HTTPRouteFilter{
					{
						Type: "RequestHeaderModifier",
						RequestHeaderModifier: &HeaderModifier{
							Set:    map[string]string{"X-Forwarded-Proto": "https"},
							Add:    map[string]string{"X-Request-ID": "generated"},
							Remove: []string{"X-Debug"},
						},
					},
					{
						Type: "ResponseHeaderModifier",
						ResponseHeaderModifier: &HeaderModifier{
							Set: map[string]string{"X-Frame-Options": "DENY"},
						},
					},
					{
						Type: "URLRewrite",
						URLRewrite: &URLRewriteFilter{
							Hostname: "internal.example.com",
							Path:     &PathMatch{Type: "PathPrefix", Value: "/v2"},
						},
					},
				},
				BackendRefs: []BackendRef{
					{Name: "web-svc", Namespace: "default", Port: 3000},
				},
			},
		},
	}

	if err := r.ReconcileHTTPRoute(ctx, route); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, ok := store.get("httproute/default/filtered-route/rule/0")
	if !ok {
		t.Fatal("origin config not stored")
	}

	var origin OriginConfig
	if err := json.Unmarshal(data, &origin); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if origin.Modifiers == nil {
		t.Fatal("expected modifiers to be set")
	}

	// Verify request header modifier.
	reqHeaders, ok := origin.Modifiers["request_headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected request_headers modifier, got: %T", origin.Modifiers["request_headers"])
	}

	setHeaders, ok := reqHeaders["set"].(map[string]any)
	if !ok {
		t.Fatalf("expected set map, got: %T", reqHeaders["set"])
	}
	if setHeaders["X-Forwarded-Proto"] != "https" {
		t.Errorf("unexpected set header: %v", setHeaders["X-Forwarded-Proto"])
	}

	addHeaders, ok := reqHeaders["add"].(map[string]any)
	if !ok {
		t.Fatalf("expected add map, got: %T", reqHeaders["add"])
	}
	if addHeaders["X-Request-ID"] != "generated" {
		t.Errorf("unexpected add header: %v", addHeaders["X-Request-ID"])
	}

	removeHeaders, ok := reqHeaders["remove"].([]any)
	if !ok {
		t.Fatalf("expected remove slice, got: %T", reqHeaders["remove"])
	}
	if len(removeHeaders) != 1 || removeHeaders[0] != "X-Debug" {
		t.Errorf("unexpected remove headers: %v", removeHeaders)
	}

	// Verify response header modifier.
	respHeaders, ok := origin.Modifiers["response_headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected response_headers modifier, got: %T", origin.Modifiers["response_headers"])
	}
	respSet, ok := respHeaders["set"].(map[string]any)
	if !ok {
		t.Fatalf("expected set map, got: %T", respHeaders["set"])
	}
	if respSet["X-Frame-Options"] != "DENY" {
		t.Errorf("unexpected response set header: %v", respSet["X-Frame-Options"])
	}

	// Verify URL rewrite.
	rewrite, ok := origin.Modifiers["url_rewrite"].(map[string]any)
	if !ok {
		t.Fatalf("expected url_rewrite modifier, got: %T", origin.Modifiers["url_rewrite"])
	}
	if rewrite["hostname"] != "internal.example.com" {
		t.Errorf("unexpected rewrite hostname: %v", rewrite["hostname"])
	}
	if rewrite["path"] != "/v2" {
		t.Errorf("unexpected rewrite path: %v", rewrite["path"])
	}
	if rewrite["path_type"] != "PathPrefix" {
		t.Errorf("unexpected rewrite path_type: %v", rewrite["path_type"])
	}
}

func TestReconcileHTTPRoute_ParentNotFound(t *testing.T) {
	store := newMemoryStore()
	r := NewReconciler(store, testController)
	ctx := context.Background()

	route := HTTPRoute{
		Name:      "orphan",
		Namespace: "default",
		ParentRef: "default/missing-gw",
		Rules: []HTTPRouteRule{
			{BackendRefs: []BackendRef{{Name: "svc", Port: 80}}},
		},
	}

	if err := r.ReconcileHTTPRoute(ctx, route); err == nil {
		t.Error("expected error for missing parent gateway")
	}
}

func TestReconcileGRPCRoute(t *testing.T) {
	r, store := setupReconciler(t)
	ctx := context.Background()

	route := GRPCRoute{
		Name:      "grpc-route",
		Namespace: "default",
		Hostnames: []string{"grpc.example.com"},
		ParentRef: "default/main-gw",
		Rules: []GRPCRouteRule{
			{
				Matches: []GRPCRouteMatch{
					{Method: &GRPCMethodMatch{Type: "Exact", Service: "myapp.UserService", Method: "GetUser"}},
				},
				BackendRefs: []BackendRef{
					{Name: "grpc-svc", Namespace: "default", Port: 9090},
				},
			},
		},
	}

	if err := r.ReconcileGRPCRoute(ctx, route); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, ok := store.get("grpcroute/default/grpc-route/rule/0")
	if !ok {
		t.Fatal("origin config not stored")
	}

	var origin OriginConfig
	if err := json.Unmarshal(data, &origin); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if origin.Action["type"] != "grpc" {
		t.Errorf("expected grpc action type, got: %v", origin.Action["type"])
	}

	if len(origin.Paths) != 1 || origin.Paths[0] != "/myapp.UserService/GetUser" {
		t.Errorf("unexpected paths: %v", origin.Paths)
	}
}
