package loadbalancer

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestLoadBalancer_Registration(t *testing.T) {
	factory, ok := plugin.GetAction("load_balancer")
	if !ok {
		t.Fatal("load_balancer action not registered")
	}
	if factory == nil {
		t.Fatal("load_balancer factory is nil")
	}
}

func TestLoadBalancer_Type(t *testing.T) {
	cfg := `{"type":"load_balancer","targets":[{"url":"http://localhost:9001"}]}`
	h, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if h.Type() != "load_balancer" {
		t.Errorf("Type() = %q, want %q", h.Type(), "load_balancer")
	}
}

func TestLoadBalancer_SingleTarget(t *testing.T) {
	// Start a test backend.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "one")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-one"))
	}))
	defer backend.Close()

	cfg, _ := json.Marshal(Config{
		Type:    "load_balancer",
		Targets: []Target{{URL: backend.URL}},
	})

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-one" {
		t.Errorf("body = %q, want %q", string(body), "backend-one")
	}
}

func TestLoadBalancer_RoundRobin(t *testing.T) {
	// Start two test backends.
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "A")
		_, _ = w.Write([]byte("A"))
	}))
	defer backendA.Close()

	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "B")
		_, _ = w.Write([]byte("B"))
	}))
	defer backendB.Close()

	cfg, _ := json.Marshal(Config{
		Type:      "load_balancer",
		Algorithm: "round_robin",
		Targets: []Target{
			{URL: backendA.URL},
			{URL: backendB.URL},
		},
	})

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Fire 4 requests and check alternation.
	seen := make([]string, 4)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		seen[i] = string(b)
	}

	// Round-robin with 2 targets: expect A, B, A, B.
	expected := []string{"A", "B", "A", "B"}
	for i, want := range expected {
		if seen[i] != want {
			t.Errorf("request %d: got %q, want %q (sequence: %v)", i, seen[i], want, seen)
			break
		}
	}
}

func TestLoadBalancer_NoTargets(t *testing.T) {
	cfg := `{"type":"load_balancer","targets":[]}`
	_, err := New(json.RawMessage(cfg))
	if err == nil {
		t.Fatal("expected error for no targets, got nil")
	}
}

func TestLoadBalancer_InvalidTargetURL(t *testing.T) {
	cfg := `{"type":"load_balancer","targets":[{"url":""}]}`
	_, err := New(json.RawMessage(cfg))
	if err == nil {
		t.Fatal("expected error for empty target URL, got nil")
	}
}

func TestLoadBalancer_InvalidAlgorithm(t *testing.T) {
	cfg := `{"type":"load_balancer","algorithm":"bogus","targets":[{"url":"http://localhost:1"}]}`
	_, err := New(json.RawMessage(cfg))
	if err == nil {
		t.Fatal("expected error for invalid algorithm, got nil")
	}
}

func TestLoadBalancer_HashKeyRequired(t *testing.T) {
	cfg := `{"type":"load_balancer","algorithm":"header_hash","targets":[{"url":"http://localhost:1"}]}`
	_, err := New(json.RawMessage(cfg))
	if err == nil {
		t.Fatal("expected error when header_hash algorithm has no hash_key")
	}
}

func TestLoadBalancer_ConsistentHash(t *testing.T) {
	// Start three test backends.
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("A"))
	}))
	defer backendA.Close()

	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("B"))
	}))
	defer backendB.Close()

	backendC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("C"))
	}))
	defer backendC.Close()

	cfg, _ := json.Marshal(Config{
		Type:      "load_balancer",
		Algorithm: "consistent_hash",
		Targets: []Target{
			{URL: backendA.URL},
			{URL: backendB.URL},
			{URL: backendC.URL},
		},
	})

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Same path should always go to the same backend (deterministic).
	var firstResult string
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/stable-path", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got := string(b)

		if i == 0 {
			firstResult = got
		} else if got != firstResult {
			t.Errorf("request %d: got %q, want %q (consistent hash should be deterministic)", i, got, firstResult)
			break
		}
	}

	// Different paths may go to different backends. Send multiple paths and verify
	// we get at least 2 distinct backends (with 3 backends this is very likely).
	seen := make(map[string]bool)
	paths := []string{"/path-a", "/path-b", "/path-c", "/path-d", "/path-e",
		"/foo", "/bar", "/baz", "/qux", "/quux"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		seen[string(b)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected at least 2 distinct backends across %d paths, got %d", len(paths), len(seen))
	}
}

func TestLoadBalancer_ConsistentHash_RingLookup(t *testing.T) {
	// Test the hash ring directly for determinism and wrapping behavior.
	targets := []parsedTarget{
		{url: mustParseURL("http://a.example.com")},
		{url: mustParseURL("http://b.example.com")},
		{url: mustParseURL("http://c.example.com")},
	}
	ring := newConsistentHashRing(targets, 150)

	// lookup must return valid index.
	idx := ring.lookup("/test")
	if idx < 0 || idx >= len(targets) {
		t.Fatalf("lookup returned invalid index %d", idx)
	}

	// Same key must return same index.
	for i := 0; i < 100; i++ {
		if got := ring.lookup("/test"); got != idx {
			t.Fatalf("lookup not deterministic: got %d, want %d", got, idx)
		}
	}

	// Empty ring should return -1.
	emptyRing := &consistentHashRing{}
	if got := emptyRing.lookup("/test"); got != -1 {
		t.Fatalf("empty ring lookup returned %d, want -1", got)
	}
}

func TestLoadBalancer_PriorityFailover(t *testing.T) {
	// Start two backends: A is the primary, B is the fallback.
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("A"))
	}))
	defer backendA.Close()

	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("B"))
	}))
	defer backendB.Close()

	cfg, _ := json.Marshal(Config{
		Type:      "load_balancer",
		Algorithm: "priority_failover",
		Targets: []Target{
			{URL: backendA.URL},
			{URL: backendB.URL},
		},
	})

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// All requests should go to backend A (first healthy target).
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		resp := rec.Result()
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(b) != "A" {
			t.Errorf("request %d: got %q, want %q (should always select first healthy target)", i, string(b), "A")
		}
	}
}

func TestLoadBalancer_PriorityFailover_AllUnhealthy(t *testing.T) {
	// With no services provider, all targets are considered healthy.
	// Test via selectPriorityFailover method directly on a Handler with
	// a mock unhealthy provider.
	h := &Handler{
		targets: []parsedTarget{
			{url: mustParseURL("http://a.example.com")},
			{url: mustParseURL("http://b.example.com")},
		},
		algorithm: AlgorithmPriorityFailover,
		services:  &unhealthyProvider{},
	}

	idx := h.selectPriorityFailover()
	if idx != -1 {
		t.Errorf("expected -1 when all targets are unhealthy, got %d", idx)
	}
}

func TestLoadBalancer_ConsistentHash_Accepted(t *testing.T) {
	cfg := `{"type":"load_balancer","algorithm":"consistent_hash","targets":[{"url":"http://localhost:1"}]}`
	_, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("consistent_hash should be a valid algorithm, got error: %v", err)
	}
}

func TestLoadBalancer_PriorityFailover_Accepted(t *testing.T) {
	cfg := `{"type":"load_balancer","algorithm":"priority_failover","targets":[{"url":"http://localhost:1"}]}`
	_, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("priority_failover should be a valid algorithm, got error: %v", err)
	}
}

// mustParseURL parses a URL or panics.
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// unhealthyProvider is a mock ServiceProvider that reports all targets as unhealthy.
type unhealthyProvider struct {
	plugin.ServiceProvider
}

func (u *unhealthyProvider) TransportFor(cfg plugin.TransportConfig) http.RoundTripper {
	return http.DefaultTransport
}

func (u *unhealthyProvider) HealthStatus(targetURL string) plugin.HealthState {
	return plugin.HealthState{Healthy: false, ConsecutiveFailures: 5}
}

func (u *unhealthyProvider) SetHealthStatus(target string, state plugin.HealthState) {}
func (u *unhealthyProvider) KVStore() plugin.KVStore                                 { return nil }
func (u *unhealthyProvider) Cache() plugin.CacheStore                                { return nil }
func (u *unhealthyProvider) Events() plugin.EventEmitter                             { return nil }
func (u *unhealthyProvider) Logger() *slog.Logger                                    { return slog.Default() }
func (u *unhealthyProvider) Metrics() plugin.Observer                                { return nil }
func (u *unhealthyProvider) ResponseCache() plugin.ResponseCache                     { return nil }
func (u *unhealthyProvider) Sessions() plugin.SessionProvider                        { return nil }
func (u *unhealthyProvider) ResolveOriginHandler(hostname string) (http.Handler, error) {
	return nil, nil
}
func (u *unhealthyProvider) ResolveEmbeddedOriginHandler(raw json.RawMessage) (http.Handler, error) {
	return nil, nil
}

func TestLoadBalancer_Provision(t *testing.T) {
	cfg := `{"type":"load_balancer","targets":[{"url":"http://localhost:9001"}]}`
	handler, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	prov, ok := handler.(plugin.Provisioner)
	if !ok {
		t.Fatal("handler does not implement plugin.Provisioner")
	}

	err = prov.Provision(plugin.PluginContext{OriginID: "test-origin"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
}
