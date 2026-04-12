package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func BenchmarkHostLookup(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	origins := make(map[string]*CompiledOrigin, 100)
	for i := 0; i < 100; i++ {
		hostname := fmt.Sprintf("host-%d.example.com", i)
		origins[hostname] = NewCompiledOrigin(fmt.Sprintf("id-%d", i), hostname, "ws-1", "v1", handler, nil)
	}
	cc := NewCompiledConfig(origins)
	var active atomic.Pointer[CompiledConfig]
	active.Store(cc)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := active.Load()
		_ = cfg.Lookup("host-50.example.com")
	}
}

func BenchmarkServeHTTP_SimpleHandler(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	cc := NewCompiledConfig(map[string]*CompiledOrigin{
		"example.com": NewCompiledOrigin("test", "example.com", "ws-1", "v1", handler, nil),
	})
	var active atomic.Pointer[CompiledConfig]
	active.Store(cc)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		cfg := active.Load()
		origin := cfg.Lookup("example.com")
		origin.ServeHTTP(rec, req)
	}
}

func BenchmarkCompileOrigin(b *testing.B) {
	// Register a lightweight test action.
	plugin.RegisterAction("bench_noop", func(raw json.RawMessage) (plugin.ActionHandler, error) {
		return &benchNoop{}, nil
	})

	raw := &RawOrigin{
		ID:       "bench",
		Hostname: "bench.example.com",
		Action:   json.RawMessage(`{"type":"bench_noop"}`),
	}
	services := &benchServices{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CompileOrigin(raw, services)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helpers

type benchNoop struct{}

func (bn *benchNoop) Type() string { return "bench_noop" }
func (bn *benchNoop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}

// benchServices implements plugin.ServiceProvider with no-ops.
type benchServices struct{}

func (benchServices) KVStore() plugin.KVStore     { return benchKV{} }
func (benchServices) Cache() plugin.CacheStore    { return benchCache{} }
func (benchServices) Events() plugin.EventEmitter { return benchEvents{} }
func (benchServices) Logger() *slog.Logger        { return slog.Default() }
func (benchServices) Metrics() plugin.Observer    { return plugin.NoopObserver() }
func (benchServices) TransportFor(plugin.TransportConfig) http.RoundTripper {
	return http.DefaultTransport
}
func (benchServices) ResolveOriginHandler(string) (http.Handler, error) { return nil, nil }
func (benchServices) ResolveEmbeddedOriginHandler(json.RawMessage) (http.Handler, error) {
	return nil, nil
}
func (benchServices) ResponseCache() plugin.ResponseCache        { return nil }
func (benchServices) Sessions() plugin.SessionProvider           { return nil }
func (benchServices) HealthStatus(string) plugin.HealthState     { return plugin.HealthState{} }
func (benchServices) SetHealthStatus(string, plugin.HealthState) {}

type benchKV struct{}

func (benchKV) Get(context.Context, string) ([]byte, error)              { return nil, nil }
func (benchKV) Set(context.Context, string, []byte, time.Duration) error { return nil }
func (benchKV) Delete(context.Context, string) error                     { return nil }
func (benchKV) Increment(context.Context, string, int64) (int64, error)  { return 0, nil }

type benchCache struct{}

func (benchCache) Get(context.Context, string) (interface{}, bool)         { return nil, false }
func (benchCache) Set(context.Context, string, interface{}, time.Duration) {}

type benchEvents struct{}

func (benchEvents) Emit(context.Context, string, map[string]any) error { return nil }
func (benchEvents) Enabled(string) bool                                { return false }
