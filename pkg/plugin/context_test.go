package plugin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
)

// Compile-time check: mockServiceProvider must satisfy ServiceProvider.
var _ ServiceProvider = (*mockServiceProvider)(nil)

type mockServiceProvider struct{}

func (m *mockServiceProvider) KVStore() KVStore     { return nil }
func (m *mockServiceProvider) Cache() CacheStore    { return nil }
func (m *mockServiceProvider) Events() EventEmitter { return nil }
func (m *mockServiceProvider) Logger() *slog.Logger { return slog.Default() }
func (m *mockServiceProvider) Metrics() Observer    { return NoopObserver() }
func (m *mockServiceProvider) TransportFor(_ TransportConfig) http.RoundTripper {
	return nil
}
func (m *mockServiceProvider) ResolveOriginHandler(_ string) (http.Handler, error) {
	return nil, nil
}
func (m *mockServiceProvider) ResolveEmbeddedOriginHandler(_ json.RawMessage) (http.Handler, error) {
	return nil, nil
}
func (m *mockServiceProvider) ResponseCache() ResponseCache            { return nil }
func (m *mockServiceProvider) Sessions() SessionProvider               { return nil }
func (m *mockServiceProvider) HealthStatus(_ string) HealthState       { return HealthState{} }
func (m *mockServiceProvider) SetHealthStatus(_ string, _ HealthState) {}

func TestServiceProviderInterface(t *testing.T) {
	// The compile-time var _ check above is the real test.
	// This exercises the mock at runtime to confirm all methods are callable.
	var sp ServiceProvider = &mockServiceProvider{}
	if sp.Logger() == nil {
		t.Error("Logger should return non-nil default")
	}
	if sp.KVStore() != nil {
		t.Error("KVStore should be nil for mock")
	}
}

func TestPluginContext_Fields(t *testing.T) {
	ctx := PluginContext{
		OriginID:    "origin-1",
		WorkspaceID: "ws-1",
		Hostname:    "api.example.com",
		Version:     "1.0.0",
	}
	if ctx.OriginID != "origin-1" {
		t.Errorf("expected origin-1, got %s", ctx.OriginID)
	}
	if ctx.WorkspaceID != "ws-1" {
		t.Errorf("expected ws-1, got %s", ctx.WorkspaceID)
	}
}
