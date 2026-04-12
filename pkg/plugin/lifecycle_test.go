package plugin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
)

type mockProvisioner struct {
	provisioned bool
	validated   bool
	cleaned     bool
	ctx         PluginContext
}

func (m *mockProvisioner) Provision(ctx PluginContext) error {
	m.provisioned = true
	m.ctx = ctx
	return nil
}
func (m *mockProvisioner) Validate() error { m.validated = true; return nil }
func (m *mockProvisioner) Cleanup() error  { m.cleaned = true; return nil }

func TestLifecycle_Interfaces(t *testing.T) {
	m := &mockProvisioner{}
	var p interface{} = m
	if _, ok := p.(Provisioner); !ok {
		t.Error("expected Provisioner")
	}
	if _, ok := p.(Validator); !ok {
		t.Error("expected Validator")
	}
	if _, ok := p.(Cleanup); !ok {
		t.Error("expected Cleanup")
	}
}

type nullServices struct{}

func (n *nullServices) KVStore() KVStore                                 { return nil }
func (n *nullServices) Events() EventEmitter                             { return nil }
func (n *nullServices) Logger() *slog.Logger                             { return slog.Default() }
func (n *nullServices) Cache() CacheStore                                { return nil }
func (n *nullServices) Metrics() Observer                                { return NoopObserver() }
func (n *nullServices) TransportFor(_ TransportConfig) http.RoundTripper { return nil }
func (n *nullServices) ResolveOriginHandler(_ string) (http.Handler, error) {
	return nil, nil
}
func (n *nullServices) ResolveEmbeddedOriginHandler(_ json.RawMessage) (http.Handler, error) {
	return nil, nil
}
func (n *nullServices) ResponseCache() ResponseCache            { return nil }
func (n *nullServices) Sessions() SessionProvider               { return nil }
func (n *nullServices) HealthStatus(_ string) HealthState       { return HealthState{} }
func (n *nullServices) SetHealthStatus(_ string, _ HealthState) {}

func TestPluginContext_WithServices(t *testing.T) {
	ctx := PluginContext{
		OriginID: "o1",
		Services: &nullServices{},
	}
	if ctx.Services == nil {
		t.Error("expected services")
	}
	if ctx.Services.KVStore() != nil {
		t.Error("null should return nil KVStore")
	}
	if ctx.Services.Logger() == nil {
		t.Error("logger should not be nil")
	}
}
