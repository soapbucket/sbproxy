// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// Compile-time check: configServiceProvider must satisfy plugin.ServiceProvider.
var _ plugin.ServiceProvider = (*configServiceProvider)(nil)

// configServiceProvider bridges *Config to plugin.ServiceProvider.
// It is passed to every PluginContext so leaf modules can access shared runtime services.
type configServiceProvider struct {
	cfg *Config
}

// NewServiceProvider creates a plugin.ServiceProvider backed by the given Config.
func NewServiceProvider(cfg *Config) plugin.ServiceProvider {
	return &configServiceProvider{cfg: cfg}
}

func (s *configServiceProvider) KVStore() plugin.KVStore { return nil }

func (s *configServiceProvider) Events() plugin.EventEmitter {
	return &configEventEmitter{cfg: s.cfg}
}

func (s *configServiceProvider) Logger() *slog.Logger { return slog.Default() }

func (s *configServiceProvider) Cache() plugin.CacheStore { return nil }

func (s *configServiceProvider) Metrics() plugin.Observer { return plugin.NoopObserver() }

func (s *configServiceProvider) TransportFor(_ plugin.TransportConfig) http.RoundTripper {
	return http.DefaultTransport
}

func (s *configServiceProvider) ResolveOriginHandler(hostname string) (http.Handler, error) {
	if s.cfg.OriginConfigLoader == nil {
		return nil, fmt.Errorf("origin config loader not available")
	}
	return s.cfg.OriginConfigLoader(hostname)
}

func (s *configServiceProvider) ResolveEmbeddedOriginHandler(raw json.RawMessage) (http.Handler, error) {
	if s.cfg.EmbeddedConfigLoader == nil {
		return nil, fmt.Errorf("embedded config loader not available")
	}
	return s.cfg.EmbeddedConfigLoader(raw)
}

func (s *configServiceProvider) ResponseCache() plugin.ResponseCache { return nil }

func (s *configServiceProvider) Sessions() plugin.SessionProvider { return nil }

func (s *configServiceProvider) HealthStatus(_ string) plugin.HealthState {
	return plugin.HealthState{}
}

func (s *configServiceProvider) SetHealthStatus(_ string, _ plugin.HealthState) {}

// configEventEmitter adapts *Config event-enabled checks to plugin.EventEmitter.
type configEventEmitter struct {
	cfg *Config
}

func (e *configEventEmitter) Emit(_ context.Context, _ string, _ map[string]any) error {
	return nil
}

func (e *configEventEmitter) Enabled(event string) bool {
	if e.cfg == nil {
		return false
	}
	return e.cfg.EventEnabled(event)
}

// PluginActionAdapter wraps a pkg/plugin.ActionHandler to satisfy the internal ActionConfig interface.
// It embeds BaseAction for default implementations of Rewrite, Transport, ModifyResponse, and ErrorHandler.
// IsProxy returns true only when the wrapped handler also implements plugin.ReverseProxyAction.
type PluginActionAdapter struct {
	BaseAction
	handler plugin.ActionHandler
}

// Init stores the config, then calls Provision (if implemented), falls back to InitPlugin
// (legacy Initable), and finally calls Validate (if implemented).
func (a *PluginActionAdapter) Init(cfg *Config) error {
	if err := a.BaseAction.Init(cfg); err != nil {
		return err
	}
	ctx := plugin.PluginContext{
		OriginID:    cfg.ID,
		WorkspaceID: cfg.WorkspaceID,
		Hostname:    cfg.Hostname,
		Version:     cfg.Version,
		Services:    &configServiceProvider{cfg: cfg},
	}
	if p, ok := a.handler.(plugin.Provisioner); ok {
		if err := p.Provision(ctx); err != nil {
			return fmt.Errorf("provision %s: %w", a.GetType(), err)
		}
	} else if p, ok := a.handler.(plugin.Initable); ok {
		if err := p.InitPlugin(ctx); err != nil {
			return fmt.Errorf("init plugin %s: %w", a.GetType(), err)
		}
	}
	if v, ok := a.handler.(plugin.Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("validate %s: %w", a.GetType(), err)
		}
	}
	return nil
}

// GetType returns the action type name from the wrapped handler.
func (a *PluginActionAdapter) GetType() string {
	return a.handler.Type()
}

// Handler returns the wrapped ActionHandler as an http.Handler.
func (a *PluginActionAdapter) Handler() http.Handler {
	return a.handler
}

// IsProxy returns true when the wrapped handler implements plugin.ReverseProxyAction,
// indicating it participates in the reverse proxy lifecycle.
func (a *PluginActionAdapter) IsProxy() bool {
	_, ok := a.handler.(plugin.ReverseProxyAction)
	return ok
}

// Rewrite bridges plugin.ReverseProxyAction.Rewrite to the internal RewriteFn.
// When the wrapped handler implements ReverseProxyAction, returns a RewriteFn that
// delegates to it. Otherwise falls back to the BaseAction nil implementation.
func (a *PluginActionAdapter) Rewrite() RewriteFn {
	rpa, ok := a.handler.(plugin.ReverseProxyAction)
	if !ok {
		return nil
	}
	return RewriteFn(rpa.Rewrite)
}

// Transport bridges plugin.ReverseProxyAction.Transport to the internal TransportFn.
// When the wrapped handler implements ReverseProxyAction and provides a transport,
// returns a TransportFn wrapping it. Otherwise falls back to the BaseAction implementation.
func (a *PluginActionAdapter) Transport() TransportFn {
	rpa, ok := a.handler.(plugin.ReverseProxyAction)
	if !ok {
		return a.BaseAction.Transport()
	}
	tr := rpa.Transport()
	if tr == nil {
		return nil
	}
	return TransportFn(func(req *http.Request) (*http.Response, error) {
		return tr.RoundTrip(req)
	})
}

// PluginPolicyAdapter wraps a pkg/plugin.PolicyEnforcer to satisfy the internal PolicyConfig interface.
// It embeds BasePolicy for default implementations.
type PluginPolicyAdapter struct {
	BasePolicy
	enforcer plugin.PolicyEnforcer
}

// Init calls Provision (if implemented), falls back to InitPlugin (legacy Initable),
// and finally calls Validate (if implemented) on the wrapped enforcer.
func (p *PluginPolicyAdapter) Init(cfg *Config) error {
	ctx := plugin.PluginContext{
		OriginID:    cfg.ID,
		WorkspaceID: cfg.WorkspaceID,
		Hostname:    cfg.Hostname,
		Version:     cfg.Version,
		Services:    &configServiceProvider{cfg: cfg},
	}
	if prov, ok := p.enforcer.(plugin.Provisioner); ok {
		if err := prov.Provision(ctx); err != nil {
			return fmt.Errorf("provision %s: %w", p.GetType(), err)
		}
	} else if init, ok := p.enforcer.(plugin.Initable); ok {
		if err := init.InitPlugin(ctx); err != nil {
			return fmt.Errorf("init plugin %s: %w", p.GetType(), err)
		}
	}
	if v, ok := p.enforcer.(plugin.Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("validate %s: %w", p.GetType(), err)
		}
	}
	return nil
}

// GetType returns the policy type name from the wrapped enforcer.
func (p *PluginPolicyAdapter) GetType() string {
	return p.enforcer.Type()
}

// Apply delegates to the wrapped enforcer's Enforce method.
func (p *PluginPolicyAdapter) Apply(next http.Handler) http.Handler {
	return p.enforcer.Enforce(next)
}

// CSPReportURI implements plugin.CSPReportURIProvider by forwarding to the
// wrapped enforcer if it also implements that interface.
func (p *PluginPolicyAdapter) CSPReportURI() string {
	if provider, ok := p.enforcer.(plugin.CSPReportURIProvider); ok {
		return provider.CSPReportURI()
	}
	return ""
}

// PluginAuthAdapter wraps a pkg/plugin.AuthProvider to satisfy the internal AuthConfig interface.
// It embeds BaseAuthConfig for default implementations.
type PluginAuthAdapter struct {
	BaseAuthConfig
	provider plugin.AuthProvider
}

// Init calls Provision (if implemented), falls back to InitPlugin (legacy Initable),
// and finally calls Validate (if implemented) on the wrapped provider.
func (a *PluginAuthAdapter) Init(cfg *Config) error {
	ctx := plugin.PluginContext{
		OriginID:    cfg.ID,
		WorkspaceID: cfg.WorkspaceID,
		Hostname:    cfg.Hostname,
		Version:     cfg.Version,
		Services:    &configServiceProvider{cfg: cfg},
	}
	if p, ok := a.provider.(plugin.Provisioner); ok {
		if err := p.Provision(ctx); err != nil {
			return fmt.Errorf("provision %s: %w", a.GetType(), err)
		}
	} else if p, ok := a.provider.(plugin.Initable); ok {
		if err := p.InitPlugin(ctx); err != nil {
			return fmt.Errorf("init plugin %s: %w", a.GetType(), err)
		}
	}
	if v, ok := a.provider.(plugin.Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("validate %s: %w", a.GetType(), err)
		}
	}
	return nil
}

// GetType returns the auth type name from the wrapped provider.
func (a *PluginAuthAdapter) GetType() string {
	return a.provider.Type()
}

// Authenticate delegates to the wrapped provider's Wrap method.
func (a *PluginAuthAdapter) Authenticate(next http.Handler) http.Handler {
	return a.provider.Wrap(next)
}

// PluginTransformAdapter wraps a pkg/plugin.TransformHandler to satisfy the internal TransformConfig interface.
// It embeds BaseTransform for default implementations.
type PluginTransformAdapter struct {
	BaseTransform
	transform plugin.TransformHandler
}

// Init calls Provision (if implemented), falls back to InitPlugin (legacy Initable),
// and finally calls Validate (if implemented) on the wrapped transform handler.
func (t *PluginTransformAdapter) Init(cfg *Config) error {
	ctx := plugin.PluginContext{
		OriginID:    cfg.ID,
		WorkspaceID: cfg.WorkspaceID,
		Hostname:    cfg.Hostname,
		Version:     cfg.Version,
		Services:    &configServiceProvider{cfg: cfg},
	}
	if p, ok := t.transform.(plugin.Provisioner); ok {
		if err := p.Provision(ctx); err != nil {
			return fmt.Errorf("provision %s: %w", t.GetType(), err)
		}
	} else if p, ok := t.transform.(plugin.Initable); ok {
		if err := p.InitPlugin(ctx); err != nil {
			return fmt.Errorf("init plugin %s: %w", t.GetType(), err)
		}
	}
	if v, ok := t.transform.(plugin.Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("validate %s: %w", t.GetType(), err)
		}
	}
	return nil
}

// GetType returns the transform type name from the wrapped handler.
func (t *PluginTransformAdapter) GetType() string {
	return t.transform.Type()
}

// Apply delegates to the wrapped transform handler's Apply method.
func (t *PluginTransformAdapter) Apply(resp *http.Response) error {
	return t.transform.Apply(resp)
}
