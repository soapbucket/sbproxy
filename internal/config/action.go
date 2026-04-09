// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ActionConfigLoaderFn is a function type for action config loader fn callbacks.
type ActionConfigLoaderFn func(data []byte) (ActionConfig, error)

var loaderFns = map[string]ActionConfigLoaderFn{}

// LoadActionConfig performs the load action config operation.
// It uses the global Registry if set, otherwise falls back to legacy init() maps.
func LoadActionConfig(data json.RawMessage) (ActionConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadAction(data)
	}
	var obj BaseAction
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	loaderFn, ok := loaderFns[obj.ActionType]
	if !ok {
		return nil, fmt.Errorf("unknown action type: %s", obj.ActionType)
	}
	return loaderFn(data)
}

// ActionConfig defines the interface for action config operations.
type ActionConfig interface {
	Init(*Config) error
	GetType() string
	Rewrite() RewriteFn
	Transport() TransportFn
	Handler() http.Handler
	ModifyResponse() ModifyResponseFn
	ErrorHandler() ErrorHandlerFn
	IsProxy() bool
}

// Init performs the init operation on the BaseAction.
func (b *BaseAction) Init(cfg *Config) error {
	b.cfg = cfg
	return nil
}

// SetTransport sets the transport on the BaseAction.
// Used by action sub-packages that cannot access the unexported tr field.
func (b *BaseAction) SetTransport(rt http.RoundTripper) {
	b.tr = rt
}

// GetRoundTripper returns the transport RoundTripper.
func (b *BaseAction) GetRoundTripper() http.RoundTripper {
	return b.tr
}

// GetConfig returns the config reference stored during Init.
func (b *BaseAction) GetConfig() *Config {
	return b.cfg
}

// IsProxy reports whether the BaseAction is proxy.
func (b *BaseAction) IsProxy() bool {
	return b.tr != nil
}

// GetType returns the type for the BaseAction.
func (t *BaseAction) GetType() string {
	return t.ActionType
}

// Handler performs the handler operation on the BaseAction.
func (*BaseAction) Handler() http.Handler {
	return nil
}

// Rewrite performs the rewrite operation on the BaseAction.
func (*BaseAction) Rewrite() RewriteFn {
	return nil
}

// Transport performs the transport operation on the BaseAction.
func (t *BaseAction) Transport() TransportFn {
	if t.tr == nil {
		return nil
	}

	return TransportFn(func(req *http.Request) (*http.Response, error) {
		return t.tr.RoundTrip(req)
	})
}

// ModifyResponse performs the modify response operation on the BaseAction.
func (*BaseAction) ModifyResponse() ModifyResponseFn {
	return nil
}

// ErrorHandler performs the error handler operation on the BaseAction.
func (*BaseAction) ErrorHandler() ErrorHandlerFn {
	return nil
}
