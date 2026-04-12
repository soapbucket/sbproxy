// registry.go defines the Registry that holds factory functions for all config types.
package config

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// Registry holds factory functions for all config types (actions, auth, policies, transforms).
// It replaces the package-level init() registration pattern, enabling implementations
// to live in sub-packages without creating import cycles.
//
// Usage:
//
//	r := config.NewRegistry()
//	r.RegisterAction("proxy", action.LoadProxy)
//	r.RegisterAuth("jwt", auth.LoadJWT)
//	config.SetRegistry(r)
type Registry struct {
	mu         sync.RWMutex
	actions    map[string]ActionConfigLoaderFn
	auths      map[string]AuthConfigConstructorFn
	policies   map[string]PolicyConfigConstructorFn
	transforms map[string]TransformConstructorFn
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		actions:    make(map[string]ActionConfigLoaderFn),
		auths:      make(map[string]AuthConfigConstructorFn),
		policies:   make(map[string]PolicyConfigConstructorFn),
		transforms: make(map[string]TransformConstructorFn),
	}
}

// RegisterAction registers a factory function for an action type.
func (r *Registry) RegisterAction(typeName string, fn ActionConfigLoaderFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions[typeName] = fn
}

// RegisterAuth registers a factory function for an auth type.
func (r *Registry) RegisterAuth(typeName string, fn AuthConfigConstructorFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auths[typeName] = fn
}

// RegisterPolicy registers a factory function for a policy type.
func (r *Registry) RegisterPolicy(typeName string, fn PolicyConfigConstructorFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[typeName] = fn
}

// RegisterTransform registers a factory function for a transform type.
func (r *Registry) RegisterTransform(typeName string, fn TransformConstructorFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transforms[typeName] = fn
}

// LoadAction looks up and invokes the factory for the given action type.
func (r *Registry) LoadAction(data json.RawMessage) (ActionConfig, error) {
	var obj BaseAction
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	r.mu.RLock()
	fn, ok := r.actions[obj.ActionType]
	r.mu.RUnlock()
	if !ok {
		if factory, found := plugin.GetAction(obj.ActionType); found {
			handler, err := factory(data)
			if err != nil {
				return nil, err
			}
			return &PluginActionAdapter{handler: handler}, nil
		}
		return nil, fmt.Errorf("unknown action type: %s", obj.ActionType)
	}
	return fn(data)
}

// LoadAuth looks up and invokes the factory for the given auth type.
func (r *Registry) LoadAuth(data json.RawMessage) (AuthConfig, error) {
	var obj BaseAuthConfig
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	r.mu.RLock()
	fn, ok := r.auths[obj.AuthType]
	r.mu.RUnlock()
	if !ok {
		if factory, found := plugin.GetAuth(obj.AuthType); found {
			provider, err := factory(data)
			if err != nil {
				return nil, err
			}
			adapter := &PluginAuthAdapter{provider: provider}
			adapter.BaseAuthConfig.AuthType = obj.AuthType
			return adapter, nil
		}
		return nil, fmt.Errorf("unknown auth type: %s", obj.AuthType)
	}
	return fn(data)
}

// LoadPolicy looks up and invokes the factory for the given policy type.
func (r *Registry) LoadPolicy(data json.RawMessage) (PolicyConfig, error) {
	var obj BasePolicy
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	r.mu.RLock()
	fn, ok := r.policies[obj.PolicyType]
	r.mu.RUnlock()
	if !ok {
		if factory, found := plugin.GetPolicy(obj.PolicyType); found {
			enforcer, err := factory(data)
			if err != nil {
				return nil, err
			}
			adapter := &PluginPolicyAdapter{enforcer: enforcer}
			adapter.BasePolicy.PolicyType = obj.PolicyType
			return adapter, nil
		}
		return nil, fmt.Errorf("unknown policy type: %s", obj.PolicyType)
	}
	return fn(data)
}

// LoadTransform looks up and invokes the factory for the given transform type.
func (r *Registry) LoadTransform(data json.RawMessage) (TransformConfig, error) {
	var obj BaseTransform
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	r.mu.RLock()
	fn, ok := r.transforms[obj.TransformType]
	r.mu.RUnlock()
	if !ok {
		if factory, found := plugin.GetTransform(obj.TransformType); found {
			handler, err := factory(data)
			if err != nil {
				return nil, err
			}
			adapter := &PluginTransformAdapter{transform: handler}
			adapter.BaseTransform.TransformType = obj.TransformType
			return adapter, nil
		}
		return nil, fmt.Errorf("unknown transform type: %s", obj.TransformType)
	}
	return fn(data)
}

// global registry instance, set during startup
var globalRegistry *Registry

// SetRegistry sets the global registry used by config loading.
// Call this during application startup before loading any configs.
func SetRegistry(r *Registry) {
	globalRegistry = r
}

// GetRegistry returns the global registry, creating a default one if needed.
func GetRegistry() *Registry {
	if globalRegistry == nil {
		globalRegistry = NewRegistry()
	}
	return globalRegistry
}

// DefaultRegistry creates a Registry pre-populated with all built-in types.
// In production, the registry is populated via the modules packages via
// plugin.Register* calls in init() functions.
func DefaultRegistry() *Registry {
	return NewRegistry()
}
