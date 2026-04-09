// Package plugin provides the plugin registry and interfaces for extending sbproxy.
//
// This package follows a Caddy-inspired plugin architecture: plugins register
// themselves during init() by calling Register functions, and the proxy engine
// looks them up by name when building request pipelines from configuration.
//
// The registry is the meeting point between configuration (which references plugins
// by name) and implementation (which provides the actual behavior). Plugin packages
// in internal/ import this package to register themselves; the engine imports this
// package to look them up. Neither side needs to know about the other directly.
//
// All Register and Get functions are safe for concurrent use.
package plugin

import (
	"encoding/json"
	"fmt"
	"sync"
)

var (
	mu             sync.RWMutex
	actions        = map[string]ActionFactory{}
	auths          = map[string]AuthFactory{}
	policies       = map[string]PolicyFactory{}
	transforms     = map[string]TransformFactory{}
	middlewares    []MiddlewareRegistration
	healthCheckers = map[string]HealthCheckerFactory{}
	transports     = map[string]TransportFactory{}
)

// RegisterAction registers an action factory under the given name. Call this from
// an init() function in the package that implements the action. The name must match
// the "type" field used in origin action configuration (e.g., "proxy", "redirect").
func RegisterAction(name string, f ActionFactory) { mu.Lock(); actions[name] = f; mu.Unlock() }

// RegisterAuth registers an authentication provider factory under the given name.
func RegisterAuth(name string, f AuthFactory) { mu.Lock(); auths[name] = f; mu.Unlock() }

// RegisterPolicy registers a policy enforcer factory under the given name.
func RegisterPolicy(name string, f PolicyFactory) { mu.Lock(); policies[name] = f; mu.Unlock() }

// RegisterTransform registers a response transform factory under the given name.
func RegisterTransform(name string, f TransformFactory) {
	mu.Lock()
	transforms[name] = f
	mu.Unlock()
}

// RegisterMiddleware registers a global middleware. Unlike other plugin types,
// middlewares are not looked up by name. All registered middlewares are applied
// to every request, sorted by priority and ordering constraints.
func RegisterMiddleware(reg MiddlewareRegistration) {
	mu.Lock()
	middlewares = append(middlewares, reg)
	mu.Unlock()
}

// GetAction returns the action factory registered under name, or false if none exists.
// Called by the engine during configuration loading, not on every request.
func GetAction(name string) (ActionFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := actions[name]
	return f, ok
}

// GetAuth returns the auth factory registered under name, or false if none exists.
func GetAuth(name string) (AuthFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := auths[name]
	return f, ok
}

// GetPolicy returns the policy factory registered under name, or false if none exists.
func GetPolicy(name string) (PolicyFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := policies[name]
	return f, ok
}

// GetTransform returns the transform factory registered under name, or false if none exists.
func GetTransform(name string) (TransformFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := transforms[name]
	return f, ok
}

// GetMiddlewares returns a copy of all registered middleware registrations.
// The caller is free to sort and modify the returned slice.
func GetMiddlewares() []MiddlewareRegistration {
	mu.RLock()
	defer mu.RUnlock()
	return append([]MiddlewareRegistration{}, middlewares...)
}

// ListActions returns the names of all registered action types.
func ListActions() []string { mu.RLock(); defer mu.RUnlock(); return keys(actions) }

// ListAuths returns the names of all registered auth types.
func ListAuths() []string { mu.RLock(); defer mu.RUnlock(); return keys(auths) }

// ListPolicies returns the names of all registered policy types.
func ListPolicies() []string { mu.RLock(); defer mu.RUnlock(); return keys(policies) }

// ListTransforms returns the names of all registered transform types.
func ListTransforms() []string { mu.RLock(); defer mu.RUnlock(); return keys(transforms) }

// RegisterHealthChecker registers a health checker factory under the given name.
// Health checkers run periodic probes against upstream targets and report their
// availability. Call this from an init() function to add custom health check
// strategies beyond the built-in HTTP and TCP checks.
func RegisterHealthChecker(name string, f HealthCheckerFactory) {
	mu.Lock()
	healthCheckers[name] = f
	mu.Unlock()
}

// GetHealthChecker returns the health checker factory registered under name, or false if none exists.
func GetHealthChecker(name string) (HealthCheckerFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := healthCheckers[name]
	return f, ok
}

// ListHealthCheckers returns the names of all registered health checker types.
func ListHealthCheckers() []string { mu.RLock(); defer mu.RUnlock(); return keys(healthCheckers) }

// RegisterTransport registers a custom transport (http.RoundTripper) factory under
// the given name. Transports control how outbound requests are sent to upstreams.
// Use this to add custom connection pooling, mutual TLS, or protocol adapters.
func RegisterTransport(name string, f TransportFactory) {
	mu.Lock()
	transports[name] = f
	mu.Unlock()
}

// GetTransport returns the transport factory registered under name, or false if none exists.
func GetTransport(name string) (TransportFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := transports[name]
	return f, ok
}

// ListTransports returns the names of all registered transport types.
func ListTransports() []string { mu.RLock(); defer mu.RUnlock(); return keys(transports) }

// CreateAction is a convenience function that looks up an action factory by name
// and immediately calls it with the provided configuration. Returns a descriptive
// error if the action type is not registered, listing all available types.
func CreateAction(name string, cfg json.RawMessage) (ActionHandler, error) {
	f, ok := GetAction(name)
	if !ok {
		return nil, fmt.Errorf("unknown action type %q; available: %v", name, ListActions())
	}
	return f(cfg)
}

func keys[K comparable, V any](m map[K]V) []K {
	result := make([]K, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
