package plugin

import (
	"encoding/json"
	"fmt"
	"sync"
)

var (
	mu          sync.RWMutex
	actions     = map[string]ActionFactory{}
	auths       = map[string]AuthFactory{}
	policies    = map[string]PolicyFactory{}
	transforms  = map[string]TransformFactory{}
	middlewares []MiddlewareRegistration
)

func RegisterAction(name string, f ActionFactory)       { mu.Lock(); actions[name] = f; mu.Unlock() }
func RegisterAuth(name string, f AuthFactory)            { mu.Lock(); auths[name] = f; mu.Unlock() }
func RegisterPolicy(name string, f PolicyFactory)        { mu.Lock(); policies[name] = f; mu.Unlock() }
func RegisterTransform(name string, f TransformFactory)  { mu.Lock(); transforms[name] = f; mu.Unlock() }
func RegisterMiddleware(reg MiddlewareRegistration)      { mu.Lock(); middlewares = append(middlewares, reg); mu.Unlock() }

func GetAction(name string) (ActionFactory, bool)        { mu.RLock(); defer mu.RUnlock(); f, ok := actions[name]; return f, ok }
func GetAuth(name string) (AuthFactory, bool)            { mu.RLock(); defer mu.RUnlock(); f, ok := auths[name]; return f, ok }
func GetPolicy(name string) (PolicyFactory, bool)        { mu.RLock(); defer mu.RUnlock(); f, ok := policies[name]; return f, ok }
func GetTransform(name string) (TransformFactory, bool)  { mu.RLock(); defer mu.RUnlock(); f, ok := transforms[name]; return f, ok }
func GetMiddlewares() []MiddlewareRegistration           { mu.RLock(); defer mu.RUnlock(); return append([]MiddlewareRegistration{}, middlewares...) }

func ListActions() []string    { mu.RLock(); defer mu.RUnlock(); return keys(actions) }
func ListAuths() []string      { mu.RLock(); defer mu.RUnlock(); return keys(auths) }
func ListPolicies() []string   { mu.RLock(); defer mu.RUnlock(); return keys(policies) }
func ListTransforms() []string { mu.RLock(); defer mu.RUnlock(); return keys(transforms) }

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
