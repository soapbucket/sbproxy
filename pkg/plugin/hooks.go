// hooks.go defines hook types and registration functions for extending proxy behavior.
package plugin

import (
	"encoding/json"
	"net/http"
	"sync"
)

// --- Hook Types ---
// Hooks allow enterprise and third-party code to extend behavior without
// modifying core code. Each hook type has a registration function (write at
// init time) and a getter (read at runtime), both guarded by RWMutex.

// TransportHook fires after every proxy RoundTrip completes. Used for traffic
// shadowing, request duplication, or response observation. Hooks receive both
// the outbound request and the upstream response.
type TransportHook func(req *http.Request, resp *http.Response)

// ConfigFieldHandler processes enterprise-only config fields stored as
// json.RawMessage on OSS types. This lets enterprise extend config schemas
// without forking the OSS struct definitions.
type ConfigFieldHandler func(fieldName string, rawConfig []byte, ctx PluginContext) error

// TrafficCaptureMiddleware wraps an http.Handler with traffic recording.
// Enterprise registers this during init(). When nil (OSS mode), traffic
// capture config in YAML is accepted but silently no-ops.
type TrafficCaptureMiddleware func(next http.Handler, cfg json.RawMessage, services ServiceProvider) http.Handler

var (
	hooksMu             sync.RWMutex
	transportHooks      []TransportHook
	configFieldHandlers = map[string]ConfigFieldHandler{}

	trafficCaptureMu         sync.RWMutex
	trafficCaptureMiddleware TrafficCaptureMiddleware
)

// RegisterTransportHook adds a hook that fires on every proxy RoundTrip.
func RegisterTransportHook(h TransportHook) {
	hooksMu.Lock()
	transportHooks = append(transportHooks, h)
	hooksMu.Unlock()
}

// GetTransportHooks returns a snapshot copy of all registered transport hooks.
func GetTransportHooks() []TransportHook {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	return append([]TransportHook{}, transportHooks...)
}

// RegisterConfigFieldHandler registers a handler for an enterprise config field name.
func RegisterConfigFieldHandler(fieldName string, h ConfigFieldHandler) {
	hooksMu.Lock()
	configFieldHandlers[fieldName] = h
	hooksMu.Unlock()
}

// GetConfigFieldHandler returns the handler for a config field, or nil if unregistered.
func GetConfigFieldHandler(fieldName string) ConfigFieldHandler {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	return configFieldHandlers[fieldName]
}

// RegisterTrafficCaptureMiddleware sets the traffic capture factory. Called by
// enterprise during init() to enable traffic capture middleware.
func RegisterTrafficCaptureMiddleware(f TrafficCaptureMiddleware) {
	trafficCaptureMu.Lock()
	trafficCaptureMiddleware = f
	trafficCaptureMu.Unlock()
}

// GetTrafficCaptureMiddleware returns the registered traffic capture factory,
// or nil if none is registered (OSS mode).
func GetTrafficCaptureMiddleware() TrafficCaptureMiddleware {
	trafficCaptureMu.RLock()
	defer trafficCaptureMu.RUnlock()
	return trafficCaptureMiddleware
}
