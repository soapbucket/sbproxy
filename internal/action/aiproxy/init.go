// Package aiproxy implements the AI gateway action for sbproxy.
//
// The AI proxy action intercepts OpenAI-compatible API requests, applies
// routing, rate limiting, guardrails, caching, and budget enforcement,
// then forwards the request to the selected upstream AI provider.
//
// Registration happens via [Register], which wires the AI proxy action
// loader into the config registry so that origins with action type
// "ai_proxy" are handled by this package.
package aiproxy

import (
	"github.com/soapbucket/sbproxy/internal/config"
)

// Register adds the AI proxy action loader to the given Registry.
// After registration, any origin config with action type "ai_proxy" will be
// deserialized and validated by the AI proxy loader during config load.
func Register(r *config.Registry) {
	r.RegisterAction(config.TypeAIProxy, config.LoadAIProxy)
}
