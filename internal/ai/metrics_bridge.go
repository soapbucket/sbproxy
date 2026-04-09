// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import "github.com/soapbucket/sbproxy/pkg/plugin"

// defaultObserver holds the Observer used by the ai package for metrics.
// When the full migration is complete (Phase 2 follow-up), the wrapper
// functions in metrics.go will delegate to this observer instead of
// calling Prometheus directly.
var defaultObserver plugin.Observer = plugin.NoopObserver()

// SetObserver replaces the default metrics observer for the ai package.
func SetObserver(obs plugin.Observer) {
	if obs == nil {
		obs = plugin.NoopObserver()
	}
	defaultObserver = obs
}

// GetObserver returns the current metrics observer.
func GetObserver() plugin.Observer { return defaultObserver }
