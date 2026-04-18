// free_tier.go implements free-tier-first provider routing.
// When multiple providers can serve a request, this strategy prefers
// free-tier providers and falls back to paid providers only when needed.
package routing

// FreeTierConfig configures free-tier-first routing.
type FreeTierConfig struct {
	FreeTierProviders []string `json:"free_tier_providers" yaml:"free_tier_providers"`
	PaidProviders     []string `json:"paid_providers" yaml:"paid_providers"`
}

// SelectFreeTierFirst returns providers ordered free-first, paid-fallback.
// Free-tier providers appear first in the result, followed by paid providers.
// This allows the caller to try providers in order, falling back to paid
// only after free options are exhausted.
func SelectFreeTierFirst(cfg FreeTierConfig) []string {
	result := make([]string, 0, len(cfg.FreeTierProviders)+len(cfg.PaidProviders))
	result = append(result, cfg.FreeTierProviders...)
	result = append(result, cfg.PaidProviders...)
	return result
}
