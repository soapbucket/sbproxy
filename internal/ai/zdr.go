// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// ZDRConfig configures Zero Data Retention routing.
// When enabled, requests are only sent to providers with contractual ZDR agreements.
type ZDRConfig struct {
	Enabled bool `json:"enabled,omitempty" yaml:"enabled"`
}

// zdrProviders tracks providers that support Zero Data Retention.
// These providers either do not train on API data by default or offer
// contractual ZDR agreements.
var zdrProviders = map[string]bool{
	"openai":    true, // with ZDR API agreement
	"anthropic": true, // no training on API data by default
	"bedrock":   true, // AWS manages retention
	"azure":     true, // Azure manages retention
}

// IsZDREligible checks if a provider supports Zero Data Retention.
func IsZDREligible(provider string) bool {
	return zdrProviders[provider]
}

// FilterZDRProviders returns only ZDR-eligible providers from the input list.
// The order of providers is preserved.
func FilterZDRProviders(providers []string) []string {
	filtered := make([]string, 0, len(providers))
	for _, p := range providers {
		if zdrProviders[p] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
