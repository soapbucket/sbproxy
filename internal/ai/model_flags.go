// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// isModelEnabled checks whether a model is enabled via feature flags.
// Returns true if no flag is set (default enabled). A model is disabled
// only when the flag "ai.models.<id>.enabled" is explicitly false.
func isModelEnabled(model string, flags map[string]interface{}) bool {
	if flags == nil {
		return true
	}
	flagKey := "ai.models." + model + ".enabled"
	val, exists := flags[flagKey]
	if !exists {
		return true
	}
	enabled, ok := val.(bool)
	if !ok {
		return true
	}
	return enabled
}

// getModelWeight returns the effective weight for a provider/model combination.
// If the feature flag "ai.models.<id>.weight" is set and positive, it overrides
// the config weight. Otherwise the config weight is returned unchanged.
func getModelWeight(model string, configWeight int, flags map[string]interface{}) int {
	if flags == nil {
		return configWeight
	}
	flagKey := "ai.models." + model + ".weight"
	val, exists := flags[flagKey]
	if !exists {
		return configWeight
	}
	// Feature flags from JSON unmarshal as float64.
	if weight, ok := val.(float64); ok && weight > 0 {
		return int(weight)
	}
	// Also support int values from non-JSON sources.
	if weight, ok := val.(int); ok && weight > 0 {
		return weight
	}
	return configWeight
}
