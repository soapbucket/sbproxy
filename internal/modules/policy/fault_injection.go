// fault_injection.go provides percentage-based fault injection for testing
// service resilience.
//
// Fault injection is a chaos engineering primitive that deliberately introduces
// failures into requests. Two fault types are supported:
//
//   - Delay injection: adds artificial latency to a percentage of requests
//   - Abort injection: returns an error status code for a percentage of requests
//
// Both fault types use independent probability checks, so a single request
// can receive both a delay and an abort. Percentages are expressed as
// floating-point values between 0.0 (never) and 1.0 (always).
package policy

import (
	"math/rand"
	"time"
)

// FaultInjectionConfig configures percentage-based fault injection.
type FaultInjectionConfig struct {
	DelayMs      int     `json:"delay_ms,omitempty" yaml:"delay_ms"`
	DelayPercent float64 `json:"delay_percent,omitempty" yaml:"delay_percent"` // 0.0-1.0
	AbortCode    int     `json:"abort_code,omitempty" yaml:"abort_code"`
	AbortPercent float64 `json:"abort_percent,omitempty" yaml:"abort_percent"` // 0.0-1.0
}

// ShouldInjectDelay checks if delay should be injected for this request.
// Returns true and the delay duration if the random roll falls within the
// configured percentage. Returns false and zero duration otherwise.
func ShouldInjectDelay(cfg FaultInjectionConfig) (bool, time.Duration) {
	if cfg.DelayMs <= 0 || cfg.DelayPercent <= 0 {
		return false, 0
	}

	percent := cfg.DelayPercent
	if percent > 1.0 {
		percent = 1.0
	}

	if rand.Float64() < percent {
		return true, time.Duration(cfg.DelayMs) * time.Millisecond
	}
	return false, 0
}

// ShouldInjectAbort checks if an abort should be injected for this request.
// Returns true and the HTTP status code if the random roll falls within the
// configured percentage. Returns false and 0 otherwise.
func ShouldInjectAbort(cfg FaultInjectionConfig) (bool, int) {
	if cfg.AbortCode <= 0 || cfg.AbortPercent <= 0 {
		return false, 0
	}

	percent := cfg.AbortPercent
	if percent > 1.0 {
		percent = 1.0
	}

	if rand.Float64() < percent {
		return true, cfg.AbortCode
	}
	return false, 0
}
