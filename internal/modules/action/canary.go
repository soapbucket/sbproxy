package action

import (
	"math/rand/v2"
	"sync"
)

// CanaryConfig configures canary routing.
type CanaryConfig struct {
	Stable        UpstreamGroup `json:"stable" yaml:"stable"`
	Canary        UpstreamGroup `json:"canary" yaml:"canary"`
	CanaryPercent int           `json:"canary_percent" yaml:"canary_percent"` // 0-100
}

// CanaryHandler routes N% of traffic to canary, (100-N)% to stable.
type CanaryHandler struct {
	mu     sync.RWMutex
	config CanaryConfig
}

// NewCanaryHandler creates a CanaryHandler. The canary percentage is clamped
// to the range [0, 100].
func NewCanaryHandler(cfg CanaryConfig) *CanaryHandler {
	if cfg.CanaryPercent < 0 {
		cfg.CanaryPercent = 0
	}
	if cfg.CanaryPercent > 100 {
		cfg.CanaryPercent = 100
	}
	return &CanaryHandler{config: cfg}
}

// SelectUpstream returns the URL of the selected upstream. Requests are routed
// to the canary upstream with probability CanaryPercent/100, and to the stable
// upstream otherwise.
func (h *CanaryHandler) SelectUpstream() string {
	h.mu.RLock()
	pct := h.config.CanaryPercent
	canaryURL := h.config.Canary.URL
	stableURL := h.config.Stable.URL
	h.mu.RUnlock()

	if pct <= 0 {
		return stableURL
	}
	if pct >= 100 {
		return canaryURL
	}
	if rand.IntN(100) < pct {
		return canaryURL
	}
	return stableURL
}

// SetCanaryPercent updates the canary traffic percentage. The value is clamped
// to [0, 100].
func (h *CanaryHandler) SetCanaryPercent(pct int) {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	h.mu.Lock()
	h.config.CanaryPercent = pct
	h.mu.Unlock()
}
