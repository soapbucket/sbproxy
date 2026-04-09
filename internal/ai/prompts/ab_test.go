package prompts

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
)

// ABSelector selects prompt variants based on configured weights.
type ABSelector struct {
	config *ABTestConfig
}

// NewABSelector creates a new A/B test selector.
func NewABSelector(config *ABTestConfig) *ABSelector {
	return &ABSelector{config: config}
}

// Select picks a variant based on weights. If sessionID is non-empty,
// selection is deterministic per session (consistent assignment).
func (s *ABSelector) Select(sessionID string) (*ABTestVariant, int) {
	if s.config == nil || len(s.config.Variants) == 0 {
		return nil, -1
	}

	totalWeight := 0
	for _, v := range s.config.Variants {
		totalWeight += v.Weight
	}
	if totalWeight <= 0 {
		return &s.config.Variants[0], 0
	}

	var roll int
	if sessionID != "" {
		// Deterministic selection based on session ID
		h := sha256.Sum256([]byte(sessionID))
		roll = int(binary.BigEndian.Uint32(h[:4])) % totalWeight
		if roll < 0 {
			roll = -roll
		}
	} else {
		roll = rand.IntN(totalWeight)
	}

	cumulative := 0
	for i, v := range s.config.Variants {
		cumulative += v.Weight
		if roll < cumulative {
			return &v, i
		}
	}

	// Fallback (shouldn't reach here)
	last := len(s.config.Variants) - 1
	return &s.config.Variants[last], last
}

// Resolve selects a variant and resolves the prompt from the store.
func (s *ABSelector) Resolve(ctx context.Context, store Store, sessionID string) (*ResolvedPrompt, *ABTestResult, error) {
	variant, idx := s.Select(sessionID)
	if variant == nil {
		return nil, nil, nil
	}

	prompt, err := store.Get(ctx, variant.PromptID)
	if err != nil {
		return nil, nil, err
	}

	version := variant.Version
	if version == 0 {
		version = prompt.ActiveVersion
	}

	pv, err := store.GetVersion(ctx, variant.PromptID, version)
	if err != nil {
		return nil, nil, err
	}

	resolved := &ResolvedPrompt{
		Content:  pv.Template,
		Model:    pv.Model, //nolint:staticcheck // Legacy LegacyVersion field
		PromptID: variant.PromptID,
		Version:  version,
	}

	result := &ABTestResult{
		PromptID: variant.PromptID,
		Version:  version,
		Variant:  idx,
	}

	return resolved, result, nil
}
