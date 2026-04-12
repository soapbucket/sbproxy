// tenant_sync.go manages sidecar tenant registration lifecycle with config diffing.
package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/soapbucket/sbproxy/internal/request/classifier/classifierpkg"
)

// TenantSync manages the lifecycle of sidecar tenant registrations.
// It tracks which config IDs are registered and diffs on reload to avoid
// unnecessary re-registrations when the config has not changed.
type TenantSync struct {
	mc         *ManagedClient
	registered map[string]string // configID -> hash of TenantConfig
	mu         sync.Mutex
}

// NewTenantSync creates a TenantSync bound to the given ManagedClient.
func NewTenantSync(mc *ManagedClient) *TenantSync {
	return &TenantSync{
		mc:         mc,
		registered: make(map[string]string),
	}
}

// SidecarLabelConfig represents label config extracted from origin configs.
type SidecarLabelConfig struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
	Weight   float64  `json:"weight,omitempty"`
}

// SidecarClassifyConfig holds classification settings from origin config.
type SidecarClassifyConfig struct {
	ConfidenceThreshold float64 `json:"confidence_threshold,omitempty"`
	DefaultLabel        string  `json:"default_label,omitempty"`
}

// SidecarNormRule represents a normalization rule from origin config.
type SidecarNormRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// OriginSidecarConfig holds all sidecar-related config extracted from an origin.
type OriginSidecarConfig struct {
	Labels         []SidecarLabelConfig
	Classification *SidecarClassifyConfig
	NormRules      []SidecarNormRule
}

// IsEmpty returns true if no sidecar features are configured.
func (o *OriginSidecarConfig) IsEmpty() bool {
	return len(o.Labels) == 0 && len(o.NormRules) == 0
}

// MergeTenantConfig converts an OriginSidecarConfig into a classifierpkg.TenantConfig.
// When multiple features define the same label name, patterns are merged and the
// higher weight wins.
func MergeTenantConfig(cfg *OriginSidecarConfig) *classifierpkg.TenantConfig {
	if cfg == nil || cfg.IsEmpty() {
		return nil
	}

	// Merge labels: same name -> merge patterns, take higher weight.
	labelMap := make(map[string]*classifierpkg.TenantLabel)
	var labelOrder []string
	for _, l := range cfg.Labels {
		if existing, ok := labelMap[l.Name]; ok {
			existing.Patterns = append(existing.Patterns, l.Patterns...)
			if l.Weight > existing.Weight {
				existing.Weight = l.Weight
			}
		} else {
			labelMap[l.Name] = &classifierpkg.TenantLabel{
				Name:     l.Name,
				Patterns: append([]string{}, l.Patterns...),
				Weight:   l.Weight,
			}
			labelOrder = append(labelOrder, l.Name)
		}
	}

	labels := make([]classifierpkg.TenantLabel, 0, len(labelOrder))
	for _, name := range labelOrder {
		labels = append(labels, *labelMap[name])
	}

	tc := &classifierpkg.TenantConfig{
		Labels: labels,
	}

	if cfg.Classification != nil {
		tc.Classification = &classifierpkg.TenantClassification{
			ConfidenceThreshold: cfg.Classification.ConfidenceThreshold,
			DefaultLabel:        cfg.Classification.DefaultLabel,
		}
	}

	if len(cfg.NormRules) > 0 {
		rules := make([]classifierpkg.TenantNormRule, len(cfg.NormRules))
		for i, r := range cfg.NormRules {
			rules[i] = classifierpkg.TenantNormRule{
				Name:    r.Name,
				Pattern: r.Pattern,
				Replace: r.Replace,
				Enabled: true,
			}
		}
		tc.Normalization = &classifierpkg.TenantNormalization{
			UnicodeNFKC: true,
			Trim:        true,
			Rules:       rules,
		}
	}

	return tc
}

// RegisterOrigin registers or updates a tenant for the given config ID.
// Returns nil without action if no sidecar features are configured for this
// origin, or if the sidecar is not available.
func (ts *TenantSync) RegisterOrigin(configID string, cfg *OriginSidecarConfig) error {
	if cfg == nil || cfg.IsEmpty() {
		return nil
	}
	if ts.mc == nil || !ts.mc.IsAvailable() {
		slog.Debug("classifier sidecar not available, skipping tenant registration",
			"config_id", configID)
		return nil
	}

	tc := MergeTenantConfig(cfg)
	if tc == nil {
		return nil
	}

	hash := hashTenantConfig(tc)

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Skip if already registered with the same config.
	if existing, ok := ts.registered[configID]; ok && existing == hash {
		return nil
	}

	if err := ts.mc.Register(configID, tc); err != nil {
		slog.Warn("failed to register classifier tenant",
			"config_id", configID, "error", err)
		return err
	}

	ts.registered[configID] = hash
	slog.Info("registered classifier tenant",
		"config_id", configID, "labels", len(tc.Labels))
	return nil
}

// DeleteOrigin removes a tenant registration for the given config ID.
func (ts *TenantSync) DeleteOrigin(configID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, ok := ts.registered[configID]; !ok {
		return nil
	}

	if ts.mc != nil && ts.mc.IsAvailable() {
		if err := ts.mc.Delete(configID); err != nil {
			slog.Warn("failed to delete classifier tenant",
				"config_id", configID, "error", err)
			return err
		}
	}

	delete(ts.registered, configID)
	slog.Info("deleted classifier tenant", "config_id", configID)
	return nil
}

// RegisteredCount returns the number of currently registered tenants.
func (ts *TenantSync) RegisteredCount() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.registered)
}

// hashTenantConfig produces a short deterministic hash of a TenantConfig.
// Used for diff detection to avoid unnecessary re-registrations.
func hashTenantConfig(tc *classifierpkg.TenantConfig) string {
	data, _ := json.Marshal(tc)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8]) // 16-char hex is sufficient for diff detection
}
