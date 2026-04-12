// key_config.go defines per-API-key default settings such as model, rate limits, and tags.
package identity

import (
	"context"
	"fmt"
	"sync"

	"github.com/soapbucket/sbproxy/internal/ai"
)

// KeyConfig holds default settings associated with an API key.
// When a request does not specify a value, the key's defaults are used.
type KeyConfig struct {
	DefaultModel  string            `json:"default_model,omitempty"`
	DefaultParams map[string]any    `json:"default_params,omitempty"` // temperature, top_p, max_tokens, etc.
	AllowedModels []string          `json:"allowed_models,omitempty"`
	BlockedModels []string          `json:"blocked_models,omitempty"`
	MaxTokens     int               `json:"max_tokens,omitempty"` // Hard cap on max_tokens
	Tags          map[string]string `json:"tags,omitempty"`       // Auto-applied tags
	Metadata      map[string]string `json:"metadata,omitempty"`
	RateLimit     *KeyRateLimit     `json:"rate_limit,omitempty"`
}

// KeyRateLimit defines per-key rate limits.
type KeyRateLimit struct {
	RPM int `json:"rpm,omitempty"` // Requests per minute
	TPM int `json:"tpm,omitempty"` // Tokens per minute
}

// KeyConfigStore provides key config lookup.
type KeyConfigStore interface {
	GetKeyConfig(ctx context.Context, keyID string) (*KeyConfig, error)
}

// MemoryKeyConfigStore is an in-memory implementation of KeyConfigStore.
type MemoryKeyConfigStore struct {
	mu      sync.RWMutex
	configs map[string]*KeyConfig // keyID -> config
}

// NewMemoryKeyConfigStore creates a new in-memory key config store.
func NewMemoryKeyConfigStore() *MemoryKeyConfigStore {
	return &MemoryKeyConfigStore{
		configs: make(map[string]*KeyConfig),
	}
}

// GetKeyConfig returns the config for a key, or nil if not found.
func (s *MemoryKeyConfigStore) GetKeyConfig(_ context.Context, keyID string) (*KeyConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.configs[keyID]
	if !ok {
		return nil, nil
	}
	// Return a copy to avoid mutation.
	cp := *cfg
	return &cp, nil
}

// SetKeyConfig stores a config for a key.
func (s *MemoryKeyConfigStore) SetKeyConfig(keyID string, config *KeyConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[keyID] = config
}

// DeleteKeyConfig removes a config for a key.
func (s *MemoryKeyConfigStore) DeleteKeyConfig(keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.configs, keyID)
}

// KeyConfigResolver merges key defaults with request values.
type KeyConfigResolver struct {
	store KeyConfigStore
}

// NewKeyConfigResolver creates a new resolver backed by the given store.
func NewKeyConfigResolver(store KeyConfigStore) *KeyConfigResolver {
	return &KeyConfigResolver{store: store}
}

// ApplyDefaults merges key config defaults into the request.
// Request values take precedence over key defaults.
// Returns the effective KeyConfig applied (nil if no config found), or an error.
func (r *KeyConfigResolver) ApplyDefaults(ctx context.Context, keyID string, req *ai.ChatCompletionRequest) (*KeyConfig, error) {
	if keyID == "" || req == nil {
		return nil, nil
	}

	cfg, err := r.store.GetKeyConfig(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("key config lookup failed: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}

	// Model: use default if request is empty.
	if req.Model == "" && cfg.DefaultModel != "" {
		req.Model = cfg.DefaultModel
	}

	// Temperature: use default if request is nil.
	if req.Temperature == nil {
		if v, ok := toFloat64(cfg.DefaultParams["temperature"]); ok {
			req.Temperature = &v
		}
	}

	// TopP: use default if request is nil.
	if req.TopP == nil {
		if v, ok := toFloat64(cfg.DefaultParams["top_p"]); ok {
			req.TopP = &v
		}
	}

	// MaxTokens: use default if request is zero, cap by hard limit.
	if req.MaxTokens == nil || *req.MaxTokens == 0 {
		if v, ok := toInt(cfg.DefaultParams["max_tokens"]); ok {
			capped := v
			if cfg.MaxTokens > 0 && capped > cfg.MaxTokens {
				capped = cfg.MaxTokens
			}
			req.MaxTokens = &capped
		}
	} else if cfg.MaxTokens > 0 && req.MaxTokens != nil && *req.MaxTokens > cfg.MaxTokens {
		// Cap request max_tokens by the hard limit.
		capped := cfg.MaxTokens
		req.MaxTokens = &capped
	}

	// Tags: merge (request takes precedence).
	if len(cfg.Tags) > 0 {
		if req.SBTags == nil {
			req.SBTags = make(map[string]string, len(cfg.Tags))
		}
		for k, v := range cfg.Tags {
			if _, exists := req.SBTags[k]; !exists {
				req.SBTags[k] = v
			}
		}
	}

	return cfg, nil
}

// ValidateAccess checks if the request is allowed by key config (model restrictions, token limits).
func (r *KeyConfigResolver) ValidateAccess(ctx context.Context, keyID string, model string) error {
	if keyID == "" {
		return nil
	}

	cfg, err := r.store.GetKeyConfig(ctx, keyID)
	if err != nil {
		return fmt.Errorf("key config lookup failed: %w", err)
	}
	if cfg == nil {
		return nil
	}

	// Check blocked reqctx.
	for _, blocked := range cfg.BlockedModels {
		if blocked == model {
			return fmt.Errorf("model %q is blocked for this API key", model)
		}
	}

	// Check allowed models (if set, model must be in the list).
	if len(cfg.AllowedModels) > 0 {
		found := false
		for _, allowed := range cfg.AllowedModels {
			if allowed == model {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("model %q is not allowed for this API key", model)
		}
	}

	return nil
}

// toFloat64 converts a value from map[string]any to float64.
func toFloat64(v any) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	}
	return 0, false
}

// toInt converts a value from map[string]any to int.
func toInt(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	case float32:
		return int(val), true
	}
	return 0, false
}
