// permissions.go defines PermissionGroup and ModelGrant types for access control.
package identity

import (
	"path"
	"sort"
	"time"
)

// PermissionGroup is a named collection of members with model access grants.
type PermissionGroup struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Members      []string          `json:"members"`              // Principal IDs
	ModelGrants  []ModelGrant      `json:"model_grants"`         // Direct model grants
	AccessGroups []string          `json:"access_groups"`        // Named model sets
	Policies     []string          `json:"policies,omitempty"`   // Policy IDs applied to this group
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ModelGrant defines access to a specific model or pattern.
type ModelGrant struct {
	Model      string `json:"model"`                    // Exact name or glob pattern (e.g., "gpt-4*")
	Permission string `json:"permission"`               // "allow" or "deny"
	MaxTokens  int64  `json:"max_tokens,omitempty"`     // Per-request token limit for this model
	RPM        int    `json:"rpm,omitempty"`             // Rate limit for this model
	Priority   int    `json:"priority,omitempty"`        // Higher priority wins on conflict
}

// AccessGroup is a reusable named set of reqctx.
type AccessGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Models      []string  `json:"models"` // Model names or patterns
	CreatedAt   time.Time `json:"created_at"`
}

// ResolvedPermissions is the final computed permissions for a principal.
type ResolvedPermissions struct {
	PrincipalID string                `json:"principal_id"`
	AllowedModels []string            `json:"allowed_models"`
	DeniedModels  []string            `json:"denied_models"`
	ModelLimits   map[string]ModelLimit `json:"model_limits"`
	Groups        []string            `json:"groups"`
	Policies      []string            `json:"policies"`
}

// ModelLimit holds per-model rate and token limits.
type ModelLimit struct {
	MaxTokens int64 `json:"max_tokens,omitempty"`
	RPM       int   `json:"rpm,omitempty"`
}

// CanAccessModel checks if a model is allowed. Deny takes precedence over allow.
// If AllowedModels is empty and DeniedModels is empty, all models are allowed.
// If AllowedModels is empty but DeniedModels is non-empty, all models except denied are allowed.
func (rp *ResolvedPermissions) CanAccessModel(model string) bool {
	if rp == nil {
		return false
	}

	// Check deny list first. Deny always wins.
	for _, pattern := range rp.DeniedModels {
		if matched, _ := path.Match(pattern, model); matched {
			return false
		}
		if pattern == model {
			return false
		}
	}

	// If no allow list, everything not denied is allowed.
	if len(rp.AllowedModels) == 0 {
		return true
	}

	// Check allow list.
	for _, pattern := range rp.AllowedModels {
		if matched, _ := path.Match(pattern, model); matched {
			return true
		}
		if pattern == model {
			return true
		}
	}

	return false
}

// GetModelLimit returns limits for a specific model. Returns nil if no limits are set.
func (rp *ResolvedPermissions) GetModelLimit(model string) *ModelLimit {
	if rp == nil || rp.ModelLimits == nil {
		return nil
	}

	// Exact match first.
	if lim, ok := rp.ModelLimits[model]; ok {
		return &lim
	}

	// Glob match.
	for pattern, lim := range rp.ModelLimits {
		if matched, _ := path.Match(pattern, model); matched {
			l := lim
			return &l
		}
	}

	return nil
}

// MergeGrants merges model grants from multiple groups.
// Rules:
//   - deny wins over allow at the same priority
//   - higher priority (lower number) wins across groups
//   - limits: take most restrictive (min) across groups
func MergeGrants(grants []ModelGrant) (allowed []string, denied []string, limits map[string]ModelLimit) {
	limits = make(map[string]ModelLimit)

	if len(grants) == 0 {
		return nil, nil, limits
	}

	// Sort by priority ascending (lower number = higher priority).
	sorted := make([]ModelGrant, len(grants))
	copy(sorted, grants)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	// Track decisions per model pattern. The first decision at highest priority wins,
	// but deny at the same priority overrides allow.
	type decision struct {
		permission string
		priority   int
	}
	decisions := make(map[string]*decision)

	for _, g := range sorted {
		existing, ok := decisions[g.Model]
		if !ok {
			// First time seeing this model pattern.
			decisions[g.Model] = &decision{permission: g.Permission, priority: g.Priority}
		} else if g.Priority == existing.priority && g.Permission == "deny" {
			// Same priority, deny wins.
			existing.permission = "deny"
		}
		// Lower priority (higher number) for the same model is ignored.

		// Accumulate limits for models (regardless of allow/deny).
		if g.MaxTokens > 0 || g.RPM > 0 {
			cur, exists := limits[g.Model]
			if !exists {
				cur = ModelLimit{MaxTokens: g.MaxTokens, RPM: g.RPM}
			} else {
				if g.MaxTokens > 0 && (cur.MaxTokens == 0 || g.MaxTokens < cur.MaxTokens) {
					cur.MaxTokens = g.MaxTokens
				}
				if g.RPM > 0 && (cur.RPM == 0 || g.RPM < cur.RPM) {
					cur.RPM = g.RPM
				}
			}
			limits[g.Model] = cur
		}
	}

	allowSet := make(map[string]struct{})
	denySet := make(map[string]struct{})

	for model, d := range decisions {
		if d.permission == "deny" {
			denySet[model] = struct{}{}
		} else {
			allowSet[model] = struct{}{}
		}
	}

	// Remove models from allow if they appear in deny.
	for model := range denySet {
		delete(allowSet, model)
	}

	for model := range allowSet {
		allowed = append(allowed, model)
	}
	for model := range denySet {
		denied = append(denied, model)
	}

	// Sort for deterministic output.
	sort.Strings(allowed)
	sort.Strings(denied)

	return allowed, denied, limits
}
