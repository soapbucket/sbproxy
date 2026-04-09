package policy

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// GuardrailLevel defines where a guardrail is configured.
type GuardrailLevel string

const (
	// GuardrailLevelWorkspace applies to all requests in a workspace.
	GuardrailLevelWorkspace GuardrailLevel = "workspace"
	// GuardrailLevelPolicy applies to requests matching a policy.
	GuardrailLevelPolicy GuardrailLevel = "policy"
	// GuardrailLevelModel applies to requests using a specific model.
	GuardrailLevelModel GuardrailLevel = "model"
	// GuardrailLevelRequest applies to a single request (override).
	GuardrailLevelRequest GuardrailLevel = "request"
)

// GuardrailAction defines what happens when a guardrail triggers.
type GuardrailAction string

const (
	// GuardrailActionBlock rejects the request.
	GuardrailActionBlock GuardrailAction = "block"
	// GuardrailActionFlag allows the request but flags it for review.
	GuardrailActionFlag GuardrailAction = "flag"
	// GuardrailActionLog logs the event only.
	GuardrailActionLog GuardrailAction = "log"
	// GuardrailActionRedact masks or redacts matched content.
	GuardrailActionRedact GuardrailAction = "redact"
)

// GuardrailConfig defines a guardrail rule.
type GuardrailConfig struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`       // "keyword", "regex", "pii", "external"
	Level     GuardrailLevel  `json:"level"`
	Action    GuardrailAction `json:"action"`
	Config    map[string]any  `json:"config"`     // Type-specific configuration
	Async     bool            `json:"async"`      // Run asynchronously (don't block)
	Timeout   time.Duration   `json:"timeout,omitempty"`
	Priority  int             `json:"priority"`   // Lower = runs first
	AppliesTo string          `json:"applies_to"` // "input", "output", "both"
	Enabled   bool            `json:"enabled"`
	Disabled  bool            `json:"disabled"`   // Request-level override to disable by ID
}

// GuardrailResult is the outcome of a single guardrail evaluation.
type GuardrailResult struct {
	GuardrailID string          `json:"guardrail_id"`
	Name        string          `json:"name"`
	Triggered   bool            `json:"triggered"`
	Action      GuardrailAction `json:"action"`
	Details     string          `json:"details,omitempty"`
	Latency     time.Duration   `json:"latency"`
	Async       bool            `json:"async"`
}

// GuardrailEvaluation is the complete evaluation result.
type GuardrailEvaluation struct {
	Blocked      bool              `json:"blocked"`
	Flagged      bool              `json:"flagged"`
	Results      []GuardrailResult `json:"results"`
	TotalLatency time.Duration     `json:"total_latency"`
	AsyncPending int               `json:"async_pending"` // Number of async guardrails still running
}

// GuardrailResolver collects guardrails from all 4 levels and resolves the effective set.
type GuardrailResolver struct {
	workspace []*GuardrailConfig
	policies  map[string][]*GuardrailConfig // policyID -> guardrails
	models    map[string][]*GuardrailConfig // modelName -> guardrails
	mu        sync.RWMutex
}

// NewGuardrailResolver creates a new resolver.
func NewGuardrailResolver() *GuardrailResolver {
	return &GuardrailResolver{
		policies: make(map[string][]*GuardrailConfig),
		models:   make(map[string][]*GuardrailConfig),
	}
}

// SetWorkspaceGuardrails configures workspace-level guardrails.
func (gr *GuardrailResolver) SetWorkspaceGuardrails(guardrails []*GuardrailConfig) {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	gr.workspace = guardrails
}

// SetPolicyGuardrails configures policy-level guardrails.
func (gr *GuardrailResolver) SetPolicyGuardrails(policyID string, guardrails []*GuardrailConfig) {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	gr.policies[policyID] = guardrails
}

// SetModelGuardrails configures model-level guardrails.
func (gr *GuardrailResolver) SetModelGuardrails(model string, guardrails []*GuardrailConfig) {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	gr.models[model] = guardrails
}

// Resolve collects all applicable guardrails for a request context.
// Resolution order: workspace (base) + policy (additive) + model (additive) + request (override).
// Dedup by ID. Request-level overrides (e.g., disable specific guardrail) take precedence.
func (gr *GuardrailResolver) Resolve(policyIDs []string, model string, requestOverrides []*GuardrailConfig) []*GuardrailConfig {
	gr.mu.RLock()
	defer gr.mu.RUnlock()

	// Collect all guardrails in resolution order.
	seen := make(map[string]*GuardrailConfig)
	var order []string

	// 1. Workspace-level (base).
	for _, g := range gr.workspace {
		if !g.Enabled {
			continue
		}
		if _, exists := seen[g.ID]; !exists {
			seen[g.ID] = g
			order = append(order, g.ID)
		}
	}

	// 2. Policy-level (additive).
	for _, pid := range policyIDs {
		for _, g := range gr.policies[pid] {
			if !g.Enabled {
				continue
			}
			if _, exists := seen[g.ID]; !exists {
				seen[g.ID] = g
				order = append(order, g.ID)
			}
		}
	}

	// 3. Model-level (additive).
	for _, g := range gr.models[model] {
		if !g.Enabled {
			continue
		}
		if _, exists := seen[g.ID]; !exists {
			seen[g.ID] = g
			order = append(order, g.ID)
		}
	}

	// 4. Request-level overrides: can disable existing guardrails or add new ones.
	for _, g := range requestOverrides {
		if g.Disabled {
			// Remove this guardrail from the resolved set.
			delete(seen, g.ID)
			continue
		}
		if !g.Enabled {
			continue
		}
		// Request-level overrides replace any existing config with the same ID.
		if _, exists := seen[g.ID]; !exists {
			order = append(order, g.ID)
		}
		seen[g.ID] = g
	}

	// Build result sorted by priority.
	result := make([]*GuardrailConfig, 0, len(seen))
	for _, id := range order {
		if g, ok := seen[id]; ok {
			result = append(result, g)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority < result[j].Priority
	})

	return result
}

// GuardrailDetector is the interface for running a specific guardrail type.
type GuardrailDetector interface {
	Detect(ctx context.Context, config *GuardrailConfig, content string) (*GuardrailResult, error)
}

// GuardrailExecutor runs guardrails (sync and async).
type GuardrailExecutor struct {
	detectors map[string]GuardrailDetector // type -> detector
	resolver  *GuardrailResolver
	mu        sync.RWMutex
}

// NewGuardrailExecutor creates an executor with the given resolver.
func NewGuardrailExecutor(resolver *GuardrailResolver) *GuardrailExecutor {
	return &GuardrailExecutor{
		detectors: make(map[string]GuardrailDetector),
		resolver:  resolver,
	}
}

// RegisterDetector adds a detector for a guardrail type.
func (ge *GuardrailExecutor) RegisterDetector(guardrailType string, detector GuardrailDetector) {
	ge.mu.Lock()
	defer ge.mu.Unlock()
	ge.detectors[guardrailType] = detector
}

func (ge *GuardrailExecutor) getDetector(guardrailType string) (GuardrailDetector, bool) {
	ge.mu.RLock()
	defer ge.mu.RUnlock()
	d, ok := ge.detectors[guardrailType]
	return d, ok
}

// EvaluateInput runs all applicable guardrails on input content.
func (ge *GuardrailExecutor) EvaluateInput(ctx context.Context, policyIDs []string, model string, content string, requestOverrides []*GuardrailConfig) (*GuardrailEvaluation, error) {
	return ge.evaluate(ctx, policyIDs, model, content, requestOverrides, "input")
}

// EvaluateOutput runs all applicable guardrails on output content.
func (ge *GuardrailExecutor) EvaluateOutput(ctx context.Context, policyIDs []string, model string, content string, requestOverrides []*GuardrailConfig) (*GuardrailEvaluation, error) {
	return ge.evaluate(ctx, policyIDs, model, content, requestOverrides, "output")
}

func (ge *GuardrailExecutor) evaluate(ctx context.Context, policyIDs []string, model string, content string, requestOverrides []*GuardrailConfig, phase string) (*GuardrailEvaluation, error) {
	all := ge.resolver.Resolve(policyIDs, model, requestOverrides)

	// Filter by applies_to.
	var applicable []*GuardrailConfig
	for _, g := range all {
		if g.AppliesTo == phase || g.AppliesTo == "both" {
			applicable = append(applicable, g)
		}
	}

	eval := &GuardrailEvaluation{}
	start := time.Now()

	// Separate sync and async guardrails.
	var syncGuards, asyncGuards []*GuardrailConfig
	for _, g := range applicable {
		if g.Async {
			asyncGuards = append(asyncGuards, g)
		} else {
			syncGuards = append(syncGuards, g)
		}
	}

	// Run sync guardrails sequentially. Short-circuit on block.
	for _, g := range syncGuards {
		detector, ok := ge.getDetector(g.Type)
		if !ok {
			// Unknown detector type, skip.
			continue
		}

		evalCtx := ctx
		if g.Timeout > 0 {
			var cancel context.CancelFunc
			evalCtx, cancel = context.WithTimeout(ctx, g.Timeout)
			defer cancel()
		}

		result, err := detector.Detect(evalCtx, g, content)
		if err != nil {
			return nil, fmt.Errorf("guardrail %q (%s): %w", g.ID, g.Type, err)
		}

		eval.Results = append(eval.Results, *result)

		if result.Triggered {
			switch result.Action {
			case GuardrailActionBlock:
				eval.Blocked = true
				eval.TotalLatency = time.Since(start)
				return eval, nil
			case GuardrailActionFlag:
				eval.Flagged = true
			}
		}
	}

	// Launch async guardrails concurrently (don't wait for results).
	for range asyncGuards {
		eval.AsyncPending++
	}

	// Launch them in goroutines if there's an async tracker (handled by caller).
	// For now, just record the pending count.

	eval.TotalLatency = time.Since(start)
	return eval, nil
}

// --- Built-in Detectors ---

// KeywordDetector detects keywords/phrases in content.
// Config fields: "keywords" ([]string), "case_sensitive" (bool).
type KeywordDetector struct{}

// Detect checks content for keyword matches.
func (kd *KeywordDetector) Detect(_ context.Context, config *GuardrailConfig, content string) (*GuardrailResult, error) {
	start := time.Now()

	keywords, _ := toStringSlice(config.Config["keywords"])
	caseSensitive, _ := config.Config["case_sensitive"].(bool)

	checkContent := content
	if !caseSensitive {
		checkContent = strings.ToLower(content)
	}

	var matched []string
	for _, kw := range keywords {
		checkKw := kw
		if !caseSensitive {
			checkKw = strings.ToLower(kw)
		}
		if strings.Contains(checkContent, checkKw) {
			matched = append(matched, kw)
		}
	}

	result := &GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
		Latency:     time.Since(start),
	}

	if len(matched) > 0 {
		result.Triggered = true
		result.Details = "matched keywords: " + strings.Join(matched, ", ")
	}

	return result, nil
}

// RegexDetector detects regex patterns in content.
// Config fields: "patterns" ([]string).
type RegexDetector struct {
	cache map[string]*regexp.Regexp
	mu    sync.RWMutex
}

// NewRegexDetector creates a regex detector with a compiled pattern cache.
func NewRegexDetector() *RegexDetector {
	return &RegexDetector{
		cache: make(map[string]*regexp.Regexp),
	}
}

// Detect checks content for regex pattern matches.
func (rd *RegexDetector) Detect(_ context.Context, config *GuardrailConfig, content string) (*GuardrailResult, error) {
	start := time.Now()

	patterns, _ := toStringSlice(config.Config["patterns"])

	result := &GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
		Latency:     time.Since(start),
	}

	var matched []string
	for _, pattern := range patterns {
		re, err := rd.getOrCompile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		if re.MatchString(content) {
			matched = append(matched, pattern)
		}
	}

	if len(matched) > 0 {
		result.Triggered = true
		result.Details = "matched patterns: " + strings.Join(matched, ", ")
	}

	result.Latency = time.Since(start)
	return result, nil
}

func (rd *RegexDetector) getOrCompile(pattern string) (*regexp.Regexp, error) {
	rd.mu.RLock()
	re, ok := rd.cache[pattern]
	rd.mu.RUnlock()
	if ok {
		return re, nil
	}

	rd.mu.Lock()
	defer rd.mu.Unlock()

	// Double-check after acquiring write lock.
	if re, ok := rd.cache[pattern]; ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	rd.cache[pattern] = re
	return re, nil
}

// toStringSlice extracts a string slice from an interface value.
func toStringSlice(v any) ([]string, bool) {
	if v == nil {
		return nil, false
	}
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, true
	default:
		return nil, false
	}
}
