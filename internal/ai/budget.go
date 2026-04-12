// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// BudgetConfig defines budget limits and behavior.
type BudgetConfig struct {
	Limits             []BudgetLimit     `json:"limits"`
	OnExceed           string            `json:"on_exceed,omitempty"` // "block", "log", "downgrade"
	AlertThresholdPct  int               `json:"alert_threshold_pct,omitempty"`
	DowngradeMap       map[string]string `json:"downgrade_map,omitempty"`       // model -> cheaper model
	DowngradeThreshold float64           `json:"downgrade_threshold,omitempty"` // 0.0-1.0 utilization ratio
}

// BudgetLimit defines a single budget constraint.
type BudgetLimit struct {
	Scope      string  `json:"scope"` // "workspace", "api_key", "user", "model", "origin", "tag:<key>" (e.g. "tag:team")
	MaxCostUSD float64 `json:"max_cost_usd,omitempty"`
	MaxTokens  int64   `json:"max_tokens,omitempty"`
	Period     string  `json:"period"` // "hourly", "daily", "weekly", "monthly"
}

// IsTagScope returns true if the scope is a tag-based scope (e.g., "tag:team").
func (bl BudgetLimit) IsTagScope() bool {
	return strings.HasPrefix(bl.Scope, "tag:")
}

// TagKey returns the tag key for a tag-based scope (e.g., "team" from "tag:team").
func (bl BudgetLimit) TagKey() string {
	if bl.IsTagScope() {
		return bl.Scope[4:]
	}
	return ""
}

// BudgetUsage tracks current usage within a period.
type BudgetUsage struct {
	Tokens  int64   `json:"tokens"`
	CostUSD float64 `json:"cost_usd"`
}

// BudgetStore provides budget storage operations.
type BudgetStore interface {
	GetUsage(ctx context.Context, key string, period string) (*BudgetUsage, error)
	IncrUsage(ctx context.Context, key string, period string, tokens int64, costUSD float64) error
}

// BudgetEnforcer checks and records budget usage.
type BudgetEnforcer struct {
	config       *BudgetConfig
	store        BudgetStore
	Hierarchy    *BudgetHierarchy // Hierarchical token budget resolution (optional)
	TokenTracker *TokenTracker    // Sharded in-memory token tracking (optional)
}

// BudgetDecision captures the limit and scope that triggered a budget action.
type BudgetDecision struct {
	Limit      BudgetLimit
	ScopeValue string
	Usage      *BudgetUsage
	ExceededBy float64
}

// BudgetUtilizationSnapshot captures utilization for a resolved scope.
type BudgetUtilizationSnapshot struct {
	Limit       BudgetLimit
	ScopeValue  string
	Usage       *BudgetUsage
	Utilization float64
}

// NewBudgetEnforcer creates a new budget enforcer.
func NewBudgetEnforcer(cfg *BudgetConfig, store BudgetStore) *BudgetEnforcer {
	if cfg.OnExceed == "" {
		cfg.OnExceed = "block"
	}
	return &BudgetEnforcer{
		config: cfg,
		store:  store,
	}
}

// Config returns the budget configuration.
func (be *BudgetEnforcer) Config() *BudgetConfig {
	return be.config
}

// Store returns the budget store.
func (be *BudgetEnforcer) Store() BudgetStore {
	return be.store
}

func (be *BudgetEnforcer) scopeValueForLimit(limit BudgetLimit, scopeValues map[string]string) (string, bool) {
	if scopeValues == nil {
		return "", false
	}
	scopeValue, ok := scopeValues[limit.Scope]
	if !ok || scopeValue == "" {
		return "", false
	}
	return scopeValue, true
}

func budgetScopePriority(scope string) int {
	switch {
	case strings.HasPrefix(scope, "tag:"):
		return 6
	case scope == "api_key":
		return 5
	case scope == "user":
		return 4
	case scope == "model":
		return 3
	case scope == "origin":
		return 2
	case scope == "workspace":
		return 1
	default:
		return 0
	}
}

func pickMoreSpecificBudgetDecision(current, candidate *BudgetDecision) *BudgetDecision {
	if current == nil {
		return candidate
	}
	currentPriority := budgetScopePriority(current.Limit.Scope)
	candidatePriority := budgetScopePriority(candidate.Limit.Scope)
	if candidatePriority > currentPriority {
		return candidate
	}
	if candidatePriority < currentPriority {
		return current
	}
	if candidate.ExceededBy > current.ExceededBy {
		return candidate
	}
	return current
}

// ShouldDowngrade returns a cheaper substitute model if the budget utilization
// has reached the downgrade threshold and the model has a mapping.
// Only active when OnExceed is "downgrade".
func (be *BudgetEnforcer) ShouldDowngrade(ctx context.Context, scopeKey string, model string) (string, bool) {
	if be.config.OnExceed != "downgrade" || len(be.config.DowngradeMap) == 0 {
		return "", false
	}
	substitute, ok := be.config.DowngradeMap[model]
	if !ok {
		return "", false
	}
	threshold := be.config.DowngradeThreshold
	if threshold <= 0 {
		threshold = 0.8
	}
	for _, limit := range be.config.Limits {
		usage, err := be.store.GetUsage(ctx, be.budgetKey(scopeKey, limit), limit.Period)
		if err != nil {
			continue
		}
		if limit.MaxCostUSD > 0 && usage.CostUSD/limit.MaxCostUSD >= threshold {
			return substitute, true
		}
		if limit.MaxTokens > 0 && float64(usage.Tokens)/float64(limit.MaxTokens) >= threshold {
			return substitute, true
		}
	}
	return "", false
}

// ShouldDowngradeScopes performs downgrade evaluation using resolved scope values.
func (be *BudgetEnforcer) ShouldDowngradeScopes(ctx context.Context, scopeValues map[string]string, model string) (string, *BudgetUtilizationSnapshot, bool) {
	if be.config.OnExceed != "downgrade" || len(be.config.DowngradeMap) == 0 {
		return "", nil, false
	}
	substitute, ok := be.config.DowngradeMap[model]
	if !ok {
		return "", nil, false
	}
	threshold := be.config.DowngradeThreshold
	if threshold <= 0 {
		threshold = 0.8
	}
	snapshots := be.UtilizationSnapshots(ctx, scopeValues)
	for _, snapshot := range snapshots {
		if snapshot.Utilization >= threshold {
			s := snapshot
			return substitute, &s, true
		}
	}
	return "", nil, false
}

// Utilization returns the highest budget utilization ratio (0.0-1.0) across all limits.
func (be *BudgetEnforcer) Utilization(ctx context.Context, scopeKey string) float64 {
	var maxUtil float64
	for _, limit := range be.config.Limits {
		usage, err := be.store.GetUsage(ctx, be.budgetKey(scopeKey, limit), limit.Period)
		if err != nil {
			continue
		}
		if limit.MaxCostUSD > 0 {
			if u := usage.CostUSD / limit.MaxCostUSD; u > maxUtil {
				maxUtil = u
			}
		}
		if limit.MaxTokens > 0 {
			if u := float64(usage.Tokens) / float64(limit.MaxTokens); u > maxUtil {
				maxUtil = u
			}
		}
	}
	return maxUtil
}

// UtilizationSnapshots returns utilization for each resolved scope limit.
func (be *BudgetEnforcer) UtilizationSnapshots(ctx context.Context, scopeValues map[string]string) []BudgetUtilizationSnapshot {
	snapshots := make([]BudgetUtilizationSnapshot, 0, len(be.config.Limits))
	for _, limit := range be.config.Limits {
		scopeValue, ok := be.scopeValueForLimit(limit, scopeValues)
		if !ok {
			continue
		}
		usage, err := be.store.GetUsage(ctx, be.budgetKey(scopeValue, limit), limit.Period)
		if err != nil {
			continue
		}
		var ratio float64
		if limit.MaxCostUSD > 0 {
			ratio = usage.CostUSD / limit.MaxCostUSD
		}
		if limit.MaxTokens > 0 {
			tokenRatio := float64(usage.Tokens) / float64(limit.MaxTokens)
			if tokenRatio > ratio {
				ratio = tokenRatio
			}
		}
		snapshots = append(snapshots, BudgetUtilizationSnapshot{
			Limit:       limit,
			ScopeValue:  scopeValue,
			Usage:       usage,
			Utilization: ratio,
		})
	}
	return snapshots
}

// Check returns nil if within budget, or an error if exceeded.
func (be *BudgetEnforcer) Check(ctx context.Context, scopeKey string, estimatedTokens int) error {
	for _, limit := range be.config.Limits {
		usage, err := be.store.GetUsage(ctx, be.budgetKey(scopeKey, limit), limit.Period)
		if err != nil {
			continue // fail open on store errors
		}

		if limit.MaxTokens > 0 && usage.Tokens+int64(estimatedTokens) > limit.MaxTokens {
			switch be.config.OnExceed {
			case "block":
				return ErrBudgetExceeded(fmt.Sprintf("token budget exceeded for %s (limit: %d, used: %d)", limit.Scope, limit.MaxTokens, usage.Tokens))
			case "log":
				slog.Warn("budget exceeded - log mode",
					"scope", limit.Scope,
					"scope_key", scopeKey,
					"usage_tokens", usage.Tokens,
					"limit_tokens", limit.MaxTokens)
				return nil // Don't block
			}
		}
		if limit.MaxCostUSD > 0 && usage.CostUSD > limit.MaxCostUSD {
			switch be.config.OnExceed {
			case "block":
				return ErrBudgetExceeded(fmt.Sprintf("cost budget exceeded for %s (limit: $%.2f, used: $%.2f)", limit.Scope, limit.MaxCostUSD, usage.CostUSD))
			case "log":
				slog.Warn("budget exceeded - log mode",
					"scope", limit.Scope,
					"scope_key", scopeKey,
					"usage_cost", usage.CostUSD,
					"limit_cost", limit.MaxCostUSD)
				return nil // Don't block
			case "downgrade":
				// Downgrade is handled separately via ShouldDowngrade()
				// Log that we're in downgrade mode
				slog.Info("budget exceeded - downgrade mode",
					"scope", limit.Scope,
					"scope_key", scopeKey)
				// Continue (don't block, let router handle downgrade)
				return nil
			}
		}
	}
	return nil
}

// CheckScopes evaluates budget limits using resolved scope values.
func (be *BudgetEnforcer) CheckScopes(ctx context.Context, scopeValues map[string]string, estimatedTokens int) (*BudgetDecision, error) {
	var exceeded *BudgetDecision
	for _, limit := range be.config.Limits {
		scopeValue, ok := be.scopeValueForLimit(limit, scopeValues)
		if !ok {
			continue
		}
		usage, err := be.store.GetUsage(ctx, be.budgetKey(scopeValue, limit), limit.Period)
		if err != nil {
			continue // fail open on store errors
		}
		decision := &BudgetDecision{
			Limit:      limit,
			ScopeValue: scopeValue,
			Usage:      usage,
		}
		if limit.MaxTokens > 0 && usage.Tokens+int64(estimatedTokens) > limit.MaxTokens {
			decision.ExceededBy = float64(usage.Tokens+int64(estimatedTokens)-limit.MaxTokens) / float64(limit.MaxTokens)
			switch be.config.OnExceed {
			case "block":
				exceeded = pickMoreSpecificBudgetDecision(exceeded, decision)
			case "log":
				slog.Warn("budget exceeded - log mode",
					"scope", limit.Scope,
					"scope_value", scopeValue,
					"usage_tokens", usage.Tokens,
					"limit_tokens", limit.MaxTokens)
			}
		}
		if limit.MaxCostUSD > 0 && usage.CostUSD > limit.MaxCostUSD {
			decision.ExceededBy = (usage.CostUSD - limit.MaxCostUSD) / limit.MaxCostUSD
			switch be.config.OnExceed {
			case "block":
				exceeded = pickMoreSpecificBudgetDecision(exceeded, decision)
			case "log":
				slog.Warn("budget exceeded - log mode",
					"scope", limit.Scope,
					"scope_value", scopeValue,
					"usage_cost", usage.CostUSD,
					"limit_cost", limit.MaxCostUSD)
			case "downgrade":
				slog.Info("budget exceeded - downgrade mode",
					"scope", limit.Scope,
					"scope_value", scopeValue)
			}
		}
	}
	if exceeded != nil {
		limit := exceeded.Limit
		usage := exceeded.Usage
		if limit.MaxTokens > 0 && usage != nil && usage.Tokens+int64(estimatedTokens) > limit.MaxTokens {
			return exceeded, ErrBudgetExceeded(fmt.Sprintf("token budget exceeded for %s=%s (limit: %d, used: %d)", limit.Scope, exceeded.ScopeValue, limit.MaxTokens, usage.Tokens))
		}
		if limit.MaxCostUSD > 0 && usage != nil && usage.CostUSD > limit.MaxCostUSD {
			return exceeded, ErrBudgetExceeded(fmt.Sprintf("cost budget exceeded for %s=%s (limit: $%.2f, used: $%.2f)", limit.Scope, exceeded.ScopeValue, limit.MaxCostUSD, usage.CostUSD))
		}
	}
	return nil, nil
}

// Record records actual usage after a request completes.
func (be *BudgetEnforcer) Record(ctx context.Context, scopeKey string, tokens int64, costUSD float64) error {
	for _, limit := range be.config.Limits {
		if err := be.store.IncrUsage(ctx, be.budgetKey(scopeKey, limit), limit.Period, tokens, costUSD); err != nil {
			return err
		}
	}
	return nil
}

// RecordScopes records usage for each resolved scope exactly once.
func (be *BudgetEnforcer) RecordScopes(ctx context.Context, scopeValues map[string]string, tokens int64, costUSD float64) error {
	for _, limit := range be.config.Limits {
		scopeValue, ok := be.scopeValueForLimit(limit, scopeValues)
		if !ok {
			continue
		}
		if err := be.store.IncrUsage(ctx, be.budgetKey(scopeValue, limit), limit.Period, tokens, costUSD); err != nil {
			return err
		}
	}
	return nil
}

func (be *BudgetEnforcer) budgetKey(scopeKey string, limit BudgetLimit) string {
	return fmt.Sprintf("budget:%s:%s", limit.Scope, scopeKey)
}

// BudgetKeyForTag creates a budget key for a tag-based scope using the tag value.
func (be *BudgetEnforcer) BudgetKeyForTag(limit BudgetLimit, tagValue string) string {
	return fmt.Sprintf("budget:%s:%s", limit.Scope, tagValue)
}

// CheckTagBudgets evaluates tag-scoped budget limits using provided tags.
// Tags maps tag keys (e.g., "team") to tag values (e.g., "platform").
func (be *BudgetEnforcer) CheckTagBudgets(ctx context.Context, tags map[string]string, estimatedTokens int) error {
	for _, limit := range be.config.Limits {
		if !limit.IsTagScope() {
			continue
		}
		tagValue, ok := tags[limit.TagKey()]
		if !ok || tagValue == "" {
			continue
		}
		budgetKey := be.BudgetKeyForTag(limit, tagValue)
		usage, err := be.store.GetUsage(ctx, budgetKey, limit.Period)
		if err != nil {
			continue
		}
		if limit.MaxTokens > 0 && usage.Tokens+int64(estimatedTokens) > limit.MaxTokens {
			if be.config.OnExceed == "block" {
				return ErrBudgetExceeded(fmt.Sprintf("token budget exceeded for %s=%s (limit: %d, used: %d)", limit.Scope, tagValue, limit.MaxTokens, usage.Tokens))
			}
		}
		if limit.MaxCostUSD > 0 && usage.CostUSD > limit.MaxCostUSD {
			if be.config.OnExceed == "block" {
				return ErrBudgetExceeded(fmt.Sprintf("cost budget exceeded for %s=%s (limit: $%.2f, used: $%.2f)", limit.Scope, tagValue, limit.MaxCostUSD, usage.CostUSD))
			}
		}
	}
	return nil
}

// RecordTagBudgets records usage for tag-scoped budget limits.
func (be *BudgetEnforcer) RecordTagBudgets(ctx context.Context, tags map[string]string, tokens int64, costUSD float64) error {
	for _, limit := range be.config.Limits {
		if !limit.IsTagScope() {
			continue
		}
		tagValue, ok := tags[limit.TagKey()]
		if !ok || tagValue == "" {
			continue
		}
		budgetKey := be.BudgetKeyForTag(limit, tagValue)
		if err := be.store.IncrUsage(ctx, budgetKey, limit.Period, tokens, costUSD); err != nil {
			return err
		}
	}
	return nil
}

// CheckTokenBudget evaluates hierarchical token budget limits for the given scope values.
// It resolves the most specific applicable limit and checks current usage against it.
// Returns the matched limit and an error if the budget is exceeded (for "block" action).
func (be *BudgetEnforcer) CheckTokenBudget(ctx context.Context, scopes map[string]string, estimatedTokens int64) (*HierarchicalLimit, error) {
	if be.Hierarchy == nil || be.TokenTracker == nil {
		return nil, nil
	}

	limits := be.Hierarchy.ResolveAll(scopes)
	for _, limit := range limits {
		key := BuildKey(scopes, limit.Period)
		withinBudget, usage, err := be.TokenTracker.Check(ctx, key, &limit)
		if err != nil {
			continue // fail open on errors
		}
		if withinBudget {
			// Also check if adding estimated tokens would exceed
			if limit.TotalTokenLimit > 0 && usage.TotalTokens+estimatedTokens > limit.TotalTokenLimit {
				withinBudget = false
			}
			if limit.InputTokenLimit > 0 && usage.InputTokens+estimatedTokens > limit.InputTokenLimit {
				withinBudget = false
			}
		}
		if !withinBudget {
			action := limit.Action
			if action == "" {
				action = be.config.OnExceed
			}
			switch action {
			case "block":
				return &limit, ErrBudgetExceeded(fmt.Sprintf(
					"token budget exceeded (input: %d, output: %d, total: %d)",
					usage.InputTokens, usage.OutputTokens, usage.TotalTokens,
				))
			case "log":
				slog.Warn("token budget exceeded - log mode",
					"scopes", scopes,
					"input_tokens", usage.InputTokens,
					"output_tokens", usage.OutputTokens,
					"total_tokens", usage.TotalTokens,
				)
				return &limit, nil
			case "downgrade":
				return &limit, nil
			}
		}
	}
	return nil, nil
}

// RecordTokenUsage records token consumption against all applicable hierarchical limits.
func (be *BudgetEnforcer) RecordTokenUsage(ctx context.Context, scopes map[string]string, inputTokens, outputTokens int64) {
	if be.Hierarchy == nil || be.TokenTracker == nil {
		return
	}

	limits := be.Hierarchy.ResolveAll(scopes)
	for _, limit := range limits {
		key := BuildKey(scopes, limit.Period)
		be.TokenTracker.Record(ctx, key, limit.Period, inputTokens, outputTokens)
	}
}

// PeriodTTL returns the TTL for a budget period.
func PeriodTTL(period string) time.Duration {
	switch period {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	case "monthly":
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// InMemoryBudgetStore is a simple in-memory budget store for testing.
type InMemoryBudgetStore struct {
	usage map[string]*BudgetUsage
	mu    sync.RWMutex
}

// NewInMemoryBudgetStore creates a new in-memory budget store.
func NewInMemoryBudgetStore() *InMemoryBudgetStore {
	return &InMemoryBudgetStore{
		usage: make(map[string]*BudgetUsage),
	}
}

// GetUsage returns the usage for the InMemoryBudgetStore.
func (s *InMemoryBudgetStore) GetUsage(_ context.Context, key string, period string) (*BudgetUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := key + ":" + period
	if u, ok := s.usage[k]; ok {
		return u, nil
	}
	return &BudgetUsage{}, nil
}

// IncrUsage performs the incr usage operation on the InMemoryBudgetStore.
func (s *InMemoryBudgetStore) IncrUsage(_ context.Context, key string, period string, tokens int64, costUSD float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key + ":" + period
	u, ok := s.usage[k]
	if !ok {
		u = &BudgetUsage{}
		s.usage[k] = u
	}
	u.Tokens += tokens
	u.CostUSD += costUSD
	return nil
}
