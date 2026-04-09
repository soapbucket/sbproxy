package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Stage represents a single step in the policy pipeline.
type Stage interface {
	Name() string
	Evaluate(ctx context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error)
}

// Engine runs the 9-stage policy pipeline.
type Engine struct {
	stages []Stage
	mu     sync.RWMutex
}

// NewEngine creates an engine with the default 9 stages.
func NewEngine() *Engine {
	return &Engine{
		stages: []Stage{
			&identityValidationStage{},
			&modelAccessStage{},
			&providerAccessStage{},
			&featureGatingStage{},
			&tokenLimitsStage{},
			&rateLimitingStage{},
			&tpmLimitingStage{tpm: NewTPMLimiter()},
			&guardrailRequirementStage{},
			&tagValidationStage{},
		},
	}
}

// NewEngineWithStages creates an engine with custom stages (useful for testing).
func NewEngineWithStages(stages ...Stage) *Engine {
	return &Engine{stages: stages}
}

// Evaluate runs all stages in order, short-circuiting on deny.
func (e *Engine) Evaluate(ctx context.Context, ec *EvaluationContext, policies []*Policy) (*EvaluationResult, error) {
	e.mu.RLock()
	stages := e.stages
	e.mu.RUnlock()

	result := &EvaluationResult{
		Allowed:         true,
		AppliedPolicies: make([]string, 0, len(policies)),
	}

	for _, p := range policies {
		result.AppliedPolicies = append(result.AppliedPolicies, p.ID)
	}

	// Empty policies means allow all.
	if len(policies) == 0 {
		return result, nil
	}

	for _, stage := range stages {
		sr, err := stage.Evaluate(ctx, ec, policies)
		if err != nil {
			return nil, fmt.Errorf("policy stage %s: %w", stage.Name(), err)
		}
		if sr == nil {
			continue
		}
		result.Warnings = append(result.Warnings, sr.Warnings...)
		if !sr.Allowed {
			result.Allowed = false
			result.DeniedBy = stage.Name()
			result.Reason = sr.Reason
			return result, nil
		}
	}

	return result, nil
}

// ---------- Stage 1: Identity Validation ----------

type identityValidationStage struct{}

func (s *identityValidationStage) Name() string { return "identity_validation" }

func (s *identityValidationStage) Evaluate(_ context.Context, ec *EvaluationContext, _ []*Policy) (*StageResult, error) {
	if ec.Principal == nil {
		return &StageResult{Allowed: false, Reason: "no principal provided"}, nil
	}
	if ec.Principal.IsExpired() {
		return &StageResult{Allowed: false, Reason: "principal credentials have expired"}, nil
	}
	return &StageResult{Allowed: true}, nil
}

// ---------- Stage 2: Model Access ----------

type modelAccessStage struct{}

func (s *modelAccessStage) Name() string { return "model_access" }

func (s *modelAccessStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	if ec.Model == "" {
		return &StageResult{Allowed: true}, nil
	}

	for _, p := range policies {
		// Check blocked models first (intersection across policies, but any single block denies).
		for _, blocked := range p.BlockedModels {
			if matchModel(ec.Model, blocked) {
				return &StageResult{
					Allowed: false,
					Reason:  fmt.Sprintf("model %q is blocked by policy %q", ec.Model, p.ID),
				}, nil
			}
		}
	}

	// Check allowed models: if any policy specifies allowed models, the model must appear in at least one.
	hasAllowList := false
	for _, p := range policies {
		if len(p.AllowedModels) > 0 {
			hasAllowList = true
			for _, allowed := range p.AllowedModels {
				if matchModel(ec.Model, allowed) {
					return &StageResult{Allowed: true}, nil
				}
			}
		}
	}

	if hasAllowList {
		return &StageResult{
			Allowed: false,
			Reason:  fmt.Sprintf("model %q is not in any policy's allowed list", ec.Model),
		}, nil
	}

	return &StageResult{Allowed: true}, nil
}

// matchModel checks if a model matches a pattern. Supports wildcard suffix (e.g., "gpt-4*").
func matchModel(model, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(model, strings.TrimSuffix(pattern, "*"))
	}
	return model == pattern
}

// ---------- Stage 3: Provider Access ----------

type providerAccessStage struct{}

func (s *providerAccessStage) Name() string { return "provider_access" }

func (s *providerAccessStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	if ec.Provider == "" {
		return &StageResult{Allowed: true}, nil
	}

	for _, p := range policies {
		for _, blocked := range p.BlockedProviders {
			if ec.Provider == blocked {
				return &StageResult{
					Allowed: false,
					Reason:  fmt.Sprintf("provider %q is blocked by policy %q", ec.Provider, p.ID),
				}, nil
			}
		}
	}

	hasAllowList := false
	for _, p := range policies {
		if len(p.AllowedProviders) > 0 {
			hasAllowList = true
			for _, allowed := range p.AllowedProviders {
				if ec.Provider == allowed {
					return &StageResult{Allowed: true}, nil
				}
			}
		}
	}

	if hasAllowList {
		return &StageResult{
			Allowed: false,
			Reason:  fmt.Sprintf("provider %q is not in any policy's allowed list", ec.Provider),
		}, nil
	}

	return &StageResult{Allowed: true}, nil
}

// ---------- Stage 4: Feature Gating ----------

type featureGatingStage struct{}

func (s *featureGatingStage) Name() string { return "feature_gating" }

func (s *featureGatingStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	var warnings []string

	if ec.IsStreaming {
		allowed := featureAllowed(policies, func(p *Policy) *bool { return p.AllowStreaming })
		if !allowed {
			return &StageResult{Allowed: false, Reason: "streaming is not allowed by policy"}, nil
		}
	}

	if ec.HasTools {
		allowed := featureAllowed(policies, func(p *Policy) *bool { return p.AllowTools })
		if !allowed {
			return &StageResult{Allowed: false, Reason: "tool use is not allowed by policy"}, nil
		}
	}

	if ec.HasImages {
		allowed := featureAllowed(policies, func(p *Policy) *bool { return p.AllowImages })
		if !allowed {
			return &StageResult{Allowed: false, Reason: "image input is not allowed by policy"}, nil
		}
	}

	return &StageResult{Allowed: true, Warnings: warnings}, nil
}

// featureAllowed returns true if the feature is allowed by any policy (OR logic).
// If no policy specifies the flag, it defaults to allowed (true).
func featureAllowed(policies []*Policy, getter func(*Policy) *bool) bool {
	specified := false
	for _, p := range policies {
		val := getter(p)
		if val != nil {
			specified = true
			if *val {
				return true
			}
		}
	}
	// If no policy specifies the flag, allow by default.
	if !specified {
		return true
	}
	return false
}

// ---------- Stage 5: Token Limits ----------

type tokenLimitsStage struct{}

func (s *tokenLimitsStage) Name() string { return "token_limits" }

func (s *tokenLimitsStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	for _, p := range policies {
		if p.MaxInputTokens > 0 && ec.InputTokens > p.MaxInputTokens {
			return &StageResult{
				Allowed: false,
				Reason:  fmt.Sprintf("input tokens %d exceed limit %d (policy %q)", ec.InputTokens, p.MaxInputTokens, p.ID),
			}, nil
		}
		if p.MaxOutputTokens > 0 && ec.OutputTokens > p.MaxOutputTokens {
			return &StageResult{
				Allowed: false,
				Reason:  fmt.Sprintf("output tokens %d exceed limit %d (policy %q)", ec.OutputTokens, p.MaxOutputTokens, p.ID),
			}, nil
		}
		if p.MaxTotalTokens > 0 && (ec.InputTokens+ec.OutputTokens) > p.MaxTotalTokens {
			return &StageResult{
				Allowed: false,
				Reason:  fmt.Sprintf("total tokens %d exceed limit %d (policy %q)", ec.InputTokens+ec.OutputTokens, p.MaxTotalTokens, p.ID),
			}, nil
		}
	}
	return &StageResult{Allowed: true}, nil
}

// ---------- Stage 6: Rate Limiting (RPM/RPD) ----------

type rateLimitingStage struct {
	mu       sync.Mutex
	counters map[string]*rateCounter
}

type rateCounter struct {
	minuteBuckets [60]int32
	dayCount      int32
	lastMinute    int
	lastDay       int
}

func (s *rateLimitingStage) Name() string { return "rate_limiting" }

func (s *rateLimitingStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	if ec.Principal == nil {
		return &StageResult{Allowed: true}, nil
	}

	// Merge the most permissive limits.
	var maxRPM int
	var maxRPD int
	for _, p := range policies {
		if p.RPM > maxRPM {
			maxRPM = p.RPM
		}
		if p.RPD > maxRPD {
			maxRPD = p.RPD
		}
	}

	if maxRPM == 0 && maxRPD == 0 {
		return &StageResult{Allowed: true}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.counters == nil {
		s.counters = make(map[string]*rateCounter)
	}

	key := ec.Principal.GetID()
	rc, ok := s.counters[key]
	if !ok {
		rc = &rateCounter{}
		s.counters[key] = rc
	}

	// Simple counter approach: increment and check.
	rc.minuteBuckets[0]++
	rc.dayCount++

	if maxRPM > 0 && int(rc.minuteBuckets[0]) > maxRPM {
		rc.minuteBuckets[0]--
		rc.dayCount--
		return &StageResult{
			Allowed: false,
			Reason:  fmt.Sprintf("RPM limit exceeded: %d/%d requests per minute", rc.minuteBuckets[0], maxRPM),
		}, nil
	}

	if maxRPD > 0 && int(rc.dayCount) > maxRPD {
		rc.minuteBuckets[0]--
		rc.dayCount--
		return &StageResult{
			Allowed: false,
			Reason:  fmt.Sprintf("RPD limit exceeded: %d/%d requests per day", rc.dayCount, maxRPD),
		}, nil
	}

	return &StageResult{Allowed: true}, nil
}

// ---------- Stage 7: TPM Limiting ----------

type tpmLimitingStage struct {
	tpm *TPMLimiter
}

func (s *tpmLimitingStage) Name() string { return "tpm_limiting" }

func (s *tpmLimitingStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	if ec.Principal == nil {
		return &StageResult{Allowed: true}, nil
	}

	// Merge the most permissive TPM limit.
	var maxTPM int64
	for _, p := range policies {
		if p.TPM > maxTPM {
			maxTPM = p.TPM
		}
	}

	if maxTPM == 0 {
		return &StageResult{Allowed: true}, nil
	}

	tokens := ec.InputTokens + ec.OutputTokens
	key := ec.Principal.GetID()

	if !s.tpm.Check(key, tokens, maxTPM) {
		current := s.tpm.Usage(key)
		return &StageResult{
			Allowed: false,
			Reason:  fmt.Sprintf("TPM limit exceeded: %d+%d would exceed %d tokens/minute (current: %d)", current, tokens, maxTPM, current),
		}, nil
	}

	// Record the usage.
	s.tpm.Record(key, tokens)

	return &StageResult{Allowed: true}, nil
}

// ---------- Stage 8: Guardrail Requirement ----------

type guardrailRequirementStage struct{}

func (s *guardrailRequirementStage) Name() string { return "guardrail_requirement" }

func (s *guardrailRequirementStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	for _, p := range policies {
		if p.RequireGuardrails && !ec.GuardrailsConfigured {
			return &StageResult{
				Allowed: false,
				Reason:  fmt.Sprintf("guardrails are required by policy %q but not configured", p.ID),
			}, nil
		}
	}
	return &StageResult{Allowed: true}, nil
}

// ---------- Stage 9: Tag Validation ----------

type tagValidationStage struct{}

func (s *tagValidationStage) Name() string { return "tag_validation" }

func (s *tagValidationStage) Evaluate(_ context.Context, ec *EvaluationContext, policies []*Policy) (*StageResult, error) {
	for _, p := range policies {
		for k, v := range p.RequiredTags {
			got, ok := ec.Tags[k]
			if !ok {
				return &StageResult{
					Allowed: false,
					Reason:  fmt.Sprintf("required tag %q is missing (policy %q)", k, p.ID),
				}, nil
			}
			if v != "" && v != "*" && got != v {
				return &StageResult{
					Allowed: false,
					Reason:  fmt.Sprintf("tag %q has value %q, expected %q (policy %q)", k, got, v, p.ID),
				}, nil
			}
		}
	}
	return &StageResult{Allowed: true}, nil
}
