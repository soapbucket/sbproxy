// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"errors"
	"log/slog"
	"sort"

	celgo "github.com/google/cel-go/cel"
	celPkg "github.com/soapbucket/sbproxy/internal/extension/cel"
)

// CELRoutingRule defines a single CEL-based routing rule.
type CELRoutingRule struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`       // CEL expression that returns bool
	Provider   string `json:"provider"`          // target provider if expression matches
	Priority   int    `json:"priority"`          // lower number = higher priority (default 0)
	Model      string `json:"model,omitempty"`   // optional model override
}

// CELRoutingConfig holds CEL routing configuration.
type CELRoutingConfig struct {
	Rules            []CELRoutingRule `json:"rules"`
	FallbackProvider string           `json:"fallback_provider,omitempty"`
}

// CELRouter evaluates CEL expressions to select AI providers.
type CELRouter struct {
	rules    []compiledRule
	fallback string
}

type compiledRule struct {
	CELRoutingRule
	program celgo.Program
}

// NewCELRouter compiles all CEL expressions and returns a ready-to-use router.
// Rules are sorted by priority (ascending) at construction time so that evaluation
// always proceeds in priority order without additional sorting.
func NewCELRouter(cfg *CELRoutingConfig) (*CELRouter, error) {
	if cfg == nil {
		return nil, errors.New("cel_router: nil config")
	}

	env, err := celPkg.GetAIEnv()
	if err != nil {
		return nil, err
	}

	// Sort rules by priority (ascending) so lower numbers evaluate first
	sorted := make([]CELRoutingRule, len(cfg.Rules))
	copy(sorted, cfg.Rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	compiled := make([]compiledRule, 0, len(sorted))
	for _, rule := range sorted {
		if rule.Expression == "" {
			return nil, errors.New("cel_router: rule " + rule.Name + " has empty expression")
		}
		if rule.Provider == "" {
			return nil, errors.New("cel_router: rule " + rule.Name + " has empty provider")
		}

		ast, iss := env.Compile(rule.Expression)
		if iss != nil && iss.Err() != nil {
			return nil, errors.New("cel_router: rule " + rule.Name + " compile error: " + iss.Err().Error())
		}
		if ast == nil {
			return nil, errors.New("cel_router: rule " + rule.Name + " produced nil AST")
		}
		if ast.OutputType() != celgo.BoolType {
			return nil, errors.New("cel_router: rule " + rule.Name + " must return bool, got " + ast.OutputType().String())
		}

		program, err := env.Program(ast)
		if err != nil {
			return nil, errors.New("cel_router: rule " + rule.Name + " program error: " + err.Error())
		}

		compiled = append(compiled, compiledRule{
			CELRoutingRule: rule,
			program:        program,
		})
	}

	return &CELRouter{
		rules:    compiled,
		fallback: cfg.FallbackProvider,
	}, nil
}

// Evaluate runs all compiled rules in priority order and returns the provider and
// optional model override from the first matching rule. If no rule matches, it
// returns the fallback provider (which may be empty). The matched return value
// indicates whether any rule matched.
func (cr *CELRouter) Evaluate(ctx context.Context, req *ChatCompletionRequest, vars *celPkg.AIContextVars) (provider string, model string, matched bool) {
	if req == nil || len(cr.rules) == 0 {
		return cr.fallback, "", false
	}

	activation := celPkg.BuildAIActivation(vars, nil)

	for _, rule := range cr.rules {
		// Check context cancellation between rule evaluations
		if ctx.Err() != nil {
			slog.Debug("cel_router: context cancelled during evaluation", "error", ctx.Err())
			return cr.fallback, "", false
		}

		out, _, err := rule.program.Eval(activation)
		if err != nil {
			slog.Debug("cel_router: rule evaluation error",
				"rule", rule.Name,
				"expression", rule.Expression,
				"error", err,
			)
			continue
		}

		result, ok := out.Value().(bool)
		if !ok {
			slog.Debug("cel_router: rule returned non-bool",
				"rule", rule.Name,
				"type", out.Type(),
			)
			continue
		}

		if result {
			slog.Debug("cel_router: rule matched",
				"rule", rule.Name,
				"provider", rule.Provider,
				"model", rule.Model,
			)
			return rule.Provider, rule.Model, true
		}
	}

	return cr.fallback, "", false
}

// RuleCount returns the number of compiled rules.
func (cr *CELRouter) RuleCount() int {
	return len(cr.rules)
}
