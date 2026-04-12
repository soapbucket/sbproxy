// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
)

// RuleEngine evaluates WAF rules against HTTP requests
type RuleEngine struct {
	rules       []WAFRule
	performance map[string]*RulePerformance
	mu          sync.RWMutex

	// Cached CEL and Lua matchers
	celMatchers map[string]cel.Matcher
	luaMatchers map[string]lua.Matcher
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(rules []WAFRule) (*RuleEngine, error) {
	engine := &RuleEngine{
		rules:       rules,
		performance: make(map[string]*RulePerformance),
		celMatchers: make(map[string]cel.Matcher),
		luaMatchers: make(map[string]lua.Matcher),
	}

	// Pre-compile CEL and Lua expressions
	for _, rule := range rules {
		if rule.CELExpr != "" {
			matcher, err := cel.NewMatcher(rule.CELExpr)
			if err != nil {
				return nil, fmt.Errorf("error compiling CEL expression for rule %s: %w", rule.ID, err)
			}
			engine.celMatchers[rule.ID] = matcher
		}

		if rule.LuaScript != "" {
			matcher, err := lua.NewMatcher(rule.LuaScript)
			if err != nil {
				return nil, fmt.Errorf("error compiling Lua script for rule %s: %w", rule.ID, err)
			}
			engine.luaMatchers[rule.ID] = matcher
		}
	}

	return engine, nil
}

// EvaluateRequest evaluates all rules against an HTTP request
func (e *RuleEngine) EvaluateRequest(ctx context.Context, req *http.Request) ([]RuleMatchResult, error) {
	var matches []RuleMatchResult

	// Sort rules by phase
	phases := make(map[int][]WAFRule)
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		phases[rule.Phase] = append(phases[rule.Phase], rule)
	}

	// Evaluate rules in phase order
	for phase := 1; phase <= 5; phase++ {
		rules := phases[phase]
		for _, rule := range rules {
			startTime := time.Now()

			match, err := e.evaluateRule(ctx, req, rule)
			if err != nil {
				// Log error but continue (skip logging for now to avoid import cycle)
				continue
			}

			executionTime := time.Since(startTime)

			// Track performance using atomic counters
			perf := e.getOrCreatePerf(rule.ID)
			perf.TotalExecutions.Add(1)
			perf.ExecutionTimeNs.Add(executionTime.Nanoseconds())
			if match.Matched {
				perf.MatchCount.Add(1)
				matches = append(matches, match)
			}
		}
	}

	return matches, nil
}

// evaluateRule evaluates a single rule against a request
func (e *RuleEngine) evaluateRule(ctx context.Context, req *http.Request, rule WAFRule) (RuleMatchResult, error) {
	result := RuleMatchResult{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Action:      rule.Action,
		Description: rule.Description,
		Phase:       rule.Phase,
		Matched:     false,
	}

	// Evaluate match conditions first
	if len(rule.MatchConditions) > 0 {
		allMatch := true
		for _, condition := range rule.MatchConditions {
			if !e.evaluateCondition(req, condition) {
				allMatch = false
				break
			}
		}
		if !allMatch {
			return result, nil
		}
	}

	// Priority: CEL > Lua > Pattern matching

	// Evaluate CEL expression if present
	if rule.CELExpr != "" {
		e.mu.RLock()
		celMatcher, ok := e.celMatchers[rule.ID]
		e.mu.RUnlock()

		if ok {
			matched := celMatcher.Match(req)
			if rule.Negate {
				matched = !matched
			}

			if matched {
				result.Matched = true
				result.Pattern = rule.CELExpr
				result.Variable = "CEL"
				return result, nil
			}
			return result, nil
		}
	}

	// Evaluate Lua script if present
	if rule.LuaScript != "" {
		e.mu.RLock()
		luaMatcher, ok := e.luaMatchers[rule.ID]
		e.mu.RUnlock()

		if ok {
			matched := luaMatcher.Match(req)
			if rule.Negate {
				matched = !matched
			}

			if matched {
				result.Matched = true
				result.Pattern = rule.LuaScript
				result.Variable = "Lua"
				return result, nil
			}
			return result, nil
		}
	}

	// Evaluate variables with pattern matching
	if len(rule.Variables) > 0 {
		for _, variable := range rule.Variables {
			values := ExtractVariables(req, variable)

			for _, value := range values {
				// Apply transformations
				transformedValue := value
				if len(rule.Transformations) > 0 {
					transformedValue = ApplyTransformations(value, rule.Transformations)
				}

				// Apply operator
				operator := rule.Operator
				if operator == "" {
					operator = "rx" // Default to regex
				}

				matched := MatchOperator(transformedValue, rule.Pattern, operator)

				// Apply negation
				if rule.Negate {
					matched = !matched
				}

				if matched {
					result.Matched = true
					result.Variable = variable.Name
					result.Value = value
					result.Pattern = rule.Pattern
					return result, nil
				}
			}
		}
	} else if rule.Pattern != "" {
		// Simple pattern matching without variables
		// Check against request URI, headers, etc.
		requestLine := req.Method + " " + req.URL.RequestURI()
		transformedValue := ApplyTransformations(requestLine, rule.Transformations)

		operator := rule.Operator
		if operator == "" {
			operator = "rx"
		}

		matched := MatchOperator(transformedValue, rule.Pattern, operator)
		if rule.Negate {
			matched = !matched
		}

		if matched {
			result.Matched = true
			result.Value = requestLine
			result.Pattern = rule.Pattern
		}
	}

	return result, nil
}

// evaluateCondition evaluates a match condition
func (e *RuleEngine) evaluateCondition(req *http.Request, condition WAFMatchCondition) bool {
	values := ExtractVariables(req, WAFVariable{
		Name:            condition.Variable,
		Transformations: condition.Transformations,
	})

	for _, value := range values {
		matched := MatchOperator(value, condition.Pattern, condition.Operator)
		if condition.Negate {
			matched = !matched
		}
		if matched {
			return true
		}
	}

	return false
}

// getOrCreatePerf returns the performance tracker for a rule, creating it if needed.
func (e *RuleEngine) getOrCreatePerf(ruleID string) *RulePerformance {
	e.mu.RLock()
	perf, ok := e.performance[ruleID]
	e.mu.RUnlock()
	if ok {
		return perf
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// Double-check after acquiring write lock
	if perf, ok = e.performance[ruleID]; ok {
		return perf
	}
	perf = &RulePerformance{RuleID: ruleID}
	e.performance[ruleID] = perf
	return perf
}

// GetPerformanceMetrics returns performance metrics for all rules
func (e *RuleEngine) GetPerformanceMetrics() map[string]*RulePerformance {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]*RulePerformance, len(e.performance))
	for k, v := range e.performance {
		out[k] = v
	}
	return out
}

// GetRulePerformance returns performance metrics for a specific rule
func (e *RuleEngine) GetRulePerformance(ruleID string) *RulePerformance {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.performance[ruleID]
}

// ResetPerformanceMetrics resets performance metrics
func (e *RuleEngine) ResetPerformanceMetrics() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.performance = make(map[string]*RulePerformance)
}
