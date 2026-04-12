// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
)

// WAFRule represents a WAF rule
type WAFRule struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Phase       int      `json:"phase,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Action      string   `json:"action,omitempty"`
	Message     string   `json:"message,omitempty"`
	Targets     []string `json:"targets,omitempty"`

	MatchConditions []WAFMatchCondition `json:"match_conditions,omitempty"`
	Variables       []WAFVariable       `json:"variables,omitempty"`
	Transformations []string            `json:"transformations,omitempty"`
	Operator        string              `json:"operator,omitempty"`
	Pattern         string              `json:"pattern,omitempty"`

	CELExpr   string `json:"cel_expr,omitempty"`
	LuaScript string `json:"lua_script,omitempty"`
	Negate    bool   `json:"negate,omitempty"`
}

// UnmarshalJSON supports both string and int for the Phase field,
// and converts string targets to match_conditions.
func (r *WAFRule) UnmarshalJSON(data []byte) error {
	type Alias WAFRule
	aux := &struct {
		Phase json.RawMessage `json:"phase,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(aux.Phase) > 0 {
		var phaseInt int
		if err := json.Unmarshal(aux.Phase, &phaseInt); err == nil {
			r.Phase = phaseInt
		} else {
			var phaseStr string
			if err := json.Unmarshal(aux.Phase, &phaseStr); err == nil {
				switch strings.ToLower(phaseStr) {
				case "request", "req", "1":
					r.Phase = 1
				case "response", "resp", "2":
					r.Phase = 2
				default:
					return fmt.Errorf("invalid phase string %q: must be \"request\" (1) or \"response\" (2)", phaseStr)
				}
			} else {
				return fmt.Errorf("phase must be an int or string, got: %s", string(aux.Phase))
			}
		}
	}
	// Convert targets like "REQUEST_HEADERS:User-Agent" to match_conditions
	if len(r.Targets) > 0 && len(r.MatchConditions) == 0 && r.Pattern != "" {
		for _, target := range r.Targets {
			mc := WAFMatchCondition{
				Variable: target,
				Operator: "contains",
				Pattern:  r.Pattern,
			}
			r.MatchConditions = append(r.MatchConditions, mc)
		}
	}
	return nil
}

// WAFMatchCondition represents a condition for WAF rule matching
type WAFMatchCondition struct {
	Variable        string   `json:"variable,omitempty"`
	Operator        string   `json:"operator,omitempty"`
	Pattern         string   `json:"pattern,omitempty"`
	Transformations []string `json:"transformations,omitempty"`
	Negate          bool     `json:"negate,omitempty"`
}

// WAFVariable represents a variable to check in WAF rules
type WAFVariable struct {
	Name            string   `json:"name,omitempty"`
	Collection      string   `json:"collection,omitempty"`
	Key             string   `json:"key,omitempty"`
	Transformations []string `json:"transformations,omitempty"`
}

// OWASPCRSConfig configures the OWASP Core Rule Set
type OWASPCRSConfig struct {
	Enabled               bool     `json:"enabled,omitempty"`
	Version               string   `json:"version,omitempty"`
	ParanoiaLevel         int      `json:"paranoia_level,omitempty"`
	AnomalyScoreThreshold int      `json:"anomaly_score_threshold,omitempty"`
	Categories            []string `json:"categories,omitempty"`
	Exclusions            []string `json:"exclusions,omitempty"`
}

// RuleMatchResult represents the result of evaluating a rule
type RuleMatchResult struct {
	RuleID      string
	RuleName    string
	Matched     bool
	Variable    string
	Value       string
	Pattern     string
	Severity    string
	Action      string
	Description string
	Phase       int
}

// RulePerformance tracks performance metrics for a rule using atomic counters
type RulePerformance struct {
	RuleID          string
	ExecutionTimeNs atomic.Int64
	MatchCount      atomic.Int64
	TotalExecutions atomic.Int64
}
