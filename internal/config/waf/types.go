// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import "sync/atomic"

// WAFRule represents a WAF rule
type WAFRule struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	Phase       int    `json:"phase,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Action      string `json:"action,omitempty"`

	MatchConditions []WAFMatchCondition `json:"match_conditions,omitempty"`
	Variables       []WAFVariable       `json:"variables,omitempty"`
	Transformations []string            `json:"transformations,omitempty"`
	Operator        string              `json:"operator,omitempty"`
	Pattern         string              `json:"pattern,omitempty"`

	CELExpr   string `json:"cel_expr,omitempty"`
	LuaScript string `json:"lua_script,omitempty"`
	Negate    bool   `json:"negate,omitempty"`
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
