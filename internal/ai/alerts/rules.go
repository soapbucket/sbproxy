// Package alerts implements configurable alert rules with CEL conditions and event bus delivery.
// Alert rules are compiled at config load time; evaluation is per-request with throttle support.
package alerts

import (
	"fmt"
	"sync"
	"time"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// AlertRule is the YAML/JSON configuration for a single alert rule.
type AlertRule struct {
	Name      string            `json:"name" yaml:"name"`
	Condition string            `json:"condition" yaml:"condition"` // CEL expression returning bool
	Severity  string            `json:"severity" yaml:"severity"`   // info, warning, critical
	Message   string            `json:"message" yaml:"message"`     // Mustache template
	Throttle  time.Duration     `json:"throttle" yaml:"throttle"`   // Min time between same alert
	Tags      map[string]string `json:"tags" yaml:"tags"`           // Routing metadata for subscribers
}

// compiledRule holds a pre-compiled CEL program alongside its source config.
type compiledRule struct {
	AlertRule
	program celgo.Program
}

// AlertContext provides the data for alert rule evaluation.
type AlertContext struct {
	WorkspaceID string
	RequestID   string
	Data        map[string]interface{}
}

// alertEnv is the shared CEL environment for alert rule expressions.
var (
	alertEnvOnce sync.Once
	alertEnvVal  *celgo.Env
	alertEnvErr  error
)

// getAlertEnv returns the shared CEL environment for alert expressions.
// The environment exposes all top-level keys from AlertContext.Data as dynamic maps,
// plus common scalar types. This allows expressions like "budget.percent_used >= 80"
// or "request.latency_ms >= 10000".
func getAlertEnv() (*celgo.Env, error) {
	alertEnvOnce.Do(func() {
		alertEnvVal, alertEnvErr = celgo.NewEnv(
			celgo.Variable("budget", celgo.MapType(celgo.StringType, celgo.DynType)),
			celgo.Variable("request", celgo.MapType(celgo.StringType, celgo.DynType)),
			celgo.Variable("health", celgo.MapType(celgo.StringType, celgo.DynType)),
			celgo.Variable("workspace", celgo.StringType),
			ext.Strings(),
		)
	})
	return alertEnvVal, alertEnvErr
}

// validSeverities lists the allowed severity values.
var validSeverities = map[string]bool{
	"info":     true,
	"warning":  true,
	"critical": true,
}

// CompileRules compiles all alert rule configurations and returns compiled rules ready for evaluation.
// Invalid CEL expressions or missing fields cause an immediate error at config load time.
func CompileRules(rules []AlertRule) ([]compiledRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	env, err := getAlertEnv()
	if err != nil {
		return nil, fmt.Errorf("alert_rules: cel env error: %w", err)
	}

	compiled := make([]compiledRule, 0, len(rules))

	for i, rule := range rules {
		if rule.Name == "" {
			return nil, fmt.Errorf("alert_rules[%d]: name is required", i)
		}
		if rule.Condition == "" {
			return nil, fmt.Errorf("alert_rules[%d] %q: condition is required", i, rule.Name)
		}
		if !validSeverities[rule.Severity] {
			return nil, fmt.Errorf("alert_rules[%d] %q: severity must be info, warning, or critical, got %q", i, rule.Name, rule.Severity)
		}

		ast, iss := env.Compile(rule.Condition)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("alert_rules[%d] %q: compile error: %w", i, rule.Name, iss.Err())
		}
		if ast.OutputType() != celgo.BoolType {
			return nil, fmt.Errorf("alert_rules[%d] %q: condition must return bool, got %s", i, rule.Name, ast.OutputType())
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("alert_rules[%d] %q: program error: %w", i, rule.Name, err)
		}

		compiled = append(compiled, compiledRule{
			AlertRule: rule,
			program:   prog,
		})
	}

	return compiled, nil
}
