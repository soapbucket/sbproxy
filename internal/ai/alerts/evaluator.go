package alerts

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/template"
)

// AlertEvaluator evaluates compiled alert rules against context data, applies throttling,
// renders messages, and emits events via the event bus.
type AlertEvaluator struct {
	rules      []compiledRule
	cache      cacher.Cacher         // For distributed throttle (nil = per-instance)
	instanceID string                // Unique instance identifier for throttle keys
	localMu    sync.Mutex            // Protects localThrottle
	localThrottle map[string]time.Time // Per-instance throttle when cache is nil
}

// NewAlertEvaluator compiles alert rules and returns an evaluator ready for use.
// Returns an error if any rule has an invalid CEL expression.
// Returns nil if rules is empty.
func NewAlertEvaluator(rules []AlertRule, cache cacher.Cacher, instanceID string) (*AlertEvaluator, error) {
	compiled, err := CompileRules(rules)
	if err != nil {
		return nil, err
	}
	if len(compiled) == 0 {
		return nil, nil
	}

	return &AlertEvaluator{
		rules:         compiled,
		cache:         cache,
		instanceID:    instanceID,
		localThrottle: make(map[string]time.Time),
	}, nil
}

// Evaluate evaluates all rules against the given context, firing ai.alert.fired events
// for each rule whose condition matches and is not throttled.
func (e *AlertEvaluator) Evaluate(ctx context.Context, alertCtx AlertContext) []events.AIAlertFired {
	if e == nil || len(e.rules) == 0 {
		return nil
	}

	activation := buildActivation(alertCtx)
	var fired []events.AIAlertFired

	for _, rule := range e.rules {
		matched, err := evalRule(rule, activation)
		if err != nil {
			slog.Warn("alert_evaluator: rule eval error",
				"rule", rule.Name, "error", err,
				"workspace_id", alertCtx.WorkspaceID)
			continue
		}
		if !matched {
			continue
		}

		// Check throttle
		if e.isThrottled(ctx, rule, alertCtx.WorkspaceID) {
			slog.Debug("alert_evaluator: rule throttled",
				"rule", rule.Name, "workspace_id", alertCtx.WorkspaceID)
			continue
		}

		// Render message via Mustache template
		message := rule.Message
		if message != "" {
			rendered, renderErr := template.ResolveWithContext(message, alertCtx.Data)
			if renderErr != nil {
				slog.Warn("alert_evaluator: message render error",
					"rule", rule.Name, "error", renderErr)
				// Fall through with unrendered message
			} else {
				message = rendered
			}
		}

		// Map severity to event severity constant
		severity := mapSeverity(rule.Severity)

		// Build event
		evt := events.NewAIAlertFired(
			alertCtx.WorkspaceID,
			alertCtx.RequestID,
			severity,
			rule.Name,
			message,
			rule.Condition,
			rule.Tags,
			alertCtx.Data,
		)

		// Emit to event bus
		events.Emit(ctx, alertCtx.WorkspaceID, evt)

		// Record throttle
		e.recordThrottle(ctx, rule, alertCtx.WorkspaceID)

		fired = append(fired, evt)
	}

	return fired
}

// EvaluateBudget evaluates alert rules with budget data context.
func (e *AlertEvaluator) EvaluateBudget(ctx context.Context, alertCtx AlertContext, budgetData map[string]interface{}) []events.AIAlertFired {
	if alertCtx.Data == nil {
		alertCtx.Data = make(map[string]interface{})
	}
	alertCtx.Data["budget"] = budgetData
	return e.Evaluate(ctx, alertCtx)
}

// EvaluateRequest evaluates alert rules with request data context.
func (e *AlertEvaluator) EvaluateRequest(ctx context.Context, alertCtx AlertContext, requestData map[string]interface{}) []events.AIAlertFired {
	if alertCtx.Data == nil {
		alertCtx.Data = make(map[string]interface{})
	}
	alertCtx.Data["request"] = requestData
	return e.Evaluate(ctx, alertCtx)
}

// EvaluateHealth evaluates alert rules with health data context.
func (e *AlertEvaluator) EvaluateHealth(ctx context.Context, alertCtx AlertContext, healthData map[string]interface{}) []events.AIAlertFired {
	if alertCtx.Data == nil {
		alertCtx.Data = make(map[string]interface{})
	}
	alertCtx.Data["health"] = healthData
	return e.Evaluate(ctx, alertCtx)
}

// buildActivation constructs the CEL activation map from the alert context.
// Top-level keys (budget, request, health) are exposed as separate CEL variables.
// Missing keys default to empty maps so CEL expressions never get nil.
func buildActivation(alertCtx AlertContext) map[string]interface{} {
	act := map[string]interface{}{
		"budget":    map[string]interface{}{},
		"request":   map[string]interface{}{},
		"health":    map[string]interface{}{},
		"workspace": alertCtx.WorkspaceID,
	}

	if alertCtx.Data != nil {
		if v, ok := alertCtx.Data["budget"]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				act["budget"] = m
			}
		}
		if v, ok := alertCtx.Data["request"]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				act["request"] = m
			}
		}
		if v, ok := alertCtx.Data["health"]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				act["health"] = m
			}
		}
	}

	return act
}

// evalRule evaluates a single compiled rule against the activation map.
func evalRule(rule compiledRule, activation map[string]interface{}) (bool, error) {
	out, _, err := rule.program.Eval(activation)
	if err != nil {
		return false, err
	}
	val, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("condition did not return bool for rule %q", rule.Name)
	}
	return val, nil
}

// throttleKey builds a unique key for throttle tracking.
func (e *AlertEvaluator) throttleKey(rule compiledRule, workspaceID string) string {
	return fmt.Sprintf("alert:throttle:%s:%s:%s", e.instanceID, workspaceID, rule.Name)
}

// isThrottled checks whether the alert has fired recently within the throttle window.
func (e *AlertEvaluator) isThrottled(ctx context.Context, rule compiledRule, workspaceID string) bool {
	if rule.Throttle <= 0 {
		return false
	}

	key := e.throttleKey(rule, workspaceID)

	// Distributed throttle via cache
	if e.cache != nil {
		reader, err := e.cache.Get(ctx, "alerts", key)
		if err != nil {
			// Cache miss or error - not throttled
			return false
		}
		if reader != nil {
			// Key exists - throttled
			return true
		}
		return false
	}

	// Per-instance throttle
	e.localMu.Lock()
	defer e.localMu.Unlock()

	lastFired, ok := e.localThrottle[key]
	if !ok {
		return false
	}
	return time.Since(lastFired) < rule.Throttle
}

// recordThrottle records that an alert has fired, setting the throttle window.
func (e *AlertEvaluator) recordThrottle(ctx context.Context, rule compiledRule, workspaceID string) {
	if rule.Throttle <= 0 {
		return
	}

	key := e.throttleKey(rule, workspaceID)

	// Distributed throttle via cache (SETNX-like: PutWithExpires)
	if e.cache != nil {
		err := e.cache.PutWithExpires(ctx, "alerts", key, strings.NewReader("1"), rule.Throttle)
		if err != nil {
			slog.Warn("alert_evaluator: failed to set throttle in cache",
				"rule", rule.Name, "error", err)
		}
		return
	}

	// Per-instance throttle
	e.localMu.Lock()
	defer e.localMu.Unlock()
	e.localThrottle[key] = time.Now()
}

// mapSeverity converts a rule severity string to the events package severity constant.
func mapSeverity(severity string) string {
	switch severity {
	case "critical":
		return events.SeverityCritical
	case "warning":
		return events.SeverityWarning
	case "info":
		return events.SeverityInfo
	default:
		return events.SeverityWarning
	}
}

// compile-time check that io.Reader is used (for throttle value)
var _ io.Reader = (*strings.Reader)(nil)
