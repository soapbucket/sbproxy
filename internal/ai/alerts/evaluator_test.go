package alerts

import (
	"context"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// testEvaluator creates an evaluator with the given rules and no cache (per-instance throttle).
func testEvaluator(t *testing.T, rules []AlertRule) *AlertEvaluator {
	t.Helper()
	eval, err := NewAlertEvaluator(rules, nil, "test-instance")
	if err != nil {
		t.Fatalf("NewAlertEvaluator: %v", err)
	}
	return eval
}

func TestRuleFiresAtThreshold(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget {{budget.percent_used}}% used",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(80),
			},
		},
	}

	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert fired, got %d", len(fired))
	}
	if fired[0].RuleName != "budget_warning" {
		t.Errorf("expected rule_name 'budget_warning', got %q", fired[0].RuleName)
	}
}

func TestRuleDoesNotFireBelowThreshold(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget warning",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(79),
			},
		},
	}

	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 0 {
		t.Fatalf("expected 0 alerts fired, got %d", len(fired))
	}
}

func TestThrottlePreventsDuplicateWithinWindow(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget warning",
			Throttle:  1 * time.Hour,
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(90),
			},
		},
	}

	// First evaluation should fire
	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("first eval: expected 1 alert, got %d", len(fired))
	}

	// Second evaluation should be throttled
	fired = eval.Evaluate(ctx, alertCtx)
	if len(fired) != 0 {
		t.Fatalf("second eval: expected 0 alerts (throttled), got %d", len(fired))
	}
}

func TestThrottleExpiresAndFiresAgain(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget warning",
			Throttle:  10 * time.Millisecond, // Very short for testing
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(90),
			},
		},
	}

	// First fire
	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("first eval: expected 1 alert, got %d", len(fired))
	}

	// Wait for throttle to expire
	time.Sleep(20 * time.Millisecond)

	// Should fire again
	fired = eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("after throttle expired: expected 1 alert, got %d", len(fired))
	}
}

func TestMultipleRulesAllEvaluated(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget warning",
		},
		{
			Name:      "slow_response",
			Condition: "request.latency_ms >= 10000",
			Severity:  "warning",
			Message:   "Slow response",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(90),
			},
			"request": map[string]interface{}{
				"latency_ms": int64(15000),
			},
		},
	}

	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 2 {
		t.Fatalf("expected 2 alerts fired, got %d", len(fired))
	}

	names := map[string]bool{}
	for _, f := range fired {
		names[f.RuleName] = true
	}
	if !names["budget_warning"] {
		t.Error("expected budget_warning to fire")
	}
	if !names["slow_response"] {
		t.Error("expected slow_response to fire")
	}
}

func TestInvalidCELFailsAtConfigLoad(t *testing.T) {
	_, err := NewAlertEvaluator([]AlertRule{
		{
			Name:      "bad_rule",
			Condition: "this is not valid CEL !!!",
			Severity:  "warning",
			Message:   "nope",
		},
	}, nil, "test")
	if err == nil {
		t.Fatal("expected error for invalid CEL expression, got nil")
	}
}

func TestMustacheMessageRenderedWithContext(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget {{budget.percent_used}}% used for {{budget.scope}}",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(85),
				"scope":        "workspace",
			},
		},
	}

	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(fired))
	}
	if fired[0].Message != "Budget 85% used for workspace" {
		t.Errorf("expected rendered message, got %q", fired[0].Message)
	}
}

func TestTagsPassedThroughToEvent(t *testing.T) {
	tags := map[string]string{
		"channel": "budget-alerts",
		"team":    "platform",
	}
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "critical",
			Message:   "Budget warning",
			Tags:      tags,
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(95),
			},
		},
	}

	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(fired))
	}
	if fired[0].Tags["channel"] != "budget-alerts" {
		t.Errorf("expected tag channel=budget-alerts, got %q", fired[0].Tags["channel"])
	}
	if fired[0].Tags["team"] != "platform" {
		t.Errorf("expected tag team=platform, got %q", fired[0].Tags["team"])
	}
	if fired[0].EventSeverity() != events.SeverityCritical {
		t.Errorf("expected severity critical, got %q", fired[0].EventSeverity())
	}
}

func TestNilCachePerInstanceThrottle(t *testing.T) {
	// This test verifies that when cache is nil, per-instance throttle is used.
	// It is effectively the same as TestThrottlePreventsDuplicateWithinWindow
	// but explicitly tests that the evaluator was created with nil cache.
	eval, err := NewAlertEvaluator([]AlertRule{
		{
			Name:      "test_rule",
			Condition: "budget.percent_used >= 50",
			Severity:  "info",
			Message:   "Test",
			Throttle:  1 * time.Hour,
		},
	}, nil, "instance-1")
	if err != nil {
		t.Fatalf("NewAlertEvaluator: %v", err)
	}
	if eval.cache != nil {
		t.Fatal("expected nil cache for per-instance throttle test")
	}

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data: map[string]interface{}{
			"budget": map[string]interface{}{
				"percent_used": int64(60),
			},
		},
	}

	// First fires
	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(fired))
	}

	// Second is throttled via local map
	fired = eval.Evaluate(ctx, alertCtx)
	if len(fired) != 0 {
		t.Fatalf("expected 0 alerts (per-instance throttle), got %d", len(fired))
	}

	// Verify localThrottle map has an entry
	eval.localMu.Lock()
	if len(eval.localThrottle) == 0 {
		t.Error("expected localThrottle map to have entries")
	}
	eval.localMu.Unlock()
}

func TestEmptyRulesReturnsNilEvaluator(t *testing.T) {
	eval, err := NewAlertEvaluator([]AlertRule{}, nil, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval != nil {
		t.Fatal("expected nil evaluator for empty rules")
	}
}

func TestNilEvaluatorEvaluateSafe(t *testing.T) {
	var eval *AlertEvaluator
	fired := eval.Evaluate(context.Background(), AlertContext{})
	if fired != nil {
		t.Fatalf("expected nil from nil evaluator, got %v", fired)
	}
}

func TestEvaluateBudgetConvenience(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_high",
			Condition: "budget.percent_used >= 90",
			Severity:  "critical",
			Message:   "Budget critical",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
	}

	fired := eval.EvaluateBudget(ctx, alertCtx, map[string]interface{}{
		"percent_used": int64(95),
	})
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert from EvaluateBudget, got %d", len(fired))
	}
	if fired[0].RuleName != "budget_high" {
		t.Errorf("expected rule_name 'budget_high', got %q", fired[0].RuleName)
	}
}

func TestEvaluateRequestConvenience(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "slow_response",
			Condition: "request.latency_ms >= 10000",
			Severity:  "warning",
			Message:   "Slow",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
	}

	fired := eval.EvaluateRequest(ctx, alertCtx, map[string]interface{}{
		"latency_ms": int64(12000),
		"model":      "gpt-4",
	})
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert from EvaluateRequest, got %d", len(fired))
	}
}

func TestEvaluateHealthConvenience(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "health_degraded",
			Condition: "health.consecutive_failures >= 3",
			Severity:  "critical",
			Message:   "Health degraded",
		},
	})

	ctx := context.Background()
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
	}

	fired := eval.EvaluateHealth(ctx, alertCtx, map[string]interface{}{
		"consecutive_failures": int64(5),
	})
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert from EvaluateHealth, got %d", len(fired))
	}
}

func TestInvalidSeverityRejected(t *testing.T) {
	_, err := NewAlertEvaluator([]AlertRule{
		{
			Name:      "bad_severity",
			Condition: "budget.percent_used >= 80",
			Severity:  "debug",
			Message:   "nope",
		},
	}, nil, "test")
	if err == nil {
		t.Fatal("expected error for invalid severity, got nil")
	}
}

func TestContextIncludedInEvent(t *testing.T) {
	eval := testEvaluator(t, []AlertRule{
		{
			Name:      "budget_warning",
			Condition: "budget.percent_used >= 80",
			Severity:  "warning",
			Message:   "Budget warning",
		},
	})

	ctx := context.Background()
	data := map[string]interface{}{
		"budget": map[string]interface{}{
			"percent_used": int64(85),
			"scope":        "workspace",
		},
	}
	alertCtx := AlertContext{
		WorkspaceID: "ws-1",
		RequestID:   "req-1",
		Data:        data,
	}

	fired := eval.Evaluate(ctx, alertCtx)
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(fired))
	}
	// The event context should contain the full data map
	if fired[0].Context == nil {
		t.Fatal("expected non-nil context in event")
	}
	budgetCtx, ok := fired[0].Context["budget"].(map[string]interface{})
	if !ok {
		t.Fatal("expected budget key in event context")
	}
	if budgetCtx["scope"] != "workspace" {
		t.Errorf("expected scope=workspace in context, got %v", budgetCtx["scope"])
	}
}
