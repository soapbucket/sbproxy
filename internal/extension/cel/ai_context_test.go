package cel

import (
	"testing"
)

func TestGetAIEnv(t *testing.T) {
	env, err := GetAIEnv()
	if err != nil {
		t.Fatalf("GetAIEnv() returned error: %v", err)
	}
	if env == nil {
		t.Fatal("GetAIEnv() returned nil environment")
	}

	// Verify that AI-specific expressions compile
	expressions := []string{
		`ai.model == "gpt-4"`,
		`ai.message_count > 10`,
		`ai.has_tools == true`,
		`ai.is_streaming == false`,
		`ai.token_estimate > 1000`,
		`budget.utilization > 0.8`,
		`ai.provider == "openai"`,
	}
	for _, expr := range expressions {
		ast, iss := env.Compile(expr)
		if iss != nil && iss.Err() != nil {
			t.Errorf("failed to compile %q: %v", expr, iss.Err())
			continue
		}
		if ast == nil {
			t.Errorf("compile %q produced nil AST", expr)
		}
	}
}

func TestBuildAIActivation(t *testing.T) {
	vars := &AIContextVars{
		Model:         "gpt-4",
		Provider:      "openai",
		MessageCount:  5,
		TokenEstimate: 1500,
		HasTools:      true,
		IsStreaming:   false,
		Tags:          map[string]string{"env": "prod"},
		Budget: map[string]any{
			"utilization":      0.6,
			"remaining_tokens": int64(40000),
			"period":           "monthly",
		},
		ProviderHealth: map[string]any{
			"openai":    true,
			"anthropic": false,
		},
	}

	requestVars := map[string]any{
		"request": map[string]any{
			"headers": map[string]any{
				"X-Priority": "high",
			},
		},
	}

	activation := BuildAIActivation(vars, requestVars)

	// Verify ai map
	aiMap, ok := activation["ai"].(map[string]any)
	if !ok {
		t.Fatal("activation[ai] is not a map")
	}
	if aiMap["model"] != "gpt-4" {
		t.Errorf("ai.model = %v, want gpt-4", aiMap["model"])
	}
	if aiMap["provider"] != "openai" {
		t.Errorf("ai.provider = %v, want openai", aiMap["provider"])
	}
	if aiMap["message_count"] != int64(5) {
		t.Errorf("ai.message_count = %v, want 5", aiMap["message_count"])
	}
	if aiMap["token_estimate"] != int64(1500) {
		t.Errorf("ai.token_estimate = %v, want 1500", aiMap["token_estimate"])
	}
	if aiMap["has_tools"] != true {
		t.Errorf("ai.has_tools = %v, want true", aiMap["has_tools"])
	}
	if aiMap["is_streaming"] != false {
		t.Errorf("ai.is_streaming = %v, want false", aiMap["is_streaming"])
	}

	// Verify budget map
	budgetMap, ok := activation["budget"].(map[string]any)
	if !ok {
		t.Fatal("activation[budget] is not a map")
	}
	if budgetMap["utilization"] != 0.6 {
		t.Errorf("budget.utilization = %v, want 0.6", budgetMap["utilization"])
	}
	if budgetMap["remaining_tokens"] != int64(40000) {
		t.Errorf("budget.remaining_tokens = %v, want 40000", budgetMap["remaining_tokens"])
	}

	// Verify provider_health map
	healthMap, ok := activation["provider_health"].(map[string]any)
	if !ok {
		t.Fatal("activation[provider_health] is not a map")
	}
	if healthMap["openai"] != true {
		t.Errorf("provider_health.openai = %v, want true", healthMap["openai"])
	}

	// Verify request vars merged in
	reqMap, ok := activation["request"].(map[string]any)
	if !ok {
		t.Fatal("activation[request] is not a map")
	}
	headers, ok := reqMap["headers"].(map[string]any)
	if !ok {
		t.Fatal("activation[request][headers] is not a map")
	}
	if headers["X-Priority"] != "high" {
		t.Errorf("request.headers.X-Priority = %v, want high", headers["X-Priority"])
	}
}

func TestBuildAIActivation_Defaults(t *testing.T) {
	// Nil vars should produce valid activation with defaults
	activation := BuildAIActivation(nil, nil)

	aiMap, ok := activation["ai"].(map[string]any)
	if !ok {
		t.Fatal("activation[ai] is not a map")
	}
	if aiMap["model"] != "" {
		t.Errorf("ai.model = %v, want empty string", aiMap["model"])
	}
	if aiMap["message_count"] != int64(0) {
		t.Errorf("ai.message_count = %v, want 0", aiMap["message_count"])
	}
	if aiMap["has_tools"] != false {
		t.Errorf("ai.has_tools = %v, want false", aiMap["has_tools"])
	}

	// Verify budget defaults
	budgetMap, ok := activation["budget"].(map[string]any)
	if !ok {
		t.Fatal("activation[budget] is not a map")
	}
	if budgetMap["utilization"] != 0.0 {
		t.Errorf("budget.utilization = %v, want 0.0", budgetMap["utilization"])
	}
	if budgetMap["remaining_tokens"] != int64(0) {
		t.Errorf("budget.remaining_tokens = %v, want 0", budgetMap["remaining_tokens"])
	}

	// Verify all standard request env variables are present
	for _, key := range []string{"request", "session", "origin", "server", "vars", "features", "client", "ctx"} {
		if _, ok := activation[key]; !ok {
			t.Errorf("activation[%s] is missing", key)
		}
	}
}
