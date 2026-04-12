package cel

import (
	"fmt"
	"testing"
)

func TestJSONModifier(t *testing.T) {
	expr := `{"modified_json": {"environment": json.env, "rate_limit": json.limits.rpm, "backend": json.backends.primary}}`
	mod, err := CompileJSONModifier(expr)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	input := map[string]any{
		"env": "production",
		"limits": map[string]any{
			"rpm":   10000,
			"burst": 1000,
		},
		"backends": map[string]any{
			"primary":  "https://api-prod.backend.com",
			"fallback": "https://api-prod-fallback.backend.com",
		},
	}

	result, err := mod.ModifyJSON(input)
	if err != nil {
		t.Fatalf("eval error: %v", err)
	}
	for k, v := range result {
		t.Logf("key=%s type=%T value=%v", k, v, v)
	}
	if v, ok := result["modified_json"]; ok {
		t.Logf("modified_json type: %T", v)
		if m, ok2 := v.(map[string]any); ok2 {
			t.Logf("inner map: %+v", m)
		} else {
			t.Logf("NOT map[string]any, actual: %s", fmt.Sprintf("%T", v))
		}
	}
}
