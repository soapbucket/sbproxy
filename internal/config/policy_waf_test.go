package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewWAFPolicy(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"disabled": false,
		"custom_rules": [
			{
				"id": "test1",
				"name": "Test Rule",
				"enabled": true,
				"phase": 2,
				"severity": "warning",
				"action": "log",
				"variables": [{"name": "REQUEST_URI"}],
				"operator": "rx",
				"pattern": "/admin"
			}
		],
		"action_on_match": "block"
	}`

	policy, err := NewWAFPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("NewWAFPolicy() error = %v", err)
	}

	wafPolicy, ok := policy.(*WAFPolicyConfig)
	if !ok {
		t.Fatal("NewWAFPolicy() returned wrong type")
	}

	if len(wafPolicy.CustomRules) != 1 {
		t.Errorf("NewWAFPolicy() CustomRules length = %d, want 1", len(wafPolicy.CustomRules))
	}

	if wafPolicy.CustomRules[0].ID != "test1" {
		t.Errorf("NewWAFPolicy() rule ID = %q, want test1", wafPolicy.CustomRules[0].ID)
	}
}

func TestWAFPolicyWithCEL(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"disabled": false,
		"custom_rules": [
			{
				"id": "cel1",
				"name": "CEL Rule",
				"enabled": true,
				"phase": 2,
				"action": "log",
				"cel_expr": "request.path.startsWith('/admin')"
			}
		]
	}`

	policy, err := NewWAFPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("NewWAFPolicy() error = %v", err)
	}

	wafPolicy := policy.(*WAFPolicyConfig)
	if wafPolicy.CustomRules[0].CELExpr == "" {
		t.Error("NewWAFPolicy() CELExpr is empty")
	}
}

func TestWAFPolicyWithLua(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"disabled": false,
		"custom_rules": [
			{
				"id": "lua1",
				"name": "Lua Rule",
				"enabled": true,
				"phase": 2,
				"action": "log",
				"lua_script": "return request.path == '/admin'"
			}
		]
	}`

	policy, err := NewWAFPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("NewWAFPolicy() error = %v", err)
	}

	wafPolicy := policy.(*WAFPolicyConfig)
	if wafPolicy.CustomRules[0].LuaScript == "" {
		t.Error("NewWAFPolicy() LuaScript is empty")
	}
}

func TestWAFPolicyApply(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"disabled": false,
		"custom_rules": [
			{
				"id": "test1",
				"name": "Test Rule",
				"enabled": true,
				"phase": 2,
				"severity": "warning",
				"action": "block",
				"variables": [{"name": "REQUEST_URI"}],
				"operator": "rx",
				"pattern": "/admin"
			}
		],
		"action_on_match": "block"
	}`

	policy, err := NewWAFPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("NewWAFPolicy() error = %v", err)
	}

	wafPolicy := policy.(*WAFPolicyConfig)

	// Create a test config
	cfg := &Config{
		ID: "test-config",
	}

	err = wafPolicy.Init(cfg)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	// Create a handler that should be blocked
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply WAF policy
	handler := wafPolicy.Apply(nextHandler)
	handler.ServeHTTP(w, req)

	// Should be blocked (403)
	if w.Code != http.StatusForbidden {
		t.Errorf("WAF policy blocked request with status %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestWAFPolicyDisabled(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"disabled": true,
		"custom_rules": []
	}`

	policy, err := NewWAFPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("NewWAFPolicy() error = %v", err)
	}

	wafPolicy := policy.(*WAFPolicyConfig)
	cfg := &Config{ID: "test-config"}
	err = wafPolicy.Init(cfg)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := wafPolicy.Apply(nextHandler)
	handler.ServeHTTP(w, req)

	// Should pass through (200) when disabled
	if w.Code != http.StatusOK {
		t.Errorf("WAF policy (disabled) returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestWAFPolicyTestMode(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"disabled": false,
		"test_mode": true,
		"custom_rules": [
			{
				"id": "test1",
				"enabled": true,
				"phase": 2,
				"action": "block",
				"variables": [{"name": "REQUEST_URI"}],
				"operator": "rx",
				"pattern": "/admin"
			}
		],
		"action_on_match": "block"
	}`

	policy, err := NewWAFPolicy([]byte(policyJSON))
	if err != nil {
		t.Fatalf("NewWAFPolicy() error = %v", err)
	}

	wafPolicy := policy.(*WAFPolicyConfig)
	cfg := &Config{ID: "test-config"}
	err = wafPolicy.Init(cfg)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := wafPolicy.Apply(nextHandler)
	handler.ServeHTTP(w, req)

	// In test mode, should log but not block (200)
	if w.Code != http.StatusOK {
		t.Errorf("WAF policy (test mode) returned status %d, want %d", w.Code, http.StatusOK)
	}
}

func TestWAFPolicyJSONUnmarshal(t *testing.T) {
	policyJSON := `{
		"type": "waf",
		"modsecurity_rules": [
			"SecRule ARGS \"@rx (?i)(union|select)\" \"id:1001,phase:2,deny,msg:'SQL injection'\""
		],
		"owasp_crs": {
			"enabled": true,
			"paranoia_level": 1,
			"categories": ["sql-injection", "xss"]
		},
		"rule_sets": ["owasp-top10"]
	}`

	var policy WAFPolicy
	err := json.Unmarshal([]byte(policyJSON), &policy)
	if err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(policy.ModSecurityRules) != 1 {
		t.Errorf("ModSecurityRules length = %d, want 1", len(policy.ModSecurityRules))
	}

	if policy.OWASPCRS == nil || !policy.OWASPCRS.Enabled {
		t.Error("OWASPCRS not enabled")
	}

	if len(policy.RuleSets) != 1 {
		t.Errorf("RuleSets length = %d, want 1", len(policy.RuleSets))
	}
}

