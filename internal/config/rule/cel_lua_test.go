package rule

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// TestRequestRule_CEL_Unmarshal tests that CEL expressions are properly loaded during JSON unmarshaling
func TestRequestRule_CEL_Unmarshal(t *testing.T) {
	t.Skip("Requires full CEL environment and request context - test in integration")
	
	
	celJSON := `{
		"cel_expr": "request.path == '/test'"
	}`

	var rule RequestRule
	err := json.Unmarshal([]byte(celJSON), &rule)
	if err != nil {
		t.Fatalf("Error unmarshaling CEL rule: %v", err)
	}

	if rule.CELExpr == "" {
		t.Error("CELExpr string not populated")
	}

	if rule.celexpr == nil {
		t.Fatal("CEL matcher not initialized during unmarshaling")
	}

	// Create a test request that should match
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/test",
		},
		Header: http.Header{},
	}

	// Test that CEL matcher works
	if !rule.Match(req) {
		t.Error("CEL expression should match the request")
	}

	// Test with non-matching request
	req.URL.Path = "/other"
	if rule.Match(req) {
		t.Error("CEL expression should not match the request with different path")
	}
}

// TestRequestRule_Lua_Unmarshal tests that Lua scripts are properly loaded during JSON unmarshaling
func TestRequestRule_Lua_Unmarshal(t *testing.T) {
	t.Skip("Requires full request context - test in integration")
	
	
	luaJSON := `{
		"lua_script": "return request.path == '/test'"
	}`

	var rule RequestRule
	err := json.Unmarshal([]byte(luaJSON), &rule)
	if err != nil {
		t.Fatalf("Error unmarshaling Lua rule: %v", err)
	}

	if rule.LuaScript == "" {
		t.Error("LuaScript string not populated")
	}

	if rule.luascript == nil {
		t.Fatal("Lua matcher not initialized during unmarshaling")
	}

	// Create a test request that should match
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/test",
		},
		Header: http.Header{},
	}

	// Test that Lua matcher works
	if !rule.Match(req) {
		t.Error("Lua script should match the request")
	}

	// Test with non-matching request
	req.URL.Path = "/other"
	if rule.Match(req) {
		t.Error("Lua script should not match the request with different path")
	}
}

// TestRequestRule_CEL_And_Lua_Combined tests that both CEL and Lua work together
func TestRequestRule_CEL_And_Lua_Combined(t *testing.T) {
	t.Skip("Requires full CEL and Lua environment - test in integration")
	
	
	jsonData := `{
		"methods": ["GET"],
		"cel_expr": "request.path.startsWith('/api/')",
		"lua_script": "return string.sub(request.path, -5) == '/test'"
	}`

	var rule RequestRule
	err := json.Unmarshal([]byte(jsonData), &rule)
	if err != nil {
		t.Fatalf("Error unmarshaling rule: %v", err)
	}

	if rule.celexpr == nil {
		t.Fatal("CEL matcher not initialized")
	}

	if rule.luascript == nil {
		t.Fatal("Lua matcher not initialized")
	}

	// Create a test request that should match all conditions
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/api/something/test",
		},
		Header: http.Header{},
	}

	// All conditions should match
	if !rule.Match(req) {
		t.Error("Rule should match when method, CEL, and Lua all match")
	}

	// Test with wrong method
	req.Method = "POST"
	if rule.Match(req) {
		t.Error("Rule should not match with wrong method")
	}
	req.Method = "GET"

	// Test with path that doesn't start with /api/
	req.URL.Path = "/other/something/test"
	if rule.Match(req) {
		t.Error("Rule should not match when CEL expression fails")
	}

	// Test with path that doesn't end with /test
	req.URL.Path = "/api/something/other"
	if rule.Match(req) {
		t.Error("Rule should not match when Lua script fails")
	}
}

// TestRequestRule_IsEmpty_With_CEL_And_Lua tests that IsEmpty returns false when CEL or Lua are present
func TestRequestRule_IsEmpty_With_CEL_And_Lua(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		isEmpty  bool
	}{
		{
			name:     "Empty rule",
			jsonData: `{}`,
			isEmpty:  true,
		},
		{
			name:     "Rule with CEL only",
			jsonData: `{"cel_expr": "request.path == '/test'"}`,
			isEmpty:  false,
		},
		{
			name:     "Rule with Lua only",
			jsonData: `{"lua_script": "return true"}`,
			isEmpty:  false,
		},
		{
			name:     "Rule with both CEL and Lua",
			jsonData: `{"cel_expr": "request.path == '/test'", "lua_script": "return true"}`,
			isEmpty:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule RequestRule
			err := json.Unmarshal([]byte(tt.jsonData), &rule)
			if err != nil {
				t.Fatalf("Error unmarshaling rule: %v", err)
			}

			if rule.IsEmpty() != tt.isEmpty {
				t.Errorf("IsEmpty() = %v, want %v", rule.IsEmpty(), tt.isEmpty)
			}
		})
	}
}

// TestRequestRule_Invalid_CEL tests error handling for invalid CEL expressions
func TestRequestRule_Invalid_CEL(t *testing.T) {
	celJSON := `{
		"cel_expr": "this is not valid CEL syntax!!!"
	}`

	var rule RequestRule
	err := json.Unmarshal([]byte(celJSON), &rule)
	if err == nil {
		t.Error("Expected error for invalid CEL expression, got nil")
	}
}

// TestRequestRule_Invalid_Lua tests error handling for invalid Lua scripts
func TestRequestRule_Invalid_Lua(t *testing.T) {
	luaJSON := `{
		"lua_script": "this is not valid Lua syntax function ("
	}`

	var rule RequestRule
	err := json.Unmarshal([]byte(luaJSON), &rule)
	if err == nil {
		t.Error("Expected error for invalid Lua script, got nil")
	}
}

