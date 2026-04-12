// Package rule implements rule-based request matching using conditions, expressions, and pattern matching.
package rule

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/tidwall/gjson"
)

// match checks if the auth data matches the auth conditions
// AuthConditions use OR logic - any matching condition passes
func (ac AuthConditions) match(authData *reqctx.AuthData) bool {
	if authData == nil {
		return false
	}

	// OR logic: if any condition matches, return true
	for _, condition := range ac {
		if condition.match(authData) {
			return true
		}
	}

	return false
}

// match checks if a single auth condition matches
// Rules within a condition use AND logic - all must match
func (ac AuthCondition) match(authData *reqctx.AuthData) bool {
	// Check auth type if specified
	if ac.Type != "" && authData.Type != ac.Type {
		return false
	}

	// AND logic: all rules must match
	for _, rule := range ac.AuthConditionRules {
		if !rule.match(authData) {
			return false
		}
	}

	return true
}

// match checks if an individual auth condition rule matches
func (acr AuthConditionRule) match(authData *reqctx.AuthData) bool {
	if authData == nil || authData.Data == nil {
		return false
	}

	// If CEL expression is provided, use it for matching
	// CEL has access to the full auth data structure
	if acr.celExpr != nil {
		// Create a temporary request with auth data in context for CEL evaluation
		// Note: CEL matchers expect http.Request, so we create a minimal request
		// with auth data available via the standard context key
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(http.Header),
		}
		// Store auth data in request context so CEL can access it
		reqData := &reqctx.RequestData{
			SessionData: &reqctx.SessionData{
				AuthData: authData,
			},
		}
		req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))
		return acr.celExpr.Match(req)
	}

	// If Lua script is provided, use it for matching
	if acr.luaScript != nil {
		// Create a temporary request with auth data in context for Lua evaluation
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(http.Header),
		}
		reqData := &reqctx.RequestData{
			SessionData: &reqctx.SessionData{
				AuthData: authData,
			},
		}
		req = req.WithContext(reqctx.SetRequestData(req.Context(), reqData))
		return acr.luaScript.Match(req)
	}

	// Otherwise, use path-based matching
	// Extract value from path
	value := extractValueFromPath(authData.Data, acr.Path)
	if value == nil {
		return false
	}

	// Match against expected values
	return matchValue(value, acr.Value, acr.Values, acr.Contains, acr.StartsWith, acr.EndsWith, acr.Regex)
}

// extractValueFromPath extracts a value from a map using gjson path syntax
// Supports powerful queries like:
//   - Simple paths: "user.email", "roles.0"
//   - Array wildcards: "roles.*" (returns all role values)
//   - Array filters: "users.#(name=="John").email"
//   - Nested queries: "users.#.email" (returns all emails)
//   - Array length: "roles.#"
//   - Modifiers: "email|@reverse"
func extractValueFromPath(data map[string]any, path string) any {
	if path == "" {
		return nil
	}

	// Convert data to JSON for gjson
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil
	}

	// Use gjson to extract the value
	result := gjson.GetBytes(jsonBytes, path)
	if !result.Exists() {
		return nil
	}

	// Return the value in the appropriate type
	return result.Value()
}

// matchValue checks if a value matches against various matching criteria
func matchValue(value any, exactValue string, values []string, contains, startsWith, endsWith, regex string) bool {
	// Convert value to string for comparison
	valueStr := fmt.Sprintf("%v", value)

	// Exact match
	if exactValue != "" {
		return valueStr == exactValue
	}

	// Match against list of values (OR logic)
	if len(values) > 0 {
		for _, v := range values {
			if valueStr == v {
				return true
			}
		}
		return false
	}

	// Contains check
	if contains != "" {
		return strings.Contains(valueStr, contains)
	}

	// Starts with check
	if startsWith != "" {
		return strings.HasPrefix(valueStr, startsWith)
	}

	// Ends with check
	if endsWith != "" {
		return strings.HasSuffix(valueStr, endsWith)
	}

	// Regex match
	if regex != "" {
		matched, err := regexp.MatchString(regex, valueStr)
		if err != nil {
			// Invalid regex pattern, return false
			return false
		}
		return matched
	}

	// No matching criteria specified
	return false
}
