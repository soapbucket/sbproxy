// Package rule implements rule-based request matching using conditions, expressions, and pattern matching.
package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
)

// EmptyResponseRule is a variable for empty response rule.
var EmptyResponseRule = ResponseRule{}

// UnmarshalJSON implements custom JSON unmarshaling for ResponseRule
func (r *ResponseRule) UnmarshalJSON(data []byte) error {
	type Alias ResponseRule
	alias := (*Alias)(r)
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	// Initialize CEL response matcher if expression is provided
	if r.CELExpr != "" {
		celexpr, err := cel.NewResponseMatcher(r.CELExpr)
		if err != nil {
			return err
		}
		r.celexpr = celexpr
	}

	// Initialize Lua response matcher if script is provided
	if r.LuaScript != "" {
		luascript, err := lua.NewResponseMatcher(r.LuaScript)
		if err != nil {
			return err
		}
		r.luascript = luascript
	}

	return nil
}

// StatusConditions groups status code matching criteria
type StatusConditions struct {
	Code  int   `json:"code,omitempty"`  // Exact status code to match
	Codes []int `json:"codes,omitempty"` // Any one of these status codes must match
	Min   int   `json:"min,omitempty"`   // Minimum status code (inclusive)
	Max   int   `json:"max,omitempty"`   // Maximum status code (inclusive)
}

// GraphQLResponseConditions groups GraphQL response matching criteria
type GraphQLResponseConditions struct {
	// Error matching
	HasErrors      bool     `json:"has_errors,omitempty"`       // Match if response has errors
	ErrorMessages  []string `json:"error_messages,omitempty"`   // Match if any error message contains these substrings
	ErrorCodes     []string `json:"error_codes,omitempty"`      // Match if any error has one of these codes
	ErrorPathRegex string   `json:"error_path_regex,omitempty"` // Regex pattern to match error paths

	// Data field matching
	DataFields      []string `json:"data_fields,omitempty"`       // Match if response data contains any of these field names
	DataFieldsAll   []string `json:"data_fields_all,omitempty"`   // Match if response data contains all of these field names
	DataFieldsRegex string   `json:"data_fields_regex,omitempty"` // Regex pattern to match data field names

	// Response string matching
	ResponseContains string `json:"response_contains,omitempty"` // Response body must contain this substring
}

// JSONResponseConditions groups JSON response matching criteria
type JSONResponseConditions struct {
	// Field path matching (JSONPath-like notation)
	Fields      []string `json:"fields,omitempty"`       // Match if JSON contains any of these field paths (e.g., "user.id", "data.items")
	FieldsAll   []string `json:"fields_all,omitempty"`   // Match if JSON contains all of these field paths
	FieldsRegex string   `json:"fields_regex,omitempty"` // Regex pattern to match field paths

	// Value matching
	FieldValue      map[string]string   `json:"field_value,omitempty"`       // Match exact field values (e.g., {"user.role": "admin"})
	FieldValueIn    map[string][]string `json:"field_value_in,omitempty"`    // Match if field value is in list
	FieldValueRegex map[string]string   `json:"field_value_regex,omitempty"` // Match field values with regex

	// Response string matching
	ResponseContains string `json:"response_contains,omitempty"` // Response body must contain this substring
}

// ResponseRule represents a response rule.
type ResponseRule struct {
	Status *StatusConditions `json:"status,omitempty"`

	ContentTypes []string `json:"content_types,omitempty"`

	Headers *HeaderConditions `json:"headers,omitempty"`

	BodyContains string `json:"body_contains,omitempty"`

	// GraphQL response matching
	GraphQL *GraphQLResponseConditions `json:"graphql,omitempty"`

	// JSON response matching
	JSON *JSONResponseConditions `json:"json,omitempty"`

	CELExpr   string `json:"cel_expr,omitempty"`
	LuaScript string `json:"lua_script,omitempty"`

	celexpr   cel.ResponseMatcher `json:"-"`
	luascript lua.ResponseMatcher `json:"-"`
}

// IsEmpty reports whether the ResponseRule is empty.
func (r ResponseRule) IsEmpty() bool {
	if r.Status != nil && (r.Status.Code != 0 || len(r.Status.Codes) > 0 || r.Status.Min > 0 || r.Status.Max > 0) {
		return false
	}
	if len(r.ContentTypes) > 0 {
		return false
	}
	if r.Headers != nil && (len(r.Headers.Exact) > 0 || len(r.Headers.Exists) > 0 || len(r.Headers.NotExist) > 0) {
		return false
	}
	if r.BodyContains != "" {
		return false
	}
	if r.GraphQL != nil {
		return false
	}
	if r.JSON != nil {
		return false
	}
	if r.CELExpr != "" {
		return false
	}
	if r.LuaScript != "" {
		return false
	}
	return true
}

// Match performs the match operation on the ResponseRule.
func (r ResponseRule) Match(resp *http.Response) bool {
	if r.IsEmpty() {
		return true
	}

	// Match status code
	if r.Status != nil {
		statusMatched := false

		// Check exact code match
		if r.Status.Code != 0 {
			if r.Status.Code == resp.StatusCode {
				statusMatched = true
			}
		}

		// Check codes array match
		if !statusMatched && len(r.Status.Codes) > 0 {
			for _, code := range r.Status.Codes {
				if code == resp.StatusCode {
					statusMatched = true
					break
				}
			}
		}

		// Check min/max range match
		if !statusMatched && (r.Status.Min > 0 || r.Status.Max > 0) {
			// If both min and max are set, check range
			if r.Status.Min > 0 && r.Status.Max > 0 {
				if resp.StatusCode >= r.Status.Min && resp.StatusCode <= r.Status.Max {
					statusMatched = true
				}
			} else if r.Status.Min > 0 {
				// Only min is set
				if resp.StatusCode >= r.Status.Min {
					statusMatched = true
				}
			} else if r.Status.Max > 0 {
				// Only max is set
				if resp.StatusCode <= r.Status.Max {
					statusMatched = true
				}
			}
		}

		// If status conditions are specified but none matched, return false
		if (r.Status.Code != 0 || len(r.Status.Codes) > 0 || r.Status.Min > 0 || r.Status.Max > 0) && !statusMatched {
			return false
		}
	}

	// Match headers
	if r.Headers != nil {
		// Match exact values
		if len(r.Headers.Exact) > 0 {
			for key, value := range r.Headers.Exact {
				if resp.Header.Get(key) != value {
					return false
				}
			}
		}
		// Match exists
		if len(r.Headers.Exists) > 0 {
			for _, key := range r.Headers.Exists {
				if resp.Header.Get(key) == "" {
					return false
				}
			}
		}
		// Match not exist
		if len(r.Headers.NotExist) > 0 {
			for _, key := range r.Headers.NotExist {
				if resp.Header.Get(key) != "" {
					return false
				}
			}
		}
	}

	// Match content types
	if len(r.ContentTypes) > 0 {
		contentType := resp.Header.Get("Content-Type")
		if contentType != "" {
			// Extract base content type (remove charset, etc.)
			baseContentType := strings.ToLower(strings.Split(contentType, ";")[0])
			baseContentType = strings.TrimSpace(baseContentType)
			contentTypeMatched := false
			for _, expectedType := range r.ContentTypes {
				expectedType = strings.ToLower(strings.TrimSpace(expectedType))
				if baseContentType == expectedType || strings.Contains(baseContentType, expectedType) {
					contentTypeMatched = true
					break
				}
			}
			if !contentTypeMatched {
				return false
			}
		} else {
			// Content-Type header is missing, so it can't match any expected types
			return false
		}
	}

	// Match body contains
	if r.BodyContains != "" {
		if resp.Body != nil {
			// Read body
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				// If we can't read the body, we can't match
				return false
			}
			// Restore the body
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Check if body contains the substring
			if !strings.Contains(string(bodyBytes), r.BodyContains) {
				return false
			}
		} else {
			// Body is nil, so it can't contain anything
			return false
		}
	}

	// Match GraphQL response
	if r.GraphQL != nil {
		if !r.GraphQL.match(resp) {
			return false
		}
	}

	// Match JSON response
	if r.JSON != nil {
		if !r.JSON.match(resp) {
			return false
		}
	}

	// Match CEL expression
	if r.celexpr != nil {
		if !r.celexpr.Match(resp) {
			return false
		}
	}

	// Match Lua script
	if r.luascript != nil {
		if !r.luascript.Match(resp) {
			return false
		}
	}

	return true
}

// ResponseRules is a slice type for response rules.
type ResponseRules []ResponseRule

// Match performs the match operation on the ResponseRules.
func (r ResponseRules) Match(resp *http.Response) bool {
	if len(r) == 0 {
		return true
	}

	for _, rule := range r {
		if rule.IsEmpty() {
			return true
		}
		if rule.Match(resp) {
			return true
		}
	}
	return false
}

// match checks if GraphQL response matches the rule criteria
func (g *GraphQLResponseConditions) match(resp *http.Response) bool {
	// Check Content-Type
	contentType := resp.Header.Get("Content-Type")
	isGraphQL := strings.Contains(strings.ToLower(contentType), "application/json") ||
		strings.Contains(strings.ToLower(contentType), "application/graphql")

	if !isGraphQL {
		return false
	}

	// Read body
	if resp.Body == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// Restore the body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse GraphQL response
	var gqlResp struct {
		Data   interface{}            `json:"data,omitempty"`
		Errors []GraphQLResponseError `json:"errors,omitempty"`
	}
	if err := json.Unmarshal(bodyBytes, &gqlResp); err != nil {
		// Not a valid GraphQL response
		return false
	}

	// Match response contains
	if g.ResponseContains != "" {
		if !strings.Contains(string(bodyBytes), g.ResponseContains) {
			return false
		}
	}

	// Match has errors
	if g.HasErrors {
		if len(gqlResp.Errors) == 0 {
			return false
		}
	}

	// Match error messages
	if len(g.ErrorMessages) > 0 {
		if len(gqlResp.Errors) == 0 {
			return false
		}
		matched := false
		for _, err := range gqlResp.Errors {
			for _, expectedMsg := range g.ErrorMessages {
				if strings.Contains(err.Message, expectedMsg) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match error codes
	if len(g.ErrorCodes) > 0 {
		if len(gqlResp.Errors) == 0 {
			return false
		}
		matched := false
		for _, err := range gqlResp.Errors {
			for _, expectedCode := range g.ErrorCodes {
				if err.Extensions != nil {
					if code, ok := err.Extensions["code"].(string); ok && code == expectedCode {
						matched = true
						break
					}
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match error path regex
	if g.ErrorPathRegex != "" {
		if len(gqlResp.Errors) == 0 {
			return false
		}
		matched := false
		for _, err := range gqlResp.Errors {
			if err.Path != nil {
				pathStr := fmt.Sprintf("%v", err.Path)
				if m, _ := matchRegex(g.ErrorPathRegex, pathStr); m {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	// Match data fields
	if len(g.DataFields) > 0 || len(g.DataFieldsAll) > 0 || g.DataFieldsRegex != "" {
		if gqlResp.Data == nil {
			return false
		}

		// Extract field names from data
		fields := extractDataFields(gqlResp.Data)

		// Match fields (any)
		if len(g.DataFields) > 0 {
			matched := false
			for _, expectedField := range g.DataFields {
				for _, field := range fields {
					if strings.EqualFold(field, expectedField) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				return false
			}
		}

		// Match fields (all)
		if len(g.DataFieldsAll) > 0 {
			fieldMap := make(map[string]bool)
			for _, field := range fields {
				fieldMap[strings.ToLower(field)] = true
			}
			for _, expectedField := range g.DataFieldsAll {
				if !fieldMap[strings.ToLower(expectedField)] {
					return false
				}
			}
		}

		// Match fields regex
		if g.DataFieldsRegex != "" {
			matched := false
			for _, field := range fields {
				if m, err := matchRegex(g.DataFieldsRegex, field); err == nil && m {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	return true
}

// match checks if JSON response matches the rule criteria
func (j *JSONResponseConditions) match(resp *http.Response) bool {
	// Check Content-Type
	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(strings.ToLower(contentType), "application/json") ||
		strings.Contains(strings.ToLower(contentType), "application/graphql")

	if !isJSON {
		return false
	}

	// Read body
	if resp.Body == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// Restore the body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Match response contains
	if j.ResponseContains != "" {
		if !strings.Contains(string(bodyBytes), j.ResponseContains) {
			return false
		}
	}

	// Parse JSON
	var jsonData interface{}
	if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
		// Not valid JSON
		return false
	}

	// Extract all field paths from JSON using dot notation
	fields := extractJSONFieldsFromResponse(jsonData, "")

	// Match fields (any)
	if len(j.Fields) > 0 {
		matched := false
		for _, expectedField := range j.Fields {
			for _, field := range fields {
				if strings.EqualFold(field, expectedField) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match fields (all)
	if len(j.FieldsAll) > 0 {
		fieldMap := make(map[string]bool)
		for _, field := range fields {
			fieldMap[strings.ToLower(field)] = true
		}
		for _, expectedField := range j.FieldsAll {
			if !fieldMap[strings.ToLower(expectedField)] {
				return false
			}
		}
	}

	// Match fields regex
	if j.FieldsRegex != "" {
		matched := false
		for _, field := range fields {
			if m, err := matchRegexResponse(j.FieldsRegex, field); err == nil && m {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Match field values using dot notation
	if len(j.FieldValue) > 0 {
		for path, expectedValue := range j.FieldValue {
			actualValue := getJSONValueFromResponse(jsonData, path)
			if actualValue == nil || fmt.Sprintf("%v", actualValue) != expectedValue {
				return false
			}
		}
	}

	// Match field value in list
	if len(j.FieldValueIn) > 0 {
		for path, expectedValues := range j.FieldValueIn {
			actualValue := getJSONValueFromResponse(jsonData, path)
			if actualValue == nil {
				return false
			}
			actualValueStr := fmt.Sprintf("%v", actualValue)
			matched := false
			for _, expectedValue := range expectedValues {
				if actualValueStr == expectedValue {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Match field value regex
	if len(j.FieldValueRegex) > 0 {
		for path, pattern := range j.FieldValueRegex {
			actualValue := getJSONValueFromResponse(jsonData, path)
			if actualValue == nil {
				return false
			}
			actualValueStr := fmt.Sprintf("%v", actualValue)
			if matched, err := matchRegexResponse(pattern, actualValueStr); err != nil || !matched {
				return false
			}
		}
	}

	return true
}

// extractJSONFieldsFromResponse extracts all field paths from JSON data using dot notation
func extractJSONFieldsFromResponse(data interface{}, prefix string) []string {
	fields := make([]string, 0)
	extractJSONFieldsRecursiveFromResponse(data, prefix, &fields, make(map[string]bool))
	return fields
}

// extractJSONFieldsRecursiveFromResponse recursively extracts field paths using dot notation
func extractJSONFieldsRecursiveFromResponse(data interface{}, prefix string, fields *[]string, seen map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fieldPath := key
			if prefix != "" {
				fieldPath = prefix + "." + key
			}
			fieldPathLower := strings.ToLower(fieldPath)
			if !seen[fieldPathLower] {
				*fields = append(*fields, fieldPath)
				seen[fieldPathLower] = true
			}
			extractJSONFieldsRecursiveFromResponse(value, fieldPath, fields, seen)
		}
	case []interface{}:
		for i, item := range v {
			fieldPath := fmt.Sprintf("[%d]", i)
			if prefix != "" {
				fieldPath = prefix + fieldPath
			}
			extractJSONFieldsRecursiveFromResponse(item, fieldPath, fields, seen)
		}
	}
}

// getJSONValueFromResponse gets a value from JSON using dot notation path
func getJSONValueFromResponse(data interface{}, path string) interface{} {
	if path == "" {
		return data
	}

	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil
			}
		case []interface{}:
			// Array access not fully supported in this simplified version
			return nil
		default:
			return nil
		}
	}

	return current
}

// matchRegexResponse matches a string against a regex pattern (for responses)
func matchRegexResponse(pattern, str string) (bool, error) {
	matched, err := regexp.MatchString(pattern, str)
	return matched, err
}

// GraphQLResponseError represents a GraphQL error
type GraphQLResponseError struct {
	Message    string                 `json:"message"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// extractDataFields extracts field names from GraphQL response data
func extractDataFields(data interface{}) []string {
	fields := make([]string, 0)
	extractDataFieldsRecursive(data, &fields, make(map[string]bool))
	return fields
}

// extractDataFieldsRecursive recursively extracts field names from data
func extractDataFieldsRecursive(data interface{}, fields *[]string, seen map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			keyLower := strings.ToLower(key)
			if !seen[keyLower] {
				*fields = append(*fields, key)
				seen[keyLower] = true
			}
			extractDataFieldsRecursive(value, fields, seen)
		}
	case []interface{}:
		for _, item := range v {
			extractDataFieldsRecursive(item, fields, seen)
		}
	}
}
