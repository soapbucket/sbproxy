package lua

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewJSONTransformer(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid script with modify_json function",
			script:  "function modify_json(data, ctx) return data end",
			wantErr: false,
		},
		{
			name: "valid multi-line script",
			script: `
				function modify_json(data, ctx)
					data.processed = true
					return data
				end
			`,
			wantErr: false,
		},
		{
			name:    "empty script",
			script:  "",
			wantErr: true,
			errMsg:  "script cannot be empty",
		},
		{
			name:    "script without modify_json function",
			script:  "function other_function(data) return data end",
			wantErr: true,
			errMsg:  "must define function modify_json",
		},
		{
			name:    "invalid syntax",
			script:  "function modify_json(data return data end",
			wantErr: true,
			errMsg:  "script_compilation",
		},
		{
			name:    "modify_json is not a function",
			script:  "modify_json = 'not a function'",
			wantErr: true,
			errMsg:  "must define function modify_json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer, err := NewJSONTransformer(tt.script)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJSONTransformer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("NewJSONTransformer() error = %v, expected to contain %q", err, tt.errMsg)
				}
				return
			}
			if !tt.wantErr && transformer == nil {
				t.Error("NewJSONTransformer() returned nil transformer without error")
			}
		})
	}
}

func TestJSONTransformer_TransformResponse(t *testing.T) {
	tests := []struct {
		name           string
		script         string
		inputBody      string
		expectedOutput map[string]interface{}
		wantErr        bool
	}{
		{
			name:           "pass through unchanged",
			script:         "function modify_json(data, ctx) return data end",
			inputBody:      `{"name":"test","value":123}`,
			expectedOutput: map[string]interface{}{"name": "test", "value": float64(123)},
			wantErr:        false,
		},
		{
			name: "add field",
			script: `
				function modify_json(data, ctx)
					data.processed = true
					return data
				end
			`,
			inputBody:      `{"name":"test"}`,
			expectedOutput: map[string]interface{}{"name": "test", "processed": true},
			wantErr:        false,
		},
		{
			name: "remove field",
			script: `
				function modify_json(data, ctx)
					data.secret = nil
					return data
				end
			`,
			inputBody:      `{"name":"test","secret":"password"}`,
			expectedOutput: map[string]interface{}{"name": "test"},
			wantErr:        false,
		},
		{
			name: "transform value",
			script: `
				function modify_json(data, ctx)
					local country_map = {GERMANY = 'DE', FRANCE = 'FR', SPAIN = 'ES'}
					if data.country and country_map[data.country] then
						data.country = country_map[data.country]
					end
					return data
				end
			`,
			inputBody:      `{"country":"GERMANY","name":"Test"}`,
			expectedOutput: map[string]interface{}{"country": "DE", "name": "Test"},
			wantErr:        false,
		},
		{
			name: "transform multiple values",
			script: `
				function modify_json(data, ctx)
					local country_map = {GERMANY = 'DE', FRANCE = 'FR'}
					if data.country and country_map[data.country] then
						data.country = country_map[data.country]
					end
					if data.status == 'ACTIVE' then
						data.status = 'active'
					end
					return data
				end
			`,
			inputBody:      `{"country":"FRANCE","status":"ACTIVE"}`,
			expectedOutput: map[string]interface{}{"country": "FR", "status": "active"},
			wantErr:        false,
		},
		{
			name: "return new object",
			script: `
				function modify_json(data, ctx)
					return {
						id = data.user_id,
						full_name = data.first_name .. ' ' .. data.last_name
					}
				end
			`,
			inputBody:      `{"user_id":123,"first_name":"John","last_name":"Doe"}`,
			expectedOutput: map[string]interface{}{"id": float64(123), "full_name": "John Doe"},
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer, err := NewJSONTransformer(tt.script)
			if err != nil {
				t.Fatalf("NewJSONTransformer() error = %v", err)
			}

			resp := &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(tt.inputBody)),
				Request:    httptest.NewRequest("GET", "/test", nil),
			}

			err = transformer.TransformResponse(resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransformResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				resultBody, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}

				var result map[string]interface{}
				if err := json.Unmarshal(resultBody, &result); err != nil {
					t.Fatalf("Failed to unmarshal result: %v", err)
				}

				if !mapsEqual(result, tt.expectedOutput) {
					t.Errorf("TransformResponse() result = %v, expected %v", result, tt.expectedOutput)
				}
			}
		})
	}
}

func TestJSONTransformer_SnakeCaseConversion(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			local function to_snake_case(str)
				-- Convert camelCase to snake_case
				local result = str:gsub('(%u)', function(c)
					return '_' .. c:lower()
				end)
				-- Remove leading underscore if present
				return result:gsub('^_', '')
			end
			
			local function transform_keys(obj)
				if type(obj) ~= 'table' then
					return obj
				end
				
				local result = {}
				for k, v in pairs(obj) do
					local new_key = to_snake_case(k)
					result[new_key] = transform_keys(v)
				end
				return result
			end
			
			return transform_keys(data)
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	inputBody := `{"firstName":"John","lastName":"Doe","countryCode":"US","homeAddress":{"streetName":"Main St","zipCode":"12345"}}`

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	if err := transformer.TransformResponse(resp); err != nil {
		t.Fatalf("TransformResponse() error = %v", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	// Check top-level keys
	if _, ok := result["first_name"]; !ok {
		t.Error("Expected 'first_name' key, not found")
	}
	if _, ok := result["last_name"]; !ok {
		t.Error("Expected 'last_name' key, not found")
	}
	if _, ok := result["country_code"]; !ok {
		t.Error("Expected 'country_code' key, not found")
	}

	// Check nested keys
	homeAddress, ok := result["home_address"].(map[string]interface{})
	if !ok {
		t.Error("Expected 'home_address' to be a map")
	} else {
		if _, ok := homeAddress["street_name"]; !ok {
			t.Error("Expected 'street_name' key in home_address, not found")
		}
		if _, ok := homeAddress["zip_code"]; !ok {
			t.Error("Expected 'zip_code' key in home_address, not found")
		}
	}
}

func TestJSONTransformer_ArrayTransformation(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			-- Transform array of items
			local result = {}
			for i, item in ipairs(data) do
				result[i] = {
					id = item.id,
					name = item.name:upper()
				}
			end
			return result
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	inputBody := `[{"id":1,"name":"apple"},{"id":2,"name":"banana"}]`

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	if err := transformer.TransformResponse(resp); err != nil {
		t.Fatalf("TransformResponse() error = %v", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)
	var result []map[string]interface{}
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 items, got %d", len(result))
	}

	if result[0]["name"] != "APPLE" {
		t.Errorf("Expected first item name to be 'APPLE', got %v", result[0]["name"])
	}

	if result[1]["name"] != "BANANA" {
		t.Errorf("Expected second item name to be 'BANANA', got %v", result[1]["name"])
	}
}

func TestJSONTransformer_EmptyBody(t *testing.T) {
	script := "function modify_json(data, ctx) return data end"

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 204,
		Status:     "204 No Content",
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	if err := transformer.TransformResponse(resp); err != nil {
		t.Errorf("TransformResponse() error = %v, expected nil for empty body", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)
	if len(resultBody) != 0 {
		t.Errorf("Expected empty body, got %s", string(resultBody))
	}
}

func TestJSONTransformer_NonJSONBody(t *testing.T) {
	script := "function modify_json(data, ctx) return data end"

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	// Test with non-JSON body (should be preserved unchanged)
	inputBody := "<html><body>Hello</body></html>"
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	// Should not error, just skip transformation
	if err := transformer.TransformResponse(resp); err != nil {
		t.Errorf("TransformResponse() error = %v, expected nil for non-JSON body", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)
	if string(resultBody) != inputBody {
		t.Errorf("Expected body to be preserved, got %s", string(resultBody))
	}
}

func TestJSONTransformer_NilReturn(t *testing.T) {
	script := "function modify_json(data, ctx) return nil end"

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	inputBody := `{"name":"test"}`
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	// When nil is returned, original data should be used
	if err := transformer.TransformResponse(resp); err != nil {
		t.Errorf("TransformResponse() error = %v", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if result["name"] != "test" {
		t.Errorf("Expected original data to be preserved, got %v", result)
	}
}

func TestJSONTransformer_Timeout(t *testing.T) {
	// Script with infinite loop (should timeout)
	script := `
		function modify_json(data, ctx)
			while true do
				-- infinite loop
			end
			return data
		end
	`

	transformer, err := NewJSONTransformerWithTimeout(script, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout() error = %v", err)
	}

	inputBody := `{"name":"test"}`
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	// Should error due to timeout
	err = transformer.TransformResponse(resp)
	if err == nil {
		t.Error("TransformResponse() expected timeout error, got nil")
	}
}

func TestJSONTransformer_ContentLengthUpdate(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			-- Add a longer field to change body size
			data.added_field = "this is a longer value that increases size"
			return data
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	inputBody := `{"x":1}`
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	if err := transformer.TransformResponse(resp); err != nil {
		t.Fatalf("TransformResponse() error = %v", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)

	// Check Content-Length header was updated
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		t.Error("Content-Length header not set")
	}

	if resp.ContentLength != int64(len(resultBody)) {
		t.Errorf("ContentLength = %d, expected %d", resp.ContentLength, len(resultBody))
	}

	// Check Content-Type is application/json
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %s, expected application/json", contentType)
	}
}

func TestJSONTransformer_ComplexMigration(t *testing.T) {
	// Comprehensive migration script: snake_case keys + value mapping
	script := `
		function modify_json(data, ctx)
			local function to_snake_case(str)
				local result = str:gsub('(%u)', function(c)
					return '_' .. c:lower()
				end)
				return result:gsub('^_', '')
			end
			
			local country_map = {
				GERMANY = 'DE',
				FRANCE = 'FR',
				SPAIN = 'ES',
				ITALY = 'IT',
				UNITED_STATES = 'US'
			}
			
			local status_map = {
				ACTIVE = 'active',
				INACTIVE = 'inactive',
				PENDING = 'pending'
			}
			
			local function transform_value(key, value)
				if key == 'country' and country_map[value] then
					return country_map[value]
				end
				if key == 'status' and status_map[value] then
					return status_map[value]
				end
				return value
			end
			
			local function transform_keys(obj)
				if type(obj) ~= 'table' then
					return obj
				end
				
				local result = {}
				for k, v in pairs(obj) do
					local new_key = to_snake_case(k)
					local new_value = transform_keys(v)
					new_value = transform_value(new_key, new_value)
					result[new_key] = new_value
				end
				return result
			end
			
			return transform_keys(data)
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	inputBody := `{
		"userId": 123,
		"firstName": "John",
		"lastName": "Doe",
		"country": "GERMANY",
		"status": "ACTIVE",
		"contactInfo": {
			"emailAddress": "john@example.com",
			"phoneNumber": "+49123456789"
		}
	}`

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(inputBody)),
		Request:    httptest.NewRequest("GET", "/v1/user", nil),
	}

	if err := transformer.TransformResponse(resp); err != nil {
		t.Fatalf("TransformResponse() error = %v", err)
	}

	resultBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	// Verify snake_case conversion
	if _, ok := result["user_id"]; !ok {
		t.Error("Expected 'user_id' key (snake_case)")
	}
	if _, ok := result["first_name"]; !ok {
		t.Error("Expected 'first_name' key (snake_case)")
	}
	if _, ok := result["last_name"]; !ok {
		t.Error("Expected 'last_name' key (snake_case)")
	}

	// Verify value transformations
	if result["country"] != "DE" {
		t.Errorf("Expected country = 'DE', got %v", result["country"])
	}
	if result["status"] != "active" {
		t.Errorf("Expected status = 'active', got %v", result["status"])
	}

	// Verify nested object transformation
	contactInfo, ok := result["contact_info"].(map[string]interface{})
	if !ok {
		t.Error("Expected 'contact_info' to be a map")
	} else {
		if _, ok := contactInfo["email_address"]; !ok {
			t.Error("Expected 'email_address' key in contact_info")
		}
		if _, ok := contactInfo["phone_number"]; !ok {
			t.Error("Expected 'phone_number' key in contact_info")
		}
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestJSONTransformError_Type(t *testing.T) {
	tests := []struct {
		name           string
		script         string
		expectedType   JSONTransformErrorType
		expectedString string
	}{
		{
			name:           "empty script",
			script:         "",
			expectedType:   ErrorTypeScriptEmpty,
			expectedString: "script_empty",
		},
		{
			name:           "whitespace only script",
			script:         "   \n\t  ",
			expectedType:   ErrorTypeScriptEmpty,
			expectedString: "script_empty",
		},
		{
			name:           "compilation error",
			script:         "function modify_json(data, ctx) return",
			expectedType:   ErrorTypeScriptCompilation,
			expectedString: "script_compilation",
		},
		{
			name:           "missing function",
			script:         "local x = 1",
			expectedType:   ErrorTypeScriptMissingFunction,
			expectedString: "script_missing_function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJSONTransformer(tt.script)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}

			var transformErr *JSONTransformError
			if !errors.As(err, &transformErr) {
				t.Fatalf("Expected JSONTransformError, got %T", err)
			}

			if transformErr.Type != tt.expectedType {
				t.Errorf("Expected error type %v, got %v", tt.expectedType, transformErr.Type)
			}

			if transformErr.Type.String() != tt.expectedString {
				t.Errorf("Expected error type string %q, got %q", tt.expectedString, transformErr.Type.String())
			}
		})
	}
}

func TestJSONTransformError_ScriptSnippet(t *testing.T) {
	longScript := "function modify_json(data, ctx) " + string(make([]byte, 200)) + " return data end"

	_, err := NewJSONTransformer(longScript)
	if err == nil {
		t.Fatal("Expected error for invalid script")
	}

	var transformErr *JSONTransformError
	if errors.As(err, &transformErr) {
		// Script snippet should be truncated to ~100 chars
		if len(transformErr.Script) > 110 {
			t.Errorf("Script snippet too long: %d chars", len(transformErr.Script))
		}
		if !containsString(transformErr.Script, "...") {
			t.Error("Long script should be truncated with '...'")
		}
	}
}

func TestJSONTransformError_IsTimeout(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			while true do end
			return data
		end
	`

	transformer, err := NewJSONTransformerWithTimeout(script, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"test":1}`)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	err = transformer.TransformResponse(resp)
	if err == nil {
		t.Fatal("Expected timeout error")
	}

	var transformErr *JSONTransformError
	if !errors.As(err, &transformErr) {
		t.Fatalf("Expected JSONTransformError, got %T", err)
	}

	// IsTimeout should return true because the cause contains "context deadline exceeded"
	if !transformErr.IsTimeout() {
		t.Errorf("Expected IsTimeout() to return true, error was: %v", err)
	}

	// The error message should mention the timeout
	if !containsString(err.Error(), "context deadline exceeded") {
		t.Errorf("Expected error to mention 'context deadline exceeded', got: %v", err)
	}
}

func TestJSONTransformError_RuntimeError(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			-- This will cause a runtime error - calling nil
			local x = nil
			return x.field
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"test":1}`)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	err = transformer.TransformResponse(resp)
	if err == nil {
		t.Fatal("Expected runtime error")
	}

	var transformErr *JSONTransformError
	if !errors.As(err, &transformErr) {
		t.Fatalf("Expected JSONTransformError, got %T", err)
	}

	if transformErr.Type != ErrorTypeScriptExecution {
		t.Errorf("Expected ErrorTypeScriptExecution, got %v", transformErr.Type)
	}

	if transformErr.IsRetryable() {
		t.Error("Runtime errors should not be retryable")
	}
}

func TestJSONTransformError_Unwrap(t *testing.T) {
	_, err := NewJSONTransformer("invalid syntax {{{")

	var transformErr *JSONTransformError
	if !errors.As(err, &transformErr) {
		t.Fatalf("Expected JSONTransformError, got %T", err)
	}

	// Unwrap should return the underlying cause
	cause := transformErr.Unwrap()
	if cause == nil {
		t.Error("Expected Unwrap() to return cause")
	}
}

func TestJSONTransformer_TransformData(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			data.transformed = true
			return data
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	input := map[string]interface{}{
		"name": "test",
	}

	result, err := transformer.TransformData(input)
	if err != nil {
		t.Fatalf("TransformData() error = %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	if resultMap["transformed"] != true {
		t.Error("Expected 'transformed' field to be true")
	}
}

func TestJSONTransformer_TransformData_WithArray(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			local result = {}
			for i, v in ipairs(data) do
				result[i] = v * 2
			end
			return result
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	input := []interface{}{1.0, 2.0, 3.0}

	result, err := transformer.TransformData(input)
	if err != nil {
		t.Fatalf("TransformData() error = %v", err)
	}

	resultSlice, ok := result.([]interface{})
	if !ok {
		t.Fatalf("Expected slice result, got %T", result)
	}

	expected := []float64{2.0, 4.0, 6.0}
	for i, v := range resultSlice {
		if v.(float64) != expected[i] {
			t.Errorf("Expected %v at index %d, got %v", expected[i], i, v)
		}
	}
}

func TestJSONTransformer_TransformData_Error(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			error("intentional error")
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	_, err = transformer.TransformData(map[string]interface{}{"test": 1})
	if err == nil {
		t.Fatal("Expected error from TransformData")
	}

	var transformErr *JSONTransformError
	if !errors.As(err, &transformErr) {
		t.Fatalf("Expected JSONTransformError, got %T", err)
	}
}

func TestJSONTransformErrorType_String(t *testing.T) {
	tests := []struct {
		errType  JSONTransformErrorType
		expected string
	}{
		{ErrorTypeScriptEmpty, "script_empty"},
		{ErrorTypeScriptCompilation, "script_compilation"},
		{ErrorTypeScriptMissingFunction, "script_missing_function"},
		{ErrorTypeScriptExecution, "script_execution"},
		{ErrorTypeScriptTimeout, "script_timeout"},
		{ErrorTypeJSONParse, "json_parse"},
		{ErrorTypeJSONMarshal, "json_marshal"},
		{ErrorTypeBodyRead, "body_read"},
		{ErrorTypeNoReturn, "no_return"},
		{JSONTransformErrorType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.errType.String() != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, tt.errType.String())
			}
		})
	}
}

func TestJSONTransformError_ErrorMessage(t *testing.T) {
	// Error with cause
	errWithCause := &JSONTransformError{
		Type:    ErrorTypeScriptExecution,
		Message: "test message",
		Cause:   errors.New("underlying cause"),
	}
	if !containsString(errWithCause.Error(), "test message") {
		t.Error("Error message should contain message")
	}
	if !containsString(errWithCause.Error(), "underlying cause") {
		t.Error("Error message should contain cause")
	}

	// Error without cause
	errWithoutCause := &JSONTransformError{
		Type:    ErrorTypeScriptEmpty,
		Message: "empty script",
	}
	if !containsString(errWithoutCause.Error(), "empty script") {
		t.Error("Error message should contain message")
	}
}

func TestJSONTransformer_PreservesOriginalOnError(t *testing.T) {
	script := `
		function modify_json(data, ctx)
			error("intentional failure")
		end
	`

	transformer, err := NewJSONTransformer(script)
	if err != nil {
		t.Fatalf("NewJSONTransformer() error = %v", err)
	}

	originalBody := `{"original":"data","preserved":true}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(originalBody)),
		Request:    httptest.NewRequest("GET", "/test", nil),
	}

	// Should return error
	err = transformer.TransformResponse(resp)
	if err == nil {
		t.Fatal("Expected error from transform")
	}

	// Original body should be preserved
	resultBody, _ := io.ReadAll(resp.Body)
	if string(resultBody) != originalBody {
		t.Errorf("Original body not preserved. Got: %s", string(resultBody))
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkJSONTransformer_SimpleTransform(b *testing.B) {
	b.ReportAllocs()
	script := `function modify_json(data, ctx) data.processed = true return data end`
	transformer, _ := NewJSONTransformer(script)

	body := `{"name":"test","value":123}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(body)),
			Request:    httptest.NewRequest("GET", "/test", nil),
		}
		transformer.TransformResponse(resp)
	}
}

func BenchmarkJSONTransformer_ComplexTransform(b *testing.B) {
	b.ReportAllocs()
	script := `
		function modify_json(data, ctx)
			local function to_snake_case(str)
				return str:gsub('(%u)', function(c) return '_' .. c:lower() end):gsub('^_', '')
			end
			local function transform_keys(obj)
				if type(obj) ~= 'table' then return obj end
				local result = {}
				for k, v in pairs(obj) do
					result[to_snake_case(k)] = transform_keys(v)
				end
				return result
			end
			return transform_keys(data)
		end
	`
	transformer, _ := NewJSONTransformer(script)

	body := `{"firstName":"John","lastName":"Doe","contactInfo":{"emailAddress":"john@example.com"}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(body)),
			Request:    httptest.NewRequest("GET", "/test", nil),
		}
		transformer.TransformResponse(resp)
	}
}

func BenchmarkJSONTransformer_TransformData(b *testing.B) {
	b.ReportAllocs()
	script := `function modify_json(data, ctx) data.processed = true return data end`
	transformer, _ := NewJSONTransformer(script)

	data := map[string]interface{}{"name": "test", "value": 123}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transformer.TransformData(data)
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		// Handle nested maps
		if am, ok := v.(map[string]interface{}); ok {
			if bm, ok := bv.(map[string]interface{}); ok {
				if !mapsEqual(am, bm) {
					return false
				}
				continue
			}
			return false
		}
		if v != bv {
			return false
		}
	}
	return true
}
