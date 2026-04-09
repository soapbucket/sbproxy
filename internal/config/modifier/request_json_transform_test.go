package modifier

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustCreatePOSTRequest(t *testing.T, urlStr string, body string) *httptest.ResponseRecorder {
	t.Helper()
	_ = urlStr
	_ = body
	return httptest.NewRecorder()
}

func TestRequestModifier_JSONTransform_Basic(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  if data.userName then\n    data.username = data.userName\n    data.userName = nil\n  end\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/users", strings.NewReader(`{"userName":"alice","age":30}`))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(`{"userName":"alice","age":30}`))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if result["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", result["username"])
	}
	if _, exists := result["userName"]; exists {
		t.Error("expected userName to be removed")
	}
	if result["age"] != float64(30) {
		t.Errorf("expected age=30, got %v", result["age"])
	}

	// Verify Content-Length updated
	if req.ContentLength != int64(len(bodyBytes)) {
		t.Errorf("Content-Length mismatch: header=%d, body=%d", req.ContentLength, len(bodyBytes))
	}
}

func TestRequestModifier_JSONTransform_ArrayBody(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  for i, item in ipairs(data) do\n    item.processed = true\n  end\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `[{"id":1},{"id":2}]`
	req := httptest.NewRequest("POST", "/api/items", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	var result []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result))
	}
	for i, item := range result {
		if item["processed"] != true {
			t.Errorf("item[%d].processed = %v, want true", i, item["processed"])
		}
	}
}

func TestRequestModifier_JSONTransform_NonJSONContentType(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.modified = true\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	originalBody := "plain text body"
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(originalBody))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) != originalBody {
		t.Errorf("body should be unchanged, got %q", string(bodyBytes))
	}
}

func TestRequestModifier_JSONTransform_EmptyBody(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.ContentLength = 0

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
}

func TestRequestModifier_JSONTransform_MaxBodySizeExceeded(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.modified = true\n  return data\nend",
			"max_body_size": 10
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"largeField":"this exceeds max body size"}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Body should be unchanged (transform was skipped)
	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) != body {
		t.Errorf("body should be unchanged when exceeding max_body_size, got %q", string(bodyBytes))
	}
}

func TestRequestModifier_JSONTransform_InvalidJSON(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.modified = true\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{invalid json}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Body should be restored unchanged
	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) != body {
		t.Errorf("body should be unchanged for invalid JSON, got %q", string(bodyBytes))
	}
}

func TestRequestModifier_JSONTransform_LuaError(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  error('intentional error')\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"key":"value"}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	err := m.Apply(req)
	if err == nil {
		t.Fatal("expected error from Lua script, got nil")
	}

	// Body should be restored
	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) != body {
		t.Errorf("body should be restored after Lua error, got %q", string(bodyBytes))
	}
}

func TestRequestModifier_JSONTransform_LuaTimeout(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  while true do end\n  return data\nend",
			"timeout": "10ms"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"key":"value"}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	err := m.Apply(req)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestRequestModifier_JSONTransform_NilReturn(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  return nil\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"key":"value"}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Body should be the original (nil return means keep original)
	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) != body {
		t.Errorf("body should be unchanged on nil return, got %q", string(bodyBytes))
	}
}

func TestRequestModifier_JSONTransform_WithRules(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.transformed = true\n  return data\nend"
		},
		"rules": [{"path": {"prefix": "/api/"}}]
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	// Matching path
	body := `{"key":"value"}`
	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	var result map[string]interface{}
	json.Unmarshal(bodyBytes, &result)
	if result["transformed"] != true {
		t.Error("transform should apply when rules match")
	}

	// Non-matching path
	var m2 RequestModifier
	json.Unmarshal([]byte(modifierJSON), &m2)

	req2 := httptest.NewRequest("POST", "/other/path", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.ContentLength = int64(len(body))

	if err := m2.Apply(req2); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes2, _ := io.ReadAll(req2.Body)
	if string(bodyBytes2) != body {
		t.Errorf("transform should NOT apply when rules don't match, got %q", string(bodyBytes2))
	}
}

func TestRequestModifier_JSONTransform_OrderingWithBodyReplace(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.fromTransform = true\n  return data\nend"
		},
		"body": {
			"replace": "{\"fromBody\":true}"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"original":true}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Body.Replace runs after JSON transform, so it should win
	bodyBytes, _ := io.ReadAll(req.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if result["fromBody"] != true {
		t.Error("body.replace should override json_transform output")
	}
	if _, exists := result["fromTransform"]; exists {
		t.Error("json_transform output should be overridden by body.replace")
	}
}

func TestRequestModifier_JSONTransform_UnmarshalValidation(t *testing.T) {
	// Empty lua_script should fail
	modifierJSON := `{
		"json_transform": {
			"lua_script": ""
		}
	}`

	var m RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &m)
	if err == nil {
		t.Fatal("expected error for empty lua_script")
	}
	if !strings.Contains(err.Error(), "lua_script is required") {
		t.Errorf("expected 'lua_script is required' error, got: %v", err)
	}
}

func TestRequestModifier_JSONTransform_MissingFunction(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function other_function(data)\n  return data\nend"
		}
	}`

	var m RequestModifier
	err := json.Unmarshal([]byte(modifierJSON), &m)
	if err == nil {
		t.Fatal("expected error for missing modify_json function")
	}
	if !strings.Contains(err.Error(), "modify_json") {
		t.Errorf("expected modify_json error, got: %v", err)
	}
}

func TestRequestModifier_JSONTransform_CustomContentTypes(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.transformed = true\n  return data\nend",
			"content_types": ["application/vnd.api+json"]
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	// application/json should NOT match
	body := `{"key":"value"}`
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) != body {
		t.Errorf("should skip for non-matching content type, got %q", string(bodyBytes))
	}

	// application/vnd.api+json SHOULD match
	var m2 RequestModifier
	json.Unmarshal([]byte(modifierJSON), &m2)

	req2 := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/vnd.api+json")
	req2.ContentLength = int64(len(body))

	if err := m2.Apply(req2); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes2, _ := io.ReadAll(req2.Body)
	var result map[string]interface{}
	json.Unmarshal(bodyBytes2, &result)
	if result["transformed"] != true {
		t.Error("should transform for matching custom content type")
	}
}

func TestRequestModifier_JSONTransform_NestedObjects(t *testing.T) {
	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  if data.user and data.user.name then\n    data.user.displayName = data.user.name\n    data.user.name = nil\n  end\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"user":{"name":"Alice","email":"alice@example.com"}}`
	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	if err := m.Apply(req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	bodyBytes, _ := io.ReadAll(req.Body)
	var result map[string]interface{}
	json.Unmarshal(bodyBytes, &result)

	user, ok := result["user"].(map[string]interface{})
	if !ok {
		t.Fatal("expected user to be a map")
	}
	if user["displayName"] != "Alice" {
		t.Errorf("expected displayName=Alice, got %v", user["displayName"])
	}
	if _, exists := user["name"]; exists {
		t.Error("expected name to be removed")
	}
	if user["email"] != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %v", user["email"])
	}
}

// Benchmarks

func BenchmarkRequestModifier_JSONTransform(b *testing.B) {
	b.ReportAllocs()

	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  if data.userName then\n    data.username = data.userName\n    data.userName = nil\n  end\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		b.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := `{"userName":"alice","age":30}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(body))
		_ = m.Apply(req)
	}
}

func BenchmarkRequestModifier_JSONTransform_LargeBody(b *testing.B) {
	b.ReportAllocs()

	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  data.processed = true\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		b.Fatalf("UnmarshalJSON failed: %v", err)
	}

	// Build a ~1KB JSON body
	var sb strings.Builder
	sb.WriteString(`{"items":[`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":` + strings.Repeat("1", 3) + `,"name":"item"}`)
	}
	sb.WriteString(`]}`)
	body := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/items", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(body))
		_ = m.Apply(req)
	}
}

func BenchmarkRequestModifier_JSONTransform_Skip_NonJSON(b *testing.B) {
	b.ReportAllocs()

	modifierJSON := `{
		"json_transform": {
			"lua_script": "function modify_json(data, ctx)\n  return data\nend"
		}
	}`

	var m RequestModifier
	if err := json.Unmarshal([]byte(modifierJSON), &m); err != nil {
		b.Fatalf("UnmarshalJSON failed: %v", err)
	}

	body := "plain text body"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/data", strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		req.ContentLength = int64(len(body))
		_ = m.Apply(req)
	}
}
