package callback

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// objToTemplateContext tests
// =============================================================================

func TestObjToPongo2Context_MapInput(t *testing.T) {
	obj := map[string]any{
		"name": "test",
		"id":   42,
	}

	ctx := objToTemplateContext(obj)

	if ctx["name"] != "test" {
		t.Errorf("expected name=test, got %v", ctx["name"])
	}
	if ctx["id"] != 42 {
		t.Errorf("expected id=42, got %v", ctx["id"])
	}
}

func TestObjToPongo2Context_NilInput(t *testing.T) {
	ctx := objToTemplateContext(nil)
	if len(ctx) != 0 {
		t.Errorf("expected empty context for nil, got %d entries", len(ctx))
	}
}

func TestObjToPongo2Context_NonMapInput(t *testing.T) {
	ctx := objToTemplateContext("hello")
	if ctx["data"] != "hello" {
		t.Errorf("expected data=hello, got %v", ctx["data"])
	}
}

func TestObjToPongo2Context_NestedMap(t *testing.T) {
	obj := map[string]any{
		"steps": map[string]any{
			"auth": map[string]any{
				"response": map[string]any{
					"token": "abc123",
				},
			},
		},
	}

	ctx := objToTemplateContext(obj)
	steps, ok := ctx["steps"].(map[string]any)
	if !ok {
		t.Fatal("expected steps to be map[string]any")
	}
	auth, ok := steps["auth"].(map[string]any)
	if !ok {
		t.Fatal("expected auth to be map[string]any")
	}
	resp, ok := auth["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response to be map[string]any")
	}
	if resp["token"] != "abc123" {
		t.Errorf("expected token=abc123, got %v", resp["token"])
	}
}

// =============================================================================
// renderBodyTemplate tests
// =============================================================================

func TestRenderBodyTemplate_Simple(t *testing.T) {
	result, err := renderBodyTemplate(`{"name": "{{ name }}"}`, map[string]any{"name": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != `{"name": "test"}` {
		t.Errorf("got %q, want %q", result, `{"name": "test"}`)
	}
}

func TestRenderBodyTemplate_NoTemplateSymbols(t *testing.T) {
	// Fast path: no template syntax should return string as-is
	result, err := renderBodyTemplate("plain text body", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "plain text body" {
		t.Errorf("got %q, want %q", result, "plain text body")
	}
}

func TestRenderBodyTemplate_NestedAccess(t *testing.T) {
	ctx := map[string]any{
		"steps": map[string]any{
			"auth": map[string]any{
				"response": map[string]any{
					"token": "bearer-xyz",
				},
			},
		},
	}

	result, err := renderBodyTemplate(`{"token": "{{ steps.auth.response.token }}"}`, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != `{"token": "bearer-xyz"}` {
		t.Errorf("got %q", result)
	}
}

// =============================================================================
// buildRequestBody tests
// =============================================================================

func TestBuildRequestBody_DefaultBehavior(t *testing.T) {
	// No Body, FormFields, or ContentType — should JSON-marshal obj
	c := &Callback{Method: "POST"}
	obj := map[string]any{"key": "value"}

	reader, ct, err := c.buildRequestBody(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("expected content-type application/json, got %q", ct)
	}

	body, _ := io.ReadAll(reader)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse body as JSON: %v", err)
	}
	if parsed["key"] != "value" {
		t.Errorf("expected key=value, got %v", parsed["key"])
	}
}

func TestBuildRequestBody_BodyTemplate(t *testing.T) {
	c := &Callback{
		Method: "POST",
		Body:   `{"user": "{{ name }}", "count": {{ count }}}`,
	}
	obj := map[string]any{"name": "alice", "count": 5}

	reader, ct, err := c.buildRequestBody(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("expected content-type application/json, got %q", ct)
	}

	body, _ := io.ReadAll(reader)
	if string(body) != `{"user": "alice", "count": 5}` {
		t.Errorf("got %q", string(body))
	}
}

func TestBuildRequestBody_ContentTypeOverride(t *testing.T) {
	c := &Callback{
		Method:      "POST",
		Body:        "<request><name>{{ name }}</name></request>",
		ContentType: "text/xml",
	}
	obj := map[string]any{"name": "test"}

	reader, ct, err := c.buildRequestBody(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "text/xml" {
		t.Errorf("expected content-type text/xml, got %q", ct)
	}

	body, _ := io.ReadAll(reader)
	if string(body) != "<request><name>test</name></request>" {
		t.Errorf("got %q", string(body))
	}
}

func TestBuildRequestBody_ContentTypeOverride_DefaultMarshal(t *testing.T) {
	// ContentType set but no Body template — should still JSON-marshal but use custom CT
	c := &Callback{
		Method:      "POST",
		ContentType: "application/vnd.api+json",
	}
	obj := map[string]any{"key": "value"}

	_, ct, err := c.buildRequestBody(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/vnd.api+json" {
		t.Errorf("expected content-type application/vnd.api+json, got %q", ct)
	}
}

func TestBuildRequestBody_FormFieldsURLEncoded(t *testing.T) {
	c := &Callback{
		Method: "POST",
		FormFields: map[string]string{
			"username": "{{ user }}",
			"email":    "{{ email }}",
		},
	}
	obj := map[string]any{"user": "alice", "email": "alice@example.com"}

	reader, ct, err := c.buildRequestBody(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("expected content-type application/x-www-form-urlencoded, got %q", ct)
	}

	body, _ := io.ReadAll(reader)
	bodyStr := string(body)
	// url.Values.Encode() sorts keys alphabetically
	if !strings.Contains(bodyStr, "email=alice%40example.com") {
		t.Errorf("expected email field in body, got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "username=alice") {
		t.Errorf("expected username field in body, got %q", bodyStr)
	}
}

func TestBuildRequestBody_FormFieldsMultipart(t *testing.T) {
	c := &Callback{
		Method:      "POST",
		ContentType: "multipart/form-data",
		FormFields: map[string]string{
			"name":  "{{ user_name }}",
			"value": "hello world",
		},
	}
	obj := map[string]any{"user_name": "bob"}

	reader, ct, err := c.buildRequestBody(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Content-Type should include boundary
	if !strings.HasPrefix(ct, "multipart/form-data; boundary=") {
		t.Errorf("expected multipart content-type with boundary, got %q", ct)
	}

	// Parse the multipart body to verify fields
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("failed to parse media type: %v", err)
	}

	body, _ := io.ReadAll(reader)
	mr := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])

	fields := make(map[string]string)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read part: %v", err)
		}
		value, _ := io.ReadAll(part)
		fields[part.FormName()] = string(value)
	}

	if fields["name"] != "bob" {
		t.Errorf("expected name=bob, got %q", fields["name"])
	}
	if fields["value"] != "hello world" {
		t.Errorf("expected value='hello world', got %q", fields["value"])
	}
}

func TestBuildRequestBody_GETIgnoresBody(t *testing.T) {
	c := &Callback{
		Method: "GET",
		Body:   `{"should": "be ignored"}`,
	}

	reader, ct, err := c.buildRequestBody(map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "" {
		t.Errorf("expected empty content-type for GET, got %q", ct)
	}
	if reader != http.NoBody {
		t.Error("expected http.NoBody for GET request")
	}
}

func TestBuildRequestBody_DELETEIgnoresBody(t *testing.T) {
	c := &Callback{
		Method: "DELETE",
		Body:   `{"should": "be ignored"}`,
	}

	reader, ct, err := c.buildRequestBody(map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "" {
		t.Errorf("expected empty content-type for DELETE, got %q", ct)
	}
	if reader != http.NoBody {
		t.Error("expected http.NoBody for DELETE request")
	}
}

func TestBuildRequestBody_NilObj_WithBodyTemplate(t *testing.T) {
	c := &Callback{
		Method: "POST",
		Body:   `{"static": "value"}`,
	}

	reader, ct, err := c.buildRequestBody(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}

	body, _ := io.ReadAll(reader)
	if string(body) != `{"static": "value"}` {
		t.Errorf("got %q", string(body))
	}
}

func TestBuildRequestBody_NilObj_NoBody(t *testing.T) {
	c := &Callback{Method: "POST"}

	reader, ct, err := c.buildRequestBody(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "" {
		t.Errorf("expected empty content-type for nil obj, got %q", ct)
	}
	if reader != http.NoBody {
		t.Error("expected http.NoBody for nil obj with no body template")
	}
}

func TestBuildRequestBody_DefaultMethodIsPOST(t *testing.T) {
	// Empty method should default to POST and allow body
	c := &Callback{
		Body: `{"test": true}`,
	}

	reader, ct, err := c.buildRequestBody(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}

	body, _ := io.ReadAll(reader)
	if string(body) != `{"test": true}` {
		t.Errorf("got %q", string(body))
	}
}

// =============================================================================
// UnmarshalJSON validation tests
// =============================================================================

func TestUnmarshalJSON_BodyAndFormFieldsMutuallyExclusive(t *testing.T) {
	data := []byte(`{
		"url": "http://example.com",
		"body": "{\"key\": \"value\"}",
		"form_fields": {"field1": "value1"}
	}`)

	var c Callback
	err := json.Unmarshal(data, &c)
	if err == nil {
		t.Fatal("expected error for body + form_fields, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' error, got: %v", err)
	}
}

func TestUnmarshalJSON_FormFieldsInvalidContentType(t *testing.T) {
	data := []byte(`{
		"url": "http://example.com",
		"content_type": "text/xml",
		"form_fields": {"field1": "value1"}
	}`)

	var c Callback
	err := json.Unmarshal(data, &c)
	if err == nil {
		t.Fatal("expected error for form_fields with text/xml, got nil")
	}
	if !strings.Contains(err.Error(), "form_fields requires content_type") {
		t.Errorf("expected content_type validation error, got: %v", err)
	}
}

func TestUnmarshalJSON_FormFieldsValidContentTypes(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
	}{
		{"url-encoded", "application/x-www-form-urlencoded"},
		{"multipart", "multipart/form-data"},
		{"empty (defaults)", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := ""
			if tt.contentType != "" {
				ct = `"content_type": "` + tt.contentType + `",`
			}
			data := []byte(`{
				"url": "http://example.com",
				` + ct + `
				"form_fields": {"field1": "value1"}
			}`)

			var c Callback
			if err := json.Unmarshal(data, &c); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// Integration tests with httptest
// =============================================================================

func TestCallback_BodyTemplate_Integration(t *testing.T) {
	var receivedBody string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		receivedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	data := []byte(`{
		"url": "` + server.URL + `",
		"method": "POST",
		"body": "{\"user_id\": \"{{ user_id }}\", \"action\": \"{{ action }}\"}",
		"content_type": "application/json"
	}`)

	var c Callback
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj := map[string]any{
		"user_id": "user-123",
		"action":  "login",
	}

	result, err := c.Do(t.Context(), obj)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("server received Content-Type %q, want application/json", receivedContentType)
	}
	if receivedBody != `{"user_id": "user-123", "action": "login"}` {
		t.Errorf("server received body %q", receivedBody)
	}

	// Verify response was parsed
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCallback_FormFields_Integration(t *testing.T) {
	var receivedBody string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		receivedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	data := []byte(`{
		"url": "` + server.URL + `",
		"method": "POST",
		"form_fields": {
			"username": "{{ user }}",
			"password": "{{ pass }}"
		}
	}`)

	var c Callback
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj := map[string]any{
		"user": "alice",
		"pass": "s3cr3t",
	}

	_, err := c.Do(t.Context(), obj)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected application/x-www-form-urlencoded, got %q", receivedContentType)
	}
	if !strings.Contains(receivedBody, "password=s3cr3t") {
		t.Errorf("expected password field in body, got %q", receivedBody)
	}
	if !strings.Contains(receivedBody, "username=alice") {
		t.Errorf("expected username field in body, got %q", receivedBody)
	}
}

func TestCallback_MultipartFormFields_Integration(t *testing.T) {
	var receivedContentType string
	receivedFields := make(map[string]string)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Errorf("failed to parse multipart form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for key, values := range r.MultipartForm.Value {
			if len(values) > 0 {
				receivedFields[key] = values[0]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	data := []byte(`{
		"url": "` + server.URL + `",
		"method": "POST",
		"content_type": "multipart/form-data",
		"form_fields": {
			"name": "{{ user_name }}",
			"message": "Hello, World!"
		}
	}`)

	var c Callback
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj := map[string]any{
		"user_name": "bob",
	}

	_, err := c.Do(t.Context(), obj)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	if !strings.HasPrefix(receivedContentType, "multipart/form-data") {
		t.Errorf("expected multipart/form-data, got %q", receivedContentType)
	}
	if receivedFields["name"] != "bob" {
		t.Errorf("expected name=bob, got %q", receivedFields["name"])
	}
	if receivedFields["message"] != "Hello, World!" {
		t.Errorf("expected message='Hello, World!', got %q", receivedFields["message"])
	}
}

func TestCallback_BodyTemplate_WithOrchestrationContext(t *testing.T) {
	// Simulates the context shape that the orchestration executor produces
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	data := []byte(`{
		"url": "` + server.URL + `",
		"method": "POST",
		"body": "{\"token\": \"{{ steps.auth.response.token }}\", \"user\": \"{{ steps.auth.response.user_id }}\"}"
	}`)

	var c Callback
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Build context like orchestration executor does
	obj := map[string]any{
		"steps": map[string]any{
			"auth": map[string]any{
				"response": map[string]any{
					"token":   "jwt-abc-123",
					"user_id": "user-456",
				},
			},
		},
	}

	_, err := c.Do(t.Context(), obj)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	expected := `{"token": "jwt-abc-123", "user": "user-456"}`
	if receivedBody != expected {
		t.Errorf("got %q, want %q", receivedBody, expected)
	}
}

func TestCallback_BodyTemplate_WithOriginalRequest(t *testing.T) {
	// Simulates accessing request snapshot data in callback body template
	var receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	data := []byte(`{
		"url": "` + server.URL + `",
		"method": "POST",
		"body": "{\"forwarded_method\": \"{{ request.method }}\", \"forwarded_path\": \"{{ request.path }}\"}"
	}`)

	var c Callback
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj := map[string]any{
		"request": map[string]any{
			"method": "POST",
			"path":   "/api/webhook",
			"body":   `{"event": "user.created"}`,
		},
	}

	_, err := c.Do(t.Context(), obj)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	expected := `{"forwarded_method": "POST", "forwarded_path": "/api/webhook"}`
	if receivedBody != expected {
		t.Errorf("got %q, want %q", receivedBody, expected)
	}
}

func TestCallback_BackwardCompatibility_NoNewFields(t *testing.T) {
	// Verify existing callbacks without new fields continue to work identically
	var receivedBody string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		receivedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer server.Close()

	data := []byte(`{
		"url": "` + server.URL + `",
		"method": "POST"
	}`)

	var c Callback
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj := map[string]any{"key": "value", "num": 42}

	result, err := c.Do(t.Context(), obj)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}

	// Should have sent JSON-marshaled obj
	if receivedContentType != "application/json" {
		t.Errorf("expected application/json, got %q", receivedContentType)
	}

	// Verify it was valid JSON containing our fields
	var parsed map[string]any
	if err := json.Unmarshal([]byte(receivedBody), &parsed); err != nil {
		t.Fatalf("received body is not valid JSON: %v", err)
	}
	if parsed["key"] != "value" {
		t.Errorf("expected key=value in body, got %v", parsed["key"])
	}

	// Verify response was parsed
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
