package lua

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJSONTransformer_TransformRequestData_Basic(t *testing.T) {
	script := `function modify_json(data, ctx)
		data.transformed = true
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}
	req := httptest.NewRequest("POST", "/api/test", nil)

	result, err := transformer.TransformRequestData(data, req)
	if err != nil {
		t.Fatalf("TransformRequestData failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if resultMap["transformed"] != true {
		t.Errorf("expected transformed=true, got %v", resultMap["transformed"])
	}
	if resultMap["key"] != "value" {
		t.Errorf("expected key=value, got %v", resultMap["key"])
	}
}

func TestJSONTransformer_TransformRequestData_WithRequestContext(t *testing.T) {
	script := `function modify_json(data, ctx)
		if request ~= nil then
			data.request_path = request.path
			data.request_method = request.method
		end
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}
	req := httptest.NewRequest("POST", "/api/v1/users", nil)

	result, err := transformer.TransformRequestData(data, req)
	if err != nil {
		t.Fatalf("TransformRequestData failed: %v", err)
	}

	resultMap := result.(map[string]interface{})
	if resultMap["request_path"] != "/api/v1/users" {
		t.Errorf("expected request_path=/api/v1/users, got %v", resultMap["request_path"])
	}
	if resultMap["request_method"] != "POST" {
		t.Errorf("expected request_method=POST, got %v", resultMap["request_method"])
	}
}

func TestJSONTransformer_TransformRequestData_NilRequest(t *testing.T) {
	script := `function modify_json(data, ctx)
		data.processed = true
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}

	result, err := transformer.TransformRequestData(data, nil)
	if err != nil {
		t.Fatalf("TransformRequestData failed: %v", err)
	}

	resultMap := result.(map[string]interface{})
	if resultMap["processed"] != true {
		t.Errorf("expected processed=true, got %v", resultMap["processed"])
	}
}

func TestJSONTransformer_TransformRequestData_Timeout(t *testing.T) {
	script := `function modify_json(data, ctx)
		while true do end
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}
	req := httptest.NewRequest("POST", "/api/test", nil)

	_, err = transformer.TransformRequestData(data, req)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestJSONTransformer_TransformRequestData_NilReturn(t *testing.T) {
	script := `function modify_json(data, ctx)
		return nil
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	originalData := map[string]interface{}{"key": "value"}
	req := httptest.NewRequest("POST", "/api/test", nil)

	result, err := transformer.TransformRequestData(originalData, req)
	if err != nil {
		t.Fatalf("TransformRequestData failed: %v", err)
	}

	// nil return should return original data
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if resultMap["key"] != "value" {
		t.Errorf("expected original data preserved, got %v", resultMap)
	}
}

func TestJSONTransformer_TransformRequestData_WithCookies(t *testing.T) {
	script := `function modify_json(data, ctx)
		if cookies ~= nil and cookies.session_id ~= nil then
			data.has_session = true
		end
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}
	req := httptest.NewRequest("POST", "/api/test", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})

	result, err := transformer.TransformRequestData(data, req)
	if err != nil {
		t.Fatalf("TransformRequestData failed: %v", err)
	}

	resultMap := result.(map[string]interface{})
	if resultMap["has_session"] != true {
		t.Errorf("expected has_session=true, got %v", resultMap["has_session"])
	}
}

func TestJSONTransformer_TransformRequestData_WithQueryParams(t *testing.T) {
	script := `function modify_json(data, ctx)
		if params ~= nil and params.version ~= nil then
			data.api_version = params.version
		end
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}
	req := httptest.NewRequest("POST", "/api/test?version=2", nil)

	result, err := transformer.TransformRequestData(data, req)
	if err != nil {
		t.Fatalf("TransformRequestData failed: %v", err)
	}

	resultMap := result.(map[string]interface{})
	if resultMap["api_version"] != "2" {
		t.Errorf("expected api_version=2, got %v", resultMap["api_version"])
	}
}

// Benchmarks

func BenchmarkJSONTransformer_TransformRequestData(b *testing.B) {
	b.ReportAllocs()

	script := `function modify_json(data, ctx)
		if data.userName then
			data.username = data.userName
			data.userName = nil
		end
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		b.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"userName": "alice", "age": float64(30)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/users", nil)
		_, _ = transformer.TransformRequestData(data, req)
	}
}

func BenchmarkJSONTransformer_TransformRequestData_NilRequest(b *testing.B) {
	b.ReportAllocs()

	script := `function modify_json(data, ctx)
		data.processed = true
		return data
	end`

	transformer, err := NewJSONTransformerWithTimeout(script, 100*time.Millisecond)
	if err != nil {
		b.Fatalf("NewJSONTransformerWithTimeout failed: %v", err)
	}

	data := map[string]interface{}{"key": "value"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = transformer.TransformRequestData(data, nil)
	}
}
