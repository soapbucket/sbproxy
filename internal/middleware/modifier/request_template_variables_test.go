package modifier

import (
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestResolveTemplateVariables_RequestID tests {{request.id}} template variable resolution
func TestResolveTemplateVariables_RequestID(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// Test without RequestData
	t.Run("without RequestData", func(t *testing.T) {
		result := resolveTemplateVariables("{{request.id}}", req)
		if result != "" {
			t.Errorf("Expected empty string when RequestData is nil, got: %s", result)
		}
	})

	// Test with RequestData but no ID
	t.Run("with RequestData but no ID", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{request.id}}", req)
		if result != "" {
			t.Errorf("Expected empty string when RequestData.ID is empty, got: %s", result)
		}
	})

	// Test with RequestData and ID
	t.Run("with RequestData and ID", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.ID = "test-request-id-123"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{request.id}}", req)
		if result != "test-request-id-123" {
			t.Errorf("Expected 'test-request-id-123', got: %s", result)
		}
	})
}

// TestResolveTemplateVariables_RemoteAddr tests {{request.remote_addr}} template variable resolution
func TestResolveTemplateVariables_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	// Test without RemoteAddr
	t.Run("without RemoteAddr", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)
		req.RemoteAddr = "" // Explicitly set to empty

		result := resolveTemplateVariables("{{request.remote_addr}}", req)
		if result != "" {
			t.Errorf("Expected empty string when RemoteAddr is empty, got: %s", result)
		}
	})

	// Test with RemoteAddr (with port)
	t.Run("with RemoteAddr and port", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)
		req.RemoteAddr = "192.168.1.100:12345"

		result := resolveTemplateVariables("{{request.remote_addr}}", req)
		if result != "192.168.1.100" {
			t.Errorf("Expected '192.168.1.100', got: %s", result)
		}
	})

	// Test with RemoteAddr (without port)
	t.Run("with RemoteAddr without port", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)
		req.RemoteAddr = "192.168.1.100"

		result := resolveTemplateVariables("{{request.remote_addr}}", req)
		if result != "192.168.1.100" {
			t.Errorf("Expected '192.168.1.100', got: %s", result)
		}
	})
}

// TestRequestModifier_ApplyWithTemplateVariables tests request modifier with template variables
func TestRequestModifier_ApplyWithTemplateVariables(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// Create RequestData with ID
	requestData := reqctx.NewRequestData()
	requestData.ID = "test-request-id-456"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	// Create request modifier with template variables
	modifier := &RequestModifier{
		Headers: &HeaderModifications{
			Set: map[string]string{
				"X-Request-ID":    "{{request.id}}",
				"X-Real-IP":       "{{request.remote_addr}}",
				"X-Forwarded-Proto": "https",
			},
		},
	}

	// Apply modifier
	err := modifier.Apply(req)
	if err != nil {
		t.Fatalf("Failed to apply modifier: %v", err)
	}

	// Check headers
	if req.Header.Get("X-Request-ID") != "test-request-id-456" {
		t.Errorf("Expected X-Request-ID to be 'test-request-id-456', got: %s", req.Header.Get("X-Request-ID"))
	}

	// request.remote_addr strips the port (IP only)
	if req.Header.Get("X-Real-IP") != "192.168.1.100" {
		t.Errorf("Expected X-Real-IP to be '192.168.1.100' (port stripped), got: %s", req.Header.Get("X-Real-IP"))
	}

	if req.Header.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("Expected X-Forwarded-Proto to be 'https', got: %s", req.Header.Get("X-Forwarded-Proto"))
	}
}

// TestResolveTemplateVariables_RequestData tests {{request.data.key}} template variable resolution
func TestResolveTemplateVariables_RequestData(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	// Test with RequestData.Data
	t.Run("with RequestData.Data", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.Data = map[string]any{
			"user_prefs": map[string]any{
				"theme":    "dark",
				"language": "en",
			},
			"processing_id": "abc123",
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		// Test {{request.data.key}} syntax
		result1 := resolveTemplateVariables("{{request.data.user_prefs.theme}}", req)
		if result1 != "dark" {
			t.Errorf("Expected 'dark', got: %s", result1)
		}

		result2 := resolveTemplateVariables("{{request.data.processing_id}}", req)
		if result2 != "abc123" {
			t.Errorf("Expected 'abc123', got: %s", result2)
		}

		// Test nested access
		result3 := resolveTemplateVariables("{{request.data.user_prefs.language}}", req)
		if result3 != "en" {
			t.Errorf("Expected 'en' for request.data.user_prefs.language, got: %s", result3)
		}
	})

	// Test without RequestData.Data
	t.Run("without RequestData.Data", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.Data = nil
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{request.data.user_prefs.theme}}", req)
		if result != "" {
			t.Errorf("Expected empty string when RequestData.Data is nil, got: %s", result)
		}
	})
}

// TestResolveTemplateVariables_SessionData tests {{session.data.key}} template variable resolution
func TestResolveTemplateVariables_SessionData(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	// Test with SessionData.Data
	t.Run("with SessionData.Data", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.SessionData = &reqctx.SessionData{
			Data: map[string]any{
				"user_prefs": map[string]any{
					"theme":    "dark",
					"language": "en",
				},
				"subscription": map[string]any{
					"tier": "premium",
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		// Test {{session.data.key}} syntax
		result1 := resolveTemplateVariables("{{session.data.user_prefs.theme}}", req)
		if result1 != "dark" {
			t.Errorf("Expected 'dark', got: %s", result1)
		}

		result2 := resolveTemplateVariables("{{session.data.subscription.tier}}", req)
		if result2 != "premium" {
			t.Errorf("Expected 'premium', got: %s", result2)
		}

		// Test nested access
		result3 := resolveTemplateVariables("{{session.data.subscription.tier}}", req)
		if result3 != "premium" {
			t.Errorf("Expected 'premium' for session.data.subscription.tier, got: %s", result3)
		}
	})

	// Test without SessionData.Data
	t.Run("without SessionData.Data", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.SessionData = nil
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{session.data.user_prefs.theme}}", req)
		if result != "" {
			t.Errorf("Expected empty string when SessionData.Data is nil, got: %s", result)
		}
	})
}

// TestResolveTemplateVariables_AuthData tests {{session.auth.data.key}} template variable resolution
func TestResolveTemplateVariables_AuthData(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	// Test with AuthData.Data
	t.Run("with AuthData.Data", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.SessionData = &reqctx.SessionData{
			AuthData: &reqctx.AuthData{
				Data: map[string]any{
					"user_id": "123",
					"email":   "user@example.com",
					"roles":   []any{"admin", "user"},
					"profile": map[string]any{
						"name": "John Doe",
					},
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		// Test {{session.auth.data.key}} syntax
		result1 := resolveTemplateVariables("{{session.auth.data.email}}", req)
		if result1 != "user@example.com" {
			t.Errorf("Expected 'user@example.com', got: %s", result1)
		}

		result2 := resolveTemplateVariables("{{session.auth.data.profile.name}}", req)
		if result2 != "John Doe" {
			t.Errorf("Expected 'John Doe', got: %s", result2)
		}

		// Test nested auth data access
		result3 := resolveTemplateVariables("{{session.auth.data.profile.name}}", req)
		if result3 != "John Doe" {
			t.Errorf("Expected 'John Doe' for session.auth.data.profile.name, got: %s", result3)
		}
	})

	// Test without AuthData.Data
	t.Run("without AuthData.Data", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.SessionData = &reqctx.SessionData{
			AuthData: nil,
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{session.auth.data.email}}", req)
		if result != "" {
			t.Errorf("Expected empty string when AuthData.Data is nil, got: %s", result)
		}
	})

	// Test without SessionData
	t.Run("without SessionData", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.SessionData = nil
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{session.auth.data.email}}", req)
		if result != "" {
			t.Errorf("Expected empty string when SessionData is nil, got: %s", result)
		}
	})

	// Test {{session.auth.data.key}} syntax
	t.Run("with session.auth.data syntax", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.SessionData = &reqctx.SessionData{
			AuthData: &reqctx.AuthData{
				Data: map[string]any{
					"email":   "user@example.com",
					"user_id": "123",
				},
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		// Test {{session.auth.data.key}} syntax
		result1 := resolveTemplateVariables("{{session.auth.data.email}}", req)
		if result1 != "user@example.com" {
			t.Errorf("Expected 'user@example.com', got: %s", result1)
		}

		result2 := resolveTemplateVariables("{{session.auth.data.user_id}}", req)
		if result2 != "123" {
			t.Errorf("Expected '123' for session.auth.data.user_id, got: %s", result2)
		}
	})
}

// TestResolveTemplateVariables_LowercaseHeaders tests that headers are accessible via lowercase keys
func TestResolveTemplateVariables_LowercaseHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("Content-Type", "application/json")

	requestData := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	// Test lowercase header access
	t.Run("lowercase header access", func(t *testing.T) {
		result1 := resolveTemplateVariables("{{request.headers.authorization}}", req)
		if result1 != "Bearer token123" {
			t.Errorf("Expected 'Bearer token123', got: %s", result1)
		}

		// Headers with hyphens are converted to underscores for dot notation access
		result2 := resolveTemplateVariables("{{request.headers.x_custom_header}}", req)
		if result2 != "custom-value" {
			t.Errorf("Expected 'custom-value', got: %s", result2)
		}

		result3 := resolveTemplateVariables("{{request.headers.content_type}}", req)
		if result3 != "application/json" {
			t.Errorf("Expected 'application/json', got: %s", result3)
		}
	})

	// Test snapshot headers access via request.headers (from Snapshot)
	t.Run("snapshot headers access", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.Snapshot = &reqctx.RequestSnapshot{
			Headers: map[string]string{
				"authorization": "Bearer original-token",
				"x_original":    "original-value",
			},
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result1 := resolveTemplateVariables("{{request.headers.authorization}}", req)
		if result1 != "Bearer original-token" {
			t.Errorf("Expected 'Bearer original-token', got: %s", result1)
		}

		// Headers with hyphens are converted to underscores for dot notation access
		result2 := resolveTemplateVariables("{{request.headers.x_original}}", req)
		if result2 != "original-value" {
			t.Errorf("Expected 'original-value', got: %s", result2)
		}
	})

	// Test missing header returns empty
	t.Run("missing header returns empty", func(t *testing.T) {
		result := resolveTemplateVariables("{{request.headers.missing_header}}", req)
		if result != "" {
			t.Errorf("Expected empty string for missing header, got: %s", result)
		}
	})
}

// TestResolveTemplateVariables_DefaultValue tests default values using Mustache inverted sections
func TestResolveTemplateVariables_DefaultValue(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	// Test with existing variable (should not use default)
	t.Run("existing variable ignores default", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.Data = map[string]any{
			"user_id": "12345",
		}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{request.data.user_id}}{{^request.data.user_id}}default{{/request.data.user_id}}", req)
		if result != "12345" {
			t.Errorf("Expected '12345' (existing value), got: %s", result)
		}
	})

	// Test with missing variable (should use default)
	t.Run("missing variable uses default", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.Data = map[string]any{}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{request.data.missing_key}}{{^request.data.missing_key}}default{{/request.data.missing_key}}", req)
		if result != "default" {
			t.Errorf("Expected 'default' (default value), got: %s", result)
		}
	})

	// Test with custom default value
	t.Run("custom default value", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		requestData.Data = map[string]any{}
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		result := resolveTemplateVariables("{{request.data.api_version}}{{^request.data.api_version}}v1.0{{/request.data.api_version}}", req)
		if result != "v1.0" {
			t.Errorf("Expected 'v1.0' (custom default value), got: %s", result)
		}
	})

	// Test with header default value
	t.Run("header with default value", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)
		// Don't set the header

		result := resolveTemplateVariables("{{request.headers.x_api_version}}{{^request.headers.x_api_version}}v2.0{{/request.headers.x_api_version}}", req)
		if result != "v2.0" {
			t.Errorf("Expected 'v2.0' (default value for missing header), got: %s", result)
		}
	})

	// Test with existing header (should not use default)
	t.Run("existing header ignores default", func(t *testing.T) {
		requestData := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)
		req.Header.Set("X-API-Version", "v3.0")

		result := resolveTemplateVariables("{{request.headers.x_api_version}}{{^request.headers.x_api_version}}v2.0{{/request.headers.x_api_version}}", req)
		if result != "v3.0" {
			t.Errorf("Expected 'v3.0' (existing header value), got: %s", result)
		}
	})
}

