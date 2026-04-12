package modifier

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

// mockStreamingConfigProvider implements StreamingConfigProvider for testing
type mockStreamingConfigProvider struct {
	config StreamingConfig
}

func (m *mockStreamingConfigProvider) GetStreamingConfig() StreamingConfig {
	return m.config
}

func TestApplyResponseBodyModifications_SizeCheck(t *testing.T) {
	// Create a mock streaming config provider
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:           true,
			ModifierThreshold: 1024, // 1KB
		},
	}

	tests := []struct {
		name         string
		bodySize     int
		threshold    int64
		shouldModify bool
		modification *BodyModifications
	}{
		{
			name:         "Small body - should modify",
			bodySize:     500,
			threshold:    1024,
			shouldModify: true,
			modification: &BodyModifications{
				Replace: "modified",
			},
		},
		{
			name:         "Large body - should skip",
			bodySize:     2000,
			threshold:    1024,
			shouldModify: false,
			modification: &BodyModifications{
				Replace: "modified",
			},
		},
		{
			name:         "Exactly at threshold - should modify",
			bodySize:     1024,
			threshold:    1024,
			shouldModify: true,
			modification: &BodyModifications{
				Replace: "modified",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create response with body
			bodyData := make([]byte, tt.bodySize)
			for i := range bodyData {
				bodyData[i] = byte(i % 256)
			}

			resp := &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(tt.bodySize),
				Body:          io.NopCloser(bytes.NewReader(bodyData)),
				Header:        make(http.Header),
			}

			// Create request with streaming config provider in context
			req := &http.Request{}
			ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
			resp.Request = req.WithContext(ctx)

			// Apply modifications
			err := applyResponseBodyModifications(resp, tt.modification)
			if err != nil {
				t.Fatalf("applyResponseBodyModifications error: %v", err)
			}

			// Read the body to check if it was modified
			resultBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}

			if tt.shouldModify {
				// Should be modified
				if string(resultBody) != "modified" {
					t.Errorf("Expected body to be modified, got %q", string(resultBody))
				}
			} else {
				// Should be original (passthrough)
				if len(resultBody) != tt.bodySize {
					t.Errorf("Expected original body size %d, got %d", tt.bodySize, len(resultBody))
				}
				// Check first few bytes match
				if len(resultBody) > 0 && resultBody[0] != bodyData[0] {
					t.Error("Body should be unchanged (passthrough)")
				}
			}
		})
	}
}

func TestApplyResponseBodyModifications_ThresholdDuringRead(t *testing.T) {
	// Test case where Content-Length is unknown but body exceeds threshold during read
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:           true,
			ModifierThreshold: 1024, // 1KB
		},
	}

	// Create a body larger than threshold but with unknown Content-Length
	bodyData := make([]byte, 2000)
	for i := range bodyData {
		bodyData[i] = byte(i % 256)
	}

	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: -1, // Unknown length
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
	}

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	resp.Request = req.WithContext(ctx)

	modification := &BodyModifications{
		Replace: "modified",
	}

	err := applyResponseBodyModifications(resp, modification)
	if err != nil {
		t.Fatalf("applyResponseBodyModifications error: %v", err)
	}

	// Should pass through without modification (body was restored from what was read)
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	// When threshold is exceeded during read, body is restored from what was read
	// so it should contain the original body data
	if len(resultBody) != len(bodyData) {
		t.Errorf("Expected original body size %d, got %d", len(bodyData), len(resultBody))
	}
	// Verify first few bytes match
	if len(resultBody) > 0 && resultBody[0] != bodyData[0] {
		t.Error("Body content should match original")
	}
}

func TestApplyResponseBodyModifications_NoConfig(t *testing.T) {
	// Test with no config - should use defaults
	bodyData := make([]byte, 100)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(bodyData)),
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
		Request:       &http.Request{}, // No config in context
	}

	modification := &BodyModifications{
		Replace: "modified",
	}

	err := applyResponseBodyModifications(resp, modification)
	if err != nil {
		t.Fatalf("applyResponseBodyModifications error: %v", err)
	}

	// Should modify (default threshold is 10MB, so 100 bytes is fine)
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if string(resultBody) != "modified" {
		t.Errorf("Expected modified body, got %q", string(resultBody))
	}
}

func TestApplyResponseBodyModifications_DisabledStreaming(t *testing.T) {
	// Test with streaming disabled - should always modify
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled: false,
		},
	}

	bodyData := make([]byte, 20000) // Large body
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(bodyData)),
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
	}

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	resp.Request = req.WithContext(ctx)

	modification := &BodyModifications{
		Replace: "modified",
	}

	err := applyResponseBodyModifications(resp, modification)
	if err != nil {
		t.Fatalf("applyResponseBodyModifications error: %v", err)
	}

	// Should modify even though body is large (streaming disabled)
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if string(resultBody) != "modified" {
		t.Errorf("Expected modified body, got %q", string(resultBody))
	}
}

func TestApplyResponseBodyModifications_RemoveModification(t *testing.T) {
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:           true,
			ModifierThreshold: 1024, // 1KB
		},
	}

	bodyData := make([]byte, 500)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(bodyData)),
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
	}

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	resp.Request = req.WithContext(ctx)

	modification := &BodyModifications{
		Remove: true,
	}

	err := applyResponseBodyModifications(resp, modification)
	if err != nil {
		t.Fatalf("applyResponseBodyModifications error: %v", err)
	}

	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(resultBody) != 0 {
		t.Errorf("Expected empty body, got %d bytes", len(resultBody))
	}
}

func TestGetStreamingConfigProviderFromRequest(t *testing.T) {
	t.Run("With provider in context", func(t *testing.T) {
		provider := &mockStreamingConfigProvider{
			config: StreamingConfig{
				Enabled:           true,
				ModifierThreshold: 1024,
			},
		}
		req := &http.Request{}
		ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
		req = req.WithContext(ctx)

		result := getStreamingConfigProviderFromRequest(req)
		if result == nil {
			t.Fatal("Expected provider, got nil")
		}
		config := result.GetStreamingConfig()
		if !config.Enabled {
			t.Error("Expected streaming enabled, got disabled")
		}
		if config.ModifierThreshold != 1024 {
			t.Errorf("Expected modifier threshold 1024, got %d", config.ModifierThreshold)
		}
	})

	t.Run("Without provider in context", func(t *testing.T) {
		req := &http.Request{}
		result := getStreamingConfigProviderFromRequest(req)
		if result != nil {
			t.Error("Expected nil, got provider")
		}
	})

	t.Run("Nil request", func(t *testing.T) {
		result := getStreamingConfigProviderFromRequest(nil)
		if result != nil {
			t.Error("Expected nil, got provider")
		}
	})
}

func TestResponseModifier_Apply_WithSizeCheck(t *testing.T) {
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:           true,
			ModifierThreshold: 1024, // 1KB
		},
	}

	// Large body that should be skipped
	bodyData := make([]byte, 2000)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(bodyData)),
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
	}

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	resp.Request = req.WithContext(ctx)

	modifier := &ResponseModifier{
		Body: &BodyModifications{
			Replace: "modified",
		},
	}

	err := modifier.Apply(resp)
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}

	// Should pass through without modification
	resultBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(resultBody) != len(bodyData) {
		t.Errorf("Expected original body size %d, got %d", len(bodyData), len(resultBody))
	}
}
