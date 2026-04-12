package transport

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

// Mock verifier for testing
type mockVerifier struct {
	verifyFunc func(*http.Response) error
}

func (m *mockVerifier) VerifyResponse(resp *http.Response) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(resp)
	}
	return nil
}

func TestResponseVerificationTransport_LargeBody(t *testing.T) {
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled:            true,
			SignatureThreshold: 1024, // 1KB
		},
	}

	tests := []struct {
		name              string
		bodySize          int
		shouldVerify      bool
		expectPassthrough bool
	}{
		{
			name:              "Small body - should verify",
			bodySize:          500,
			shouldVerify:      true,
			expectPassthrough: false,
		},
		{
			name:              "Large body - should skip verification",
			bodySize:          2000,
			shouldVerify:      false,
			expectPassthrough: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyData := make([]byte, tt.bodySize)
			for i := range bodyData {
				bodyData[i] = byte(i % 256)
			}

			// Create a mock transport that returns our response
			mockTransport := &verificationTestTransport{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					resp := &http.Response{
						StatusCode:    http.StatusOK,
						ContentLength: int64(tt.bodySize),
						Body:          io.NopCloser(bytes.NewReader(bodyData)),
						Header:        make(http.Header),
						Request:       req,
					}
					return resp, nil
				},
			}

			verifierCalled := false
			verifier := &mockVerifier{
				verifyFunc: func(resp *http.Response) error {
					verifierCalled = true
					return nil
				},
			}

			transport := &ResponseVerificationTransport{
				Transport: mockTransport,
				Config: ResponseVerificationConfig{
					Verifier: verifier,
				},
			}

			req := &http.Request{}
			ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
			req = req.WithContext(ctx)

			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip error: %v", err)
			}

			if resp == nil {
				t.Fatal("Expected response, got nil")
			}

			if tt.shouldVerify && !verifierCalled {
				t.Error("Expected verifier to be called")
			}
			if !tt.shouldVerify && verifierCalled {
				t.Error("Expected verifier NOT to be called for large body")
			}

			// Check body is still readable
			resultBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll error: %v", err)
			}

			if len(resultBody) != tt.bodySize {
				t.Errorf("Expected body size %d, got %d", tt.bodySize, len(resultBody))
			}
		})
	}
}

func TestResponseVerificationTransport_NoConfig(t *testing.T) {
	// Test with no config - should use defaults
	bodyData := make([]byte, 100)
	mockTransport := &verificationTestTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(len(bodyData)),
				Body:          io.NopCloser(bytes.NewReader(bodyData)),
				Header:        make(http.Header),
				Request:       req,
			}
			return resp, nil
		},
	}

	verifierCalled := false
	verifier := &mockVerifier{
		verifyFunc: func(resp *http.Response) error {
			verifierCalled = true
			return nil
		},
	}

	transport := &ResponseVerificationTransport{
		Transport: mockTransport,
		Config: ResponseVerificationConfig{
			Verifier: verifier,
		},
	}

	req := &http.Request{} // No config in context

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected response, got nil")
	}

	// Should verify (default threshold is 50MB, so 100 bytes is fine)
	if !verifierCalled {
		t.Error("Expected verifier to be called")
	}
}

func TestResponseVerificationTransport_DisabledStreaming(t *testing.T) {
	provider := &mockStreamingConfigProvider{
		config: StreamingConfig{
			Enabled: false,
		},
	}

	bodyData := make([]byte, 20000) // Large body
	mockTransport := &verificationTestTransport{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode:    http.StatusOK,
				ContentLength: int64(len(bodyData)),
				Body:          io.NopCloser(bytes.NewReader(bodyData)),
				Header:        make(http.Header),
				Request:       req,
			}
			return resp, nil
		},
	}

	verifierCalled := false
	verifier := &mockVerifier{
		verifyFunc: func(resp *http.Response) error {
			verifierCalled = true
			return nil
		},
	}

	transport := &ResponseVerificationTransport{
		Transport: mockTransport,
		Config: ResponseVerificationConfig{
			Verifier: verifier,
		},
	}

	req := &http.Request{}
	ctx := context.WithValue(req.Context(), streamingConfigProviderContextKey{}, provider)
	req = req.WithContext(ctx)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected response, got nil")
	}

	// Should verify even though body is large (streaming disabled)
	if !verifierCalled {
		t.Error("Expected verifier to be called")
	}
}

func TestVerifyLargeResponse(t *testing.T) {
	transport := &ResponseVerificationTransport{
		Config: ResponseVerificationConfig{
			Verifier: &mockVerifier{},
		},
	}

	bodyData := make([]byte, 5000)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(bodyData)),
		Body:          io.NopCloser(bytes.NewReader(bodyData)),
		Header:        make(http.Header),
	}

	result, err := transport.verifyLargeResponse(resp, 1000)
	if err != nil {
		t.Fatalf("verifyLargeResponse error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}

	// Should pass through without verification
	resultBody, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}

	if len(resultBody) != len(bodyData) {
		t.Errorf("Expected body size %d, got %d", len(bodyData), len(resultBody))
	}
}

func TestGetStreamingConfigProviderFromRequest_Verification(t *testing.T) {
	t.Run("With provider in context", func(t *testing.T) {
		provider := &mockStreamingConfigProvider{
			config: StreamingConfig{
				Enabled:            true,
				SignatureThreshold: 1024,
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
		if config.SignatureThreshold != 1024 {
			t.Errorf("Expected signature threshold 1024, got %d", config.SignatureThreshold)
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

func TestShouldSkipVerification(t *testing.T) {
	transport := &ResponseVerificationTransport{
		Config: ResponseVerificationConfig{
			Verifier: &mockVerifier{},
		},
	}

	tests := []struct {
		name            string
		verifier        ResponseVerifier
		skipStatusCodes []int
		contentTypes    []string
		statusCode      int
		contentType     string
		shouldSkip      bool
	}{
		{
			name:       "No verifier",
			verifier:   nil,
			shouldSkip: true,
		},
		{
			name:       "With verifier",
			verifier:   &mockVerifier{},
			shouldSkip: false,
		},
		{
			name:            "Skip status code",
			verifier:        &mockVerifier{},
			skipStatusCodes: []int{404, 500},
			statusCode:      404,
			shouldSkip:      true,
		},
		{
			name:            "Don't skip other status code",
			verifier:        &mockVerifier{},
			skipStatusCodes: []int{404, 500},
			statusCode:      200,
			shouldSkip:      false,
		},
		{
			name:         "Match content type",
			verifier:     &mockVerifier{},
			contentTypes: []string{"application/json"},
			contentType:  "application/json",
			shouldSkip:   false,
		},
		{
			name:         "Don't match content type",
			verifier:     &mockVerifier{},
			contentTypes: []string{"application/json"},
			contentType:  "text/html",
			shouldSkip:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport.Config.Verifier = tt.verifier
			transport.Config.SkipStatusCodes = tt.skipStatusCodes
			transport.Config.ContentTypes = tt.contentTypes

			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			result := transport.shouldSkipVerification(resp)
			if result != tt.shouldSkip {
				t.Errorf("shouldSkipVerification() = %v, want %v", result, tt.shouldSkip)
			}
		})
	}
}

// verificationTestTransport is a helper for testing
type verificationTestTransport struct {
	roundTripFunc func(*http.Request) (*http.Response, error)
}

func (m *verificationTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.roundTripFunc != nil {
		return m.roundTripFunc(req)
	}
	return nil, nil
}
