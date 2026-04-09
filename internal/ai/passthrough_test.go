package ai

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPassthroughRequest(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		config     *PassthroughConfig
		path       string
		wantResult bool
	}{
		{
			name:       "header present and true",
			header:     "true",
			config:     nil,
			path:       "/v1/chat/completions",
			wantResult: true,
		},
		{
			name:       "header present but false",
			header:     "false",
			config:     nil,
			path:       "/v1/chat/completions",
			wantResult: false,
		},
		{
			name:       "header absent",
			header:     "",
			config:     nil,
			path:       "/v1/chat/completions",
			wantResult: false,
		},
		{
			name:       "config enabled",
			header:     "",
			config:     &PassthroughConfig{Enabled: true},
			path:       "/v1/chat/completions",
			wantResult: true,
		},
		{
			name:       "config enabled with allowed paths match",
			header:     "",
			config:     &PassthroughConfig{Enabled: true, AllowedPaths: []string{"chat/completions"}},
			path:       "/v1/chat/completions",
			wantResult: true,
		},
		{
			name:       "config enabled with allowed paths no match",
			header:     "",
			config:     &PassthroughConfig{Enabled: true, AllowedPaths: []string{"embeddings"}},
			path:       "/v1/chat/completions",
			wantResult: false,
		},
		{
			name:       "header true with allowed paths match",
			header:     "true",
			config:     &PassthroughConfig{AllowedPaths: []string{"chat/completions"}},
			path:       "/v1/chat/completions",
			wantResult: true,
		},
		{
			name:       "header true with allowed paths no match",
			header:     "true",
			config:     &PassthroughConfig{AllowedPaths: []string{"embeddings"}},
			path:       "/v1/chat/completions",
			wantResult: false,
		},
		{
			name:       "header case insensitive TRUE",
			header:     "TRUE",
			config:     nil,
			path:       "/v1/chat/completions",
			wantResult: true,
		},
		{
			name:       "config disabled explicitly",
			header:     "",
			config:     &PassthroughConfig{Enabled: false},
			path:       "/v1/chat/completions",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProviderConfig{Name: "test"}
			providers := []*ProviderConfig{cfg}
			h := &Handler{
				config: &HandlerConfig{
					Providers:          providers,
					MaxRequestBodySize: 10 * 1024 * 1024,
					Passthrough:        tt.config,
				},
				providers: map[string]providerEntry{
					cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
				},
				router: NewRouter(nil, providers),
			}

			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			if tt.header != "" {
				req.Header.Set("X-SB-Passthrough", tt.header)
			}

			got := h.isPassthroughRequest(req)
			assert.Equal(t, tt.wantResult, got)
		})
	}
}

func TestPassthroughForward(t *testing.T) {
	// Create a test upstream server that echoes back the request body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Received", "true")
		w.WriteHeader(http.StatusOK)
		// Echo the body back to verify it was forwarded unmodified.
		w.Write(body)
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	originalBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"custom_field":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(originalBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// The body should be forwarded without any parsing or modification.
	assert.Equal(t, originalBody, w.Body.String())
}

func TestPassthroughHeaders(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{
		Name:    "test",
		BaseURL: upstream.URL,
		APIKey:  "sk-test-key-123",
	}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SB-Passthrough", "true")
	req.Header.Set("X-SB-Agent", "my-agent")
	req.Header.Set("X-Custom-Header", "keep-me")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	require.NotNil(t, receivedHeaders)
	// Auth header should be injected.
	assert.Equal(t, "Bearer sk-test-key-123", receivedHeaders.Get("Authorization"))
	// X-SB-* headers should be stripped.
	assert.Empty(t, receivedHeaders.Get("X-SB-Passthrough"))
	assert.Empty(t, receivedHeaders.Get("X-SB-Agent"))
	// Non-internal headers should be preserved.
	assert.Equal(t, "keep-me", receivedHeaders.Get("X-Custom-Header"))
	// Content-Type should be preserved.
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
}

func TestPassthroughResponse(t *testing.T) {
	responseBody := `{"id":"resp-123","choices":[{"message":{"content":"Hi there"}}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "upstream-req-id")
		w.Header().Set("X-Ratelimit-Remaining", "99")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString("{}"))
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, responseBody, w.Body.String())
	// Response headers should be preserved.
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "upstream-req-id", w.Header().Get("X-Request-Id"))
	assert.Equal(t, "99", w.Header().Get("X-Ratelimit-Remaining"))
}

func TestPassthroughSkipsGuardrails(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	guardrails := &mockGuardrailRunner{}

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
			Guardrails:         guardrails,
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// The upstream was called (passthrough worked).
	assert.Equal(t, 1, callCount)
	assert.Equal(t, http.StatusOK, w.Code)
	// Guardrails should NOT have been invoked. The mockGuardrailRunner would have
	// returned a block if CheckInput/CheckOutput were called, but we cannot easily
	// detect non-calls on this mock. The key assertion is that the request succeeded
	// without being blocked, which proves guardrails were not consulted.
}

func TestPassthroughSkipsBudget(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
			// Budget is set but should not be consulted in passthrough mode.
			Budget: &BudgetEnforcer{},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// The upstream was called, meaning budget check was skipped.
	assert.Equal(t, 1, callCount)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPassthroughStreamingResponse(t *testing.T) {
	// Simulate an SSE streaming response from the upstream.
	sseData := "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sseData))
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-4","stream":true,"messages":[]}`))
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// The SSE data should be forwarded verbatim without parsing.
	assert.Equal(t, sseData, w.Body.String())
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
}

func TestPassthroughAzureAuth(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{
		Name:    "azure-test",
		Type:    "azure",
		BaseURL: upstream.URL,
		APIKey:  "azure-key-123",
	}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "azure-test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString("{}"))
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	require.NotNil(t, receivedHeaders)
	// Azure should use api-key header, not Authorization.
	assert.Equal(t, "azure-key-123", receivedHeaders.Get("api-key"))
	assert.Empty(t, receivedHeaders.Get("Authorization"))
}

func TestPassthroughPreservesQueryString(t *testing.T) {
	var receivedURL string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/models?limit=10&order=desc", nil)
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.Contains(receivedURL, "limit=10"), "query string should contain limit=10, got: %s", receivedURL)
	assert.True(t, strings.Contains(receivedURL, "order=desc"), "query string should contain order=desc, got: %s", receivedURL)
}

func TestPassthroughUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"invalid model","type":"invalid_request_error"}}`))
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "test", BaseURL: upstream.URL}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "test"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString("{}"))
	req.Header.Set("X-SB-Passthrough", "true")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// Error status and body should be forwarded as-is.
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid model")
}
