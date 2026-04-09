package ai

import (
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompatLayer_ForwardPassthroughHeaders(t *testing.T) {
	tests := []struct {
		name     string
		src      map[string]string
		expected map[string]string
	}{
		{
			name:     "OpenAI organization header",
			src:      map[string]string{"OpenAI-Organization": "org-abc123"},
			expected: map[string]string{"OpenAI-Organization": "org-abc123"},
		},
		{
			name:     "Anthropic version header",
			src:      map[string]string{"Anthropic-Version": "2024-01-01"},
			expected: map[string]string{"Anthropic-Version": "2024-01-01"},
		},
		{
			name:     "X-Request-ID header",
			src:      map[string]string{"X-Request-ID": "req-12345"},
			expected: map[string]string{"X-Request-ID": "req-12345"},
		},
		{
			name: "multiple headers",
			src: map[string]string{
				"OpenAI-Organization": "org-abc",
				"OpenAI-Project":      "proj-xyz",
				"X-Request-ID":        "req-99",
			},
			expected: map[string]string{
				"OpenAI-Organization": "org-abc",
				"OpenAI-Project":      "proj-xyz",
				"X-Request-ID":        "req-99",
			},
		},
		{
			name:     "no matching headers",
			src:      map[string]string{"Content-Type": "application/json"},
			expected: map[string]string{},
		},
	}

	compat := NewCompatLayer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := http.Header{}
			for k, v := range tt.src {
				src.Set(k, v)
			}
			dst := http.Header{}
			compat.ForwardPassthroughHeaders(src, dst)

			for k, v := range tt.expected {
				assert.Equal(t, v, dst.Get(k))
			}
			// Verify non-passthrough headers are not copied
			assert.Empty(t, dst.Get("Content-Type"))
		})
	}
}

func TestCompatLayer_MapRateLimitHeaders(t *testing.T) {
	tests := []struct {
		name        string
		provider    map[string]string
		expectKey   string
		expectValue string
	}{
		{
			name:        "standard ratelimit header passes through",
			provider:    map[string]string{"X-Ratelimit-Limit-Requests": "100"},
			expectKey:   "X-Ratelimit-Limit-Requests",
			expectValue: "100",
		},
		{
			name:        "Anthropic requests limit mapped",
			provider:    map[string]string{"Anthropic-Ratelimit-Requests-Limit": "500"},
			expectKey:   "X-Ratelimit-Limit-Requests",
			expectValue: "500",
		},
		{
			name:        "Anthropic tokens remaining mapped",
			provider:    map[string]string{"Anthropic-Ratelimit-Tokens-Remaining": "9500"},
			expectKey:   "X-Ratelimit-Remaining-Tokens",
			expectValue: "9500",
		},
	}

	compat := NewCompatLayer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerH := http.Header{}
			for k, v := range tt.provider {
				providerH.Set(k, v)
			}
			clientH := http.Header{}
			compat.MapRateLimitHeaders(providerH, clientH)
			assert.Equal(t, tt.expectValue, clientH.Get(tt.expectKey))
		})
	}
}

func TestCompatLayer_EchoRequestID(t *testing.T) {
	t.Run("echoes when present", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		r.Header.Set("X-Request-ID", "req-abc")
		w := httptest.NewRecorder()
		NewCompatLayer().EchoRequestID(r, w)
		assert.Equal(t, "req-abc", w.Header().Get("X-Request-ID"))
	})

	t.Run("no-op when absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		w := httptest.NewRecorder()
		NewCompatLayer().EchoRequestID(r, w)
		assert.Empty(t, w.Header().Get("X-Request-ID"))
	})
}

func TestCompatLayer_EnsureStreamUsage(t *testing.T) {
	t.Run("adds usage when include_usage is true and usage is nil", func(t *testing.T) {
		req := &ChatCompletionRequest{
			StreamOptions: &StreamOptions{IncludeUsage: true},
		}
		chunk := &StreamChunk{}
		NewCompatLayer().EnsureStreamUsage(req, chunk)
		require.NotNil(t, chunk.Usage)
		assert.Equal(t, 0, chunk.Usage.TotalTokens)
	})

	t.Run("preserves existing usage", func(t *testing.T) {
		req := &ChatCompletionRequest{
			StreamOptions: &StreamOptions{IncludeUsage: true},
		}
		chunk := &StreamChunk{
			Usage: &Usage{TotalTokens: 42},
		}
		NewCompatLayer().EnsureStreamUsage(req, chunk)
		assert.Equal(t, 42, chunk.Usage.TotalTokens)
	})

	t.Run("no-op when include_usage is false", func(t *testing.T) {
		req := &ChatCompletionRequest{}
		chunk := &StreamChunk{}
		NewCompatLayer().EnsureStreamUsage(req, chunk)
		assert.Nil(t, chunk.Usage)
	})

	t.Run("no-op when chunk is nil", func(t *testing.T) {
		req := &ChatCompletionRequest{
			StreamOptions: &StreamOptions{IncludeUsage: true},
		}
		NewCompatLayer().EnsureStreamUsage(req, nil)
	})
}

func TestCompatLayer_NormalizeErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantMsg    string
		wantType   string
	}{
		{
			name:       "already standard format",
			statusCode: 400,
			body:       `{"error":{"message":"bad request","type":"invalid_request_error","code":"bad_param"}}`,
			wantMsg:    "bad request",
			wantType:   "invalid_request_error",
		},
		{
			name:       "Anthropic error format",
			statusCode: 429,
			body:       `{"type":"error","error":{"type":"rate_limit_error","message":"Too many requests"}}`,
			wantMsg:    "Too many requests",
			wantType:   "rate_limit_error",
		},
		{
			name:       "flat error format",
			statusCode: 500,
			body:       `{"message":"internal failure","code":500}`,
			wantMsg:    "internal failure",
			wantType:   "server_error",
		},
		{
			name:       "plain text error",
			statusCode: 502,
			body:       `Bad Gateway`,
			wantMsg:    "Bad Gateway",
			wantType:   "server_error",
		},
		{
			name:       "empty body",
			statusCode: 503,
			body:       "",
			wantMsg:    "Service Unavailable",
			wantType:   "server_error",
		},
	}

	compat := NewCompatLayer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compat.NormalizeErrorResponse(tt.statusCode, []byte(tt.body))
			var parsed ErrorResponse
			require.NoError(t, json.Unmarshal(result, &parsed))
			assert.Equal(t, tt.wantMsg, parsed.Error.Message)
			assert.Equal(t, tt.wantType, parsed.Error.Type)
		})
	}
}

func TestMapErrorType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"not_found_error", "invalid_request_error"},
		{"authentication_error", "authentication_error"},
		{"rate_limit_error", "rate_limit_error"},
		{"overloaded_error", "server_error"},
		{"api_error", "server_error"},
		{"unknown_type", "server_error"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, mapErrorType(tt.input))
		})
	}
}

func TestHttpStatusToErrorType(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{401, "authentication_error"},
		{403, "permission_error"},
		{429, "rate_limit_error"},
		{400, "invalid_request_error"},
		{404, "invalid_request_error"},
		{500, "server_error"},
		{502, "server_error"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			assert.Equal(t, tt.want, httpStatusToErrorType(tt.code))
		})
	}
}
