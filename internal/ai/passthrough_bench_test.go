package ai

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkPassthroughForward(b *testing.B) {
	b.ReportAllocs()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"bench","choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	cfg := &ProviderConfig{Name: "bench", BaseURL: upstream.URL, APIKey: "sk-bench"}
	providers := []*ProviderConfig{cfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Passthrough:        &PassthroughConfig{Enabled: true},
		},
		providers: map[string]providerEntry{
			cfg.Name: {provider: &mockProvider{name: "bench"}, config: cfg},
		},
		router: NewRouter(nil, providers),
		client: upstream.Client(),
	}

	payload := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SB-Passthrough", "true")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
}

func BenchmarkPassthroughVsStandard(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"bench","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`))
	}))
	defer upstream.Close()

	payload := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`)

	b.Run("passthrough", func(b *testing.B) {
		b.ReportAllocs()

		cfg := &ProviderConfig{Name: "bench", BaseURL: upstream.URL, APIKey: "sk-bench"}
		providers := []*ProviderConfig{cfg}
		h := &Handler{
			config: &HandlerConfig{
				Providers:          providers,
				MaxRequestBodySize: 10 * 1024 * 1024,
				Passthrough:        &PassthroughConfig{Enabled: true},
			},
			providers: map[string]providerEntry{
				cfg.Name: {provider: &mockProvider{name: "bench"}, config: cfg},
			},
			router: NewRouter(nil, providers),
			client: upstream.Client(),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-SB-Passthrough", "true")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
		}
	})

	b.Run("standard", func(b *testing.B) {
		b.ReportAllocs()

		finishReason := "stop"
		mp := &mockProvider{
			name: "bench",
			chatResp: &ChatCompletionResponse{
				ID:      "bench-chat",
				Object:  "chat.completion",
				Created: 1700000000,
				Model:   "gpt-4o",
				Choices: []Choice{{
					Index:        0,
					Message:      Message{Role: "assistant", Content: []byte(`"Hello!"`)},
					FinishReason: &finishReason,
				}},
				Usage: &Usage{PromptTokens: 12, CompletionTokens: 8, TotalTokens: 20},
			},
		}

		cfg := &ProviderConfig{Name: "bench"}
		providers := []*ProviderConfig{cfg}
		h := &Handler{
			config: &HandlerConfig{
				Providers:          providers,
				MaxRequestBodySize: 10 * 1024 * 1024,
			},
			providers: map[string]providerEntry{
				cfg.Name: {provider: mp, config: cfg},
			},
			router: NewRouter(nil, providers),
			client: upstream.Client(),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
		}
	})
}
