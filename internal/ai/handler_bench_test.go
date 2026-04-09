package ai

import (
	"bytes"
	jsonstd "encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkHandlerChatCompletionNonStreaming(b *testing.B) {
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
	}

	payload, err := jsonstd.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "Hi"},
		},
	})
	if err != nil {
		b.Fatalf("marshal benchmark payload: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
}

func BenchmarkHandlerChatCompletionStreaming(b *testing.B) {
	b.ReportAllocs()

	text1 := "Hello"
	text2 := " world"
	finishReason := "stop"
	mp := &mockProvider{
		name: "bench",
		streamChunks: []*StreamChunk{
			{
				ID:     "bench-stream",
				Object: "chat.completion.chunk",
				Model:  "gpt-4o",
				Choices: []StreamChoice{{
					Index: 0,
					Delta: StreamDelta{Role: "assistant", Content: &text1},
				}},
			},
			{
				ID:     "bench-stream",
				Object: "chat.completion.chunk",
				Model:  "gpt-4o",
				Choices: []StreamChoice{{
					Index:        0,
					Delta:        StreamDelta{Content: &text2},
					FinishReason: &finishReason,
				}},
				Usage: &Usage{PromptTokens: 12, CompletionTokens: 8, TotalTokens: 20},
			},
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
	}

	payload, err := jsonstd.Marshal(map[string]any{
		"model":  "gpt-4o",
		"stream": true,
		"messages": []map[string]any{
			{"role": "user", "content": "Hi"},
		},
	})
	if err != nil {
		b.Fatalf("marshal benchmark payload: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
}
