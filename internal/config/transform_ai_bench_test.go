package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func makeOpenAIResponse(promptTokens, completionTokens int) []byte {
	resp := map[string]interface{}{
		"id":     "chatcmpl-test",
		"object": "chat.completion",
		"model":  "gpt-4o",
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": strings.Repeat("word ", completionTokens/2),
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     promptTokens,
			"completion_tokens": completionTokens,
			"total_tokens":      promptTokens + completionTokens,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func makeOpenAIRequest(messageWords int) []byte {
	req := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": strings.Repeat("word ", messageWords)},
		},
	}
	b, _ := json.Marshal(req)
	return b
}

func makeSSEBody(events int) []byte {
	var buf bytes.Buffer
	for i := 0; i < events; i++ {
		chunk := fmt.Sprintf(`{"id":"chatcmpl-%d","choices":[{"delta":{"content":"word "}}]}`, i)
		fmt.Fprintf(&buf, "data: %s\n\n", chunk)
	}
	buf.WriteString("data: [DONE]\n\n")
	return buf.Bytes()
}

func BenchmarkTokenCount(b *testing.B) {
	sizes := []struct {
		name   string
		prompt int
		comp   int
	}{
		{"small", 100, 50},
		{"medium", 1000, 500},
		{"large", 5000, 2000},
	}

	cfgData, _ := json.Marshal(map[string]string{"type": "token_count", "provider": "openai"})

	for _, s := range sizes {
		body := makeOpenAIResponse(s.prompt, s.comp)
		b.Run(s.name, func(b *testing.B) {
			cfg, err := NewTokenCountTransform(cfgData)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp := benchResponse(body, "application/json")
				cfg.Apply(resp)
				io.ReadAll(resp.Body)
			}
		})
	}
}

func BenchmarkCostEstimate(b *testing.B) {
	body := makeOpenAIResponse(1000, 500)
	cfgData, _ := json.Marshal(map[string]string{"type": "cost_estimate", "provider": "openai"})
	cfg, err := NewCostEstimateTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		// Pre-set token headers as if token_count ran first
		resp.Header.Set("X-Token-Count-Prompt", "1000")
		resp.Header.Set("X-Token-Count-Completion", "500")
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

func BenchmarkAISchema_Validate(b *testing.B) {
	body := makeOpenAIResponse(100, 50)
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":     "ai_schema",
		"provider": "openai",
		"action":   "validate",
	})
	cfg, err := NewAISchemaTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "application/json")
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

func BenchmarkAICache_Miss(b *testing.B) {
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type": "ai_cache",
		"ttl":  300,
	})
	cfg, err := NewAICacheTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Each iteration uses unique request body for cache miss
		reqBody := makeOpenAIRequest(10 + i%100)
		body := makeOpenAIResponse(100, 50)

		req, _ := http.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

func BenchmarkAICache_Hit(b *testing.B) {
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type": "ai_cache",
		"ttl":  300,
	})
	cfg, err := NewAICacheTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}

	// Prime the cache with one entry
	reqBody := makeOpenAIRequest(10)
	body := makeOpenAIResponse(100, 50)
	req, _ := http.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
	cfg.Apply(resp)
	io.ReadAll(resp.Body)

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}

func BenchmarkSSEChunking(b *testing.B) {
	sizes := []int{10, 50, 200}
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":     "sse_chunking",
		"provider": "openai",
	})

	for _, events := range sizes {
		body := makeSSEBody(events)
		b.Run(fmt.Sprintf("events=%d", events), func(b *testing.B) {
			cfg, err := NewSSEChunkingTransform(cfgData)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp := benchResponse(body, "text/event-stream")
				cfg.Apply(resp)
				io.ReadAll(resp.Body)
			}
		})
	}
}

func BenchmarkSSEChunking_WithFilter(b *testing.B) {
	body := makeSSEBody(100)
	cfgData, _ := json.Marshal(map[string]interface{}{
		"type":          "sse_chunking",
		"filter_events": []string{"ping", "heartbeat"},
	})
	cfg, err := NewSSEChunkingTransform(cfgData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := benchResponse(body, "text/event-stream")
		cfg.Apply(resp)
		io.ReadAll(resp.Body)
	}
}
