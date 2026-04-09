package config

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/pricing"
)

// --- Token Count Tests ---

func TestTokenCountTransform_OpenAIUsage(t *testing.T) {
	configJSON := `{"type":"token_count","provider":"openai"}`

	tc, err := NewTokenCountTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"id":"chatcmpl-123","choices":[{"message":{"content":"Hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Token-Count-Prompt") != "10" {
		t.Errorf("expected prompt tokens 10, got %s", resp.Header.Get("X-Token-Count-Prompt"))
	}
	if resp.Header.Get("X-Token-Count-Completion") != "5" {
		t.Errorf("expected completion tokens 5, got %s", resp.Header.Get("X-Token-Count-Completion"))
	}
	if resp.Header.Get("X-Token-Count-Total") != "15" {
		t.Errorf("expected total tokens 15, got %s", resp.Header.Get("X-Token-Count-Total"))
	}
}

func TestTokenCountTransform_AnthropicUsage(t *testing.T) {
	configJSON := `{"type":"token_count","provider":"anthropic"}`

	tc, err := NewTokenCountTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"id":"msg_123","content":[{"type":"text","text":"Hello"}],"usage":{"input_tokens":20,"output_tokens":8}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Token-Count-Prompt") != "20" {
		t.Errorf("expected input tokens 20, got %s", resp.Header.Get("X-Token-Count-Prompt"))
	}
	if resp.Header.Get("X-Token-Count-Completion") != "8" {
		t.Errorf("expected output tokens 8, got %s", resp.Header.Get("X-Token-Count-Completion"))
	}
}

func TestTokenCountTransform_EstimateFromContent(t *testing.T) {
	configJSON := `{"type":"token_count","provider":"openai"}`

	tc, err := NewTokenCountTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	// No usage object, just content
	body := `{"choices":[{"message":{"content":"This is a test response with some words"}}]}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	estimated := resp.Header.Get("X-Token-Count-Estimated")
	if estimated == "" {
		t.Error("expected estimated token count when no usage object")
	}
	n, _ := strconv.Atoi(estimated)
	if n <= 0 {
		t.Errorf("estimated tokens should be positive, got %d", n)
	}
}

func TestTokenCountTransform_CustomHeaderPrefix(t *testing.T) {
	configJSON := `{"type":"token_count","header_prefix":"X-Tokens"}`

	tc, err := NewTokenCountTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Tokens-Total") != "8" {
		t.Errorf("expected custom header prefix, got headers: %v", resp.Header)
	}
}

// --- Cost Estimate Tests ---

func TestCostEstimateTransform_OpenAI(t *testing.T) {
	// Set up pricing source (pricing is file-based, so we set an override for the test).
	src := pricing.NewSource(&pricing.SourceConfig{
		Overrides: map[string]*pricing.ModelPricing{
			"gpt-4o": {InputPerMToken: 2.50, OutputPerMToken: 10.00},
		},
	})
	pricing.SetGlobal(src)
	defer pricing.SetGlobal(nil)

	configJSON := `{"type":"cost_estimate","provider":"openai","model":"gpt-4o"}`

	tc, err := NewCostEstimateTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cost := resp.Header.Get("X-Estimated-Cost")
	if cost == "" {
		t.Fatal("expected X-Estimated-Cost header")
	}

	costVal, _ := strconv.ParseFloat(cost, 64)
	if costVal <= 0 {
		t.Errorf("cost should be positive, got %f", costVal)
	}

	if resp.Header.Get("X-Estimated-Cost-Currency") != "USD" {
		t.Error("expected USD currency")
	}
}

func TestCostEstimateTransform_CustomPricing(t *testing.T) {
	configJSON := `{"type":"cost_estimate","pricing_map":{"input":1.0,"output":2.0}}`

	tc, err := NewCostEstimateTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"usage":{"prompt_tokens":1000000,"completion_tokens":1000000}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cost := resp.Header.Get("X-Estimated-Cost")
	// 1M input @ $1/M + 1M output @ $2/M = $3
	costVal, _ := strconv.ParseFloat(cost, 64)
	if costVal < 2.9 || costVal > 3.1 {
		t.Errorf("expected cost ~3.0, got %f", costVal)
	}
}

func TestCostEstimateTransform_FromHeaders(t *testing.T) {
	configJSON := `{"type":"cost_estimate","pricing_map":{"input":10.0,"output":30.0}}`

	tc, err := NewCostEstimateTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"data":"no usage object"}`
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":          []string{"application/json"},
			"X-Token-Count-Prompt":     []string{"100"},
			"X-Token-Count-Completion": []string{"50"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cost := resp.Header.Get("X-Estimated-Cost")
	if cost == "" {
		t.Fatal("expected cost from token count headers")
	}
}

// --- AI Schema Tests ---

func TestAISchemaTransform_ValidOpenAI(t *testing.T) {
	configJSON := `{"type":"ai_schema","provider":"openai","action":"validate"}`

	tc, err := NewAISchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"id":"chatcmpl-123","object":"chat.completion","model":"gpt-4","choices":[{"message":{"role":"assistant","content":"Hello"}}]}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("valid OpenAI response should pass, got %d", resp.StatusCode)
	}
}

func TestAISchemaTransform_InvalidOpenAI(t *testing.T) {
	configJSON := `{"type":"ai_schema","provider":"openai","action":"validate"}`

	tc, err := NewAISchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"data":"not an OpenAI response"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("invalid OpenAI response should be rejected, got %d", resp.StatusCode)
	}
}

func TestAISchemaTransform_FixMode(t *testing.T) {
	configJSON := `{"type":"ai_schema","provider":"anthropic","action":"fix"}`

	tc, err := NewAISchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	// Missing type, role, and content fields
	body := `{"id":"msg_123","model":"claude-3"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(result, []byte(`"type"`)) {
		t.Error("fix mode should add missing 'type' field")
	}
	if !bytes.Contains(result, []byte(`"role"`)) {
		t.Error("fix mode should add missing 'role' field")
	}
	if resp.Header.Get("X-AI-Schema-Fixed") != "true" {
		t.Error("expected X-AI-Schema-Fixed header")
	}
}

func TestAISchemaTransform_WarnMode(t *testing.T) {
	configJSON := `{"type":"ai_schema","provider":"openai","action":"warn"}`

	tc, err := NewAISchemaTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"data":"incomplete"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("warn mode should keep 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-AI-Schema-Valid") != "false" {
		t.Error("expected X-AI-Schema-Valid: false header")
	}
}

// --- AI Cache Tests ---

func TestAICacheTransform_CacheHitMiss(t *testing.T) {
	configJSON := `{"type":"ai_cache","ttl":60}`

	tc, err := NewAICacheTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`

	// First call — cache miss
	req1 := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	body1 := `{"choices":[{"message":{"content":"Hi!"}}]}`
	resp1 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body1))),
		Request:    req1,
	}

	if err := tc.Apply(resp1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp1.Header.Get("X-Cache") != "MISS" {
		t.Errorf("first call should be MISS, got %s", resp1.Header.Get("X-Cache"))
	}

	// Second call with same body — cache hit
	req2 := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	body2 := `{"choices":[{"message":{"content":"Different response"}}]}`
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body2))),
		Request:    req2,
	}

	if err := tc.Apply(resp2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp2.Header.Get("X-Cache") != "HIT" {
		t.Errorf("second call should be HIT, got %s", resp2.Header.Get("X-Cache"))
	}

	// Verify cached response body
	result, _ := io.ReadAll(resp2.Body)
	if !bytes.Contains(result, []byte("Hi!")) {
		t.Errorf("cached response should contain original body, got: %s", string(result))
	}
}

func TestAICacheTransform_SkipStreaming(t *testing.T) {
	configJSON := `{"type":"ai_cache","ttl":60,"skip_streaming":true}`

	tc, err := NewAICacheTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("data: test\n\n"))),
		Request:    req,
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should NOT set cache header
	if resp.Header.Get("X-Cache") != "" {
		t.Error("streaming responses should be skipped")
	}
}

// --- SSE Chunking Tests ---

func TestSSEChunkingTransform_ParseEvents(t *testing.T) {
	configJSON := `{"type":"sse_chunking","provider":"openai"}`

	tc, err := NewSSEChunkingTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	sseBody := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: [DONE]\n\n"
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(sseBody))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Stream-Chunks") != "3" {
		t.Errorf("expected 3 chunks, got %s", resp.Header.Get("X-Stream-Chunks"))
	}
}

func TestSSEChunkingTransform_FilterEvents(t *testing.T) {
	configJSON := `{"type":"sse_chunking","filter_events":["ping","heartbeat"]}`

	tc, err := NewSSEChunkingTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	sseBody := "event: message\ndata: hello\n\nevent: ping\ndata: keepalive\n\nevent: message\ndata: world\n\n"
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(sseBody))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if bytes.Contains(result, []byte("ping")) {
		t.Errorf("filtered event should be removed: %s", string(result))
	}
	if !bytes.Contains(result, []byte("hello")) {
		t.Error("non-filtered events should be preserved")
	}
}

func TestSSEChunkingTransform_NonSSEPassthrough(t *testing.T) {
	configJSON := `{"type":"sse_chunking"}`

	tc, err := NewSSEChunkingTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	body := `{"data":"regular json"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should pass through unchanged
	result, _ := io.ReadAll(resp.Body)
	if string(result) != body {
		t.Errorf("non-SSE body should pass through, got: %s", string(result))
	}
}

// --- Invalid Config Tests ---

func TestAITransform_InvalidConfigs(t *testing.T) {
	tests := []struct {
		name        string
		constructor func([]byte) (TransformConfig, error)
		json        string
	}{
		{"ai_schema invalid action", NewAISchemaTransform, `{"type":"ai_schema","action":"bad"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.constructor([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}
