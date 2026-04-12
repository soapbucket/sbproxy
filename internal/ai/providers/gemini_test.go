package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGemini_Registration(t *testing.T) {
	p := NewGemini(http.DefaultClient)
	assert.Equal(t, "gemini", p.Name())
	assert.True(t, p.SupportsStreaming())
	assert.True(t, p.SupportsEmbeddings())
}

func TestGemini_MessageConversion(t *testing.T) {
	tests := []struct {
		name     string
		messages []ai.Message
		wantSys  string
		wantLen  int // number of contents (excluding system)
		wantRole string
	}{
		{
			name: "simple user message",
			messages: []ai.Message{
				{Role: "user", Content: json.RawMessage(`"Hello"`)},
			},
			wantLen:  1,
			wantRole: "user",
		},
		{
			name: "system message extracted",
			messages: []ai.Message{
				{Role: "system", Content: json.RawMessage(`"You are helpful."`)},
				{Role: "user", Content: json.RawMessage(`"Hi"`)},
			},
			wantSys: "You are helpful.",
			wantLen: 1,
		},
		{
			name: "assistant mapped to model",
			messages: []ai.Message{
				{Role: "user", Content: json.RawMessage(`"Hi"`)},
				{Role: "assistant", Content: json.RawMessage(`"Hello!"`)},
				{Role: "user", Content: json.RawMessage(`"How are you?"`)},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ai.ChatCompletionRequest{
				Model:    "gemini-2.5-pro",
				Messages: tt.messages,
			}
			cfg := &ai.ProviderConfig{Name: "gemini"}
			gr := convertToGeminiRequest(req, cfg)

			assert.Len(t, gr.Contents, tt.wantLen)

			if tt.wantSys != "" {
				require.NotNil(t, gr.SystemInstruction)
				assert.Equal(t, tt.wantSys, gr.SystemInstruction.Parts[0].Text)
			} else {
				assert.Nil(t, gr.SystemInstruction)
			}

			if tt.wantRole != "" {
				assert.Equal(t, tt.wantRole, gr.Contents[0].Role)
			}

			// Verify assistant -> model role mapping
			for _, c := range gr.Contents {
				assert.NotEqual(t, "assistant", c.Role, "assistant should be mapped to model")
			}
		})
	}
}

func TestGemini_SystemMessageExtraction(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(geminiResponse{
			Candidates: []geminiCandidate{{
				Content:      geminiContent{Role: "model", Parts: []geminiPart{{Text: "Hello!"}}},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsageMetadata{PromptTokenCount: 10, CandidatesTokenCount: 5, TotalTokenCount: 15},
		})
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "gemini",
		APIKey:  "test-key",
		BaseURL: server.URL,
	}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "gemini-2.5-pro",
		Messages: []ai.Message{
			{Role: "system", Content: json.RawMessage(`"You are a helpful assistant."`)},
			{Role: "user", Content: json.RawMessage(`"Hi"`)},
		},
	}, cfg)
	require.NoError(t, err)

	// Verify system instruction was extracted
	sysInstr := receivedBody["systemInstruction"].(map[string]any)
	parts := sysInstr["parts"].([]any)
	assert.Equal(t, "You are a helpful assistant.", parts[0].(map[string]any)["text"])

	// Verify only user message remains in contents
	contents := receivedBody["contents"].([]any)
	assert.Len(t, contents, 1)
	assert.Equal(t, "user", contents[0].(map[string]any)["role"])
}

func TestGemini_ChatCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/models/gemini-2.5-pro:generateContent")
		assert.Equal(t, "test-key", r.URL.Query().Get("key"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(geminiResponse{
			Candidates: []geminiCandidate{{
				Content: geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: "Hello! How can I help?"}},
				},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsageMetadata{
				PromptTokenCount:     10,
				CandidatesTokenCount: 20,
				TotalTokenCount:      30,
			},
		})
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "gemini",
		APIKey:  "test-key",
		BaseURL: server.URL,
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "gemini-2.5-pro",
		Messages: []ai.Message{
			{Role: "user", Content: json.RawMessage(`"Hello"`)},
		},
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "chat.completion", resp.Object)
	assert.Len(t, resp.Choices, 1)
	assert.Equal(t, "assistant", resp.Choices[0].Message.Role)
	assert.Equal(t, "stop", *resp.Choices[0].FinishReason)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 20, resp.Usage.CompletionTokens)
	assert.Equal(t, 30, resp.Usage.TotalTokens)
}

func TestGemini_FinishReasonMapping(t *testing.T) {
	tests := []struct {
		gemini string
		openai string
	}{
		{"STOP", "stop"},
		{"MAX_TOKENS", "length"},
		{"SAFETY", "content_filter"},
		{"RECITATION", "content_filter"},
		{"OTHER", "stop"},
		{"UNKNOWN_VALUE", "stop"},
	}
	for _, tt := range tests {
		t.Run(tt.gemini, func(t *testing.T) {
			assert.Equal(t, tt.openai, mapGeminiFinishReason(tt.gemini))
		})
	}
}

func TestGemini_ToolConversion(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(geminiResponse{
			Candidates: []geminiCandidate{{
				Content: geminiContent{
					Role: "model",
					Parts: []geminiPart{{
						FunctionCall: &geminiFunctionCall{
							Name: "get_weather",
							Args: json.RawMessage(`{"location":"NYC"}`),
						},
					}},
				},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsageMetadata{PromptTokenCount: 20, CandidatesTokenCount: 10, TotalTokenCount: 30},
		})
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{
		Name:    "gemini",
		APIKey:  "test-key",
		BaseURL: server.URL,
	}

	resp, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model: "gemini-2.5-pro",
		Messages: []ai.Message{
			{Role: "user", Content: json.RawMessage(`"What's the weather in NYC?"`)},
		},
		Tools: []ai.Tool{{
			Type: "function",
			Function: ai.ToolFunction{
				Name:        "get_weather",
				Description: "Get weather for a location",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"location":{"type":"string"}}}`),
			},
		}},
	}, cfg)

	require.NoError(t, err)

	// Verify response has tool calls in OpenAI format
	require.Len(t, resp.Choices, 1)
	require.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	tc := resp.Choices[0].Message.ToolCalls[0]
	assert.Equal(t, "function", tc.Type)
	assert.Equal(t, "get_weather", tc.Function.Name)
	assert.Equal(t, `{"location":"NYC"}`, tc.Function.Arguments)

	// Verify tools were converted to Gemini format in the request
	tools := receivedBody["tools"].([]any)
	require.Len(t, tools, 1)
	toolContainer := tools[0].(map[string]any)
	decls := toolContainer["functionDeclarations"].([]any)
	require.Len(t, decls, 1)
	decl := decls[0].(map[string]any)
	assert.Equal(t, "get_weather", decl["name"])
	assert.Equal(t, "Get weather for a location", decl["description"])
}

func TestGemini_ResponseConversion(t *testing.T) {
	resp := &geminiResponse{
		Candidates: []geminiCandidate{
			{
				Content: geminiContent{
					Role:  "model",
					Parts: []geminiPart{{Text: "Part 1"}, {Text: "Part 2"}},
				},
				FinishReason: "STOP",
			},
		},
		UsageMetadata: &geminiUsageMetadata{
			PromptTokenCount:        10,
			CandidatesTokenCount:    20,
			TotalTokenCount:         30,
			CachedContentTokenCount: 5,
		},
	}

	result := convertGeminiResponse(resp, "gemini-2.5-pro")

	assert.Equal(t, "chat.completion", result.Object)
	assert.Equal(t, "gemini-2.5-pro", result.Model)
	require.Len(t, result.Choices, 1)
	assert.Equal(t, "assistant", result.Choices[0].Message.Role)

	// Content should be concatenated
	var content string
	json.Unmarshal(result.Choices[0].Message.Content, &content)
	assert.Equal(t, "Part 1Part 2", content)

	// Usage with cached tokens
	assert.Equal(t, 10, result.Usage.PromptTokens)
	assert.Equal(t, 20, result.Usage.CompletionTokens)
	assert.Equal(t, 30, result.Usage.TotalTokens)
	assert.Equal(t, 5, result.Usage.PromptTokensCached)
}

func TestGemini_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, ":streamGenerateContent")
		assert.Equal(t, "sse", r.URL.Query().Get("alt"))

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hello"}]},"finishReason":""}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":1,"totalTokenCount":11}}`,
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":" world"}]},"finishReason":""}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"totalTokenCount":12}}`,
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"!"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":3,"totalTokenCount":13}}`,
		}
		for _, event := range events {
			w.Write([]byte(event + "\n\n"))
			flusher.Flush()
		}
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{Name: "gemini", APIKey: "test-key", BaseURL: server.URL}

	stream, err := p.ChatCompletionStream(t.Context(), &ai.ChatCompletionRequest{
		Model:    "gemini-2.5-pro",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)
	require.NoError(t, err)
	defer stream.Close()

	// First chunk should have role
	chunk, err := stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)
	assert.Equal(t, "Hello", *chunk.Choices[0].Delta.Content)

	// Second chunk
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, " world", *chunk.Choices[0].Delta.Content)

	// Third chunk with finish reason
	chunk, err = stream.Read()
	require.NoError(t, err)
	assert.Equal(t, "!", *chunk.Choices[0].Delta.Content)
	assert.Equal(t, "stop", *chunk.Choices[0].FinishReason)

	// EOF
	_, err = stream.Read()
	assert.Equal(t, io.EOF, err)
}

func TestGemini_Embeddings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, ":embedContent")

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		assert.Equal(t, "models/text-embedding-004", req["model"])

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"embedding":{"values":[0.1,0.2,0.3]}}`))
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{Name: "gemini", APIKey: "test-key", BaseURL: server.URL}

	resp, err := p.Embeddings(t.Context(), &ai.EmbeddingRequest{
		Input: "Hello world",
		Model: "text-embedding-004",
	}, cfg)

	require.NoError(t, err)
	assert.Equal(t, "list", resp.Object)
	require.Len(t, resp.Data, 1)
	assert.Equal(t, []float32{0.1, 0.2, 0.3}, resp.Data[0].Embedding)
}

func TestGemini_ListModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/models", r.URL.Path)
		assert.Equal(t, "test-key", r.URL.Query().Get("key"))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"models":[{"name":"models/gemini-2.5-pro","displayName":"Gemini 2.5 Pro"},{"name":"models/gemini-2.5-flash","displayName":"Gemini 2.5 Flash"}]}`))
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{Name: "gemini", APIKey: "test-key", BaseURL: server.URL}

	models, err := p.ListModels(t.Context(), cfg)
	require.NoError(t, err)
	assert.Len(t, models, 2)
	assert.Equal(t, "gemini-2.5-pro", models[0].ID)
	assert.Equal(t, "gemini-2.5-flash", models[1].ID)
	assert.Equal(t, "google", models[0].OwnedBy)
}

func TestGemini_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":400,"message":"Invalid model name","status":"INVALID_ARGUMENT"}}`))
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{Name: "gemini", APIKey: "test-key", BaseURL: server.URL}

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "bad-model",
		Messages: []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
	}, cfg)

	require.Error(t, err)
	aiErr, ok := err.(*ai.AIError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, aiErr.StatusCode)
	assert.Equal(t, "INVALID_ARGUMENT", aiErr.Type)
	assert.Equal(t, "Invalid model name", aiErr.Message)
}

func TestGemini_ModelPrefixHandling(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"gemini-2.5-pro", "gemini-2.5-pro"},
		{"models/gemini-2.5-pro", "gemini-2.5-pro"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveGeminiModel(tt.input))
		})
	}
}

func TestGemini_GenerationConfig(t *testing.T) {
	var receivedBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(geminiResponse{
			Candidates: []geminiCandidate{{
				Content:      geminiContent{Role: "model", Parts: []geminiPart{{Text: "ok"}}},
				FinishReason: "STOP",
			}},
			UsageMetadata: &geminiUsageMetadata{TotalTokenCount: 5},
		})
	}))
	defer server.Close()

	p := NewGemini(server.Client())
	cfg := &ai.ProviderConfig{Name: "gemini", APIKey: "test-key", BaseURL: server.URL}

	temp := 0.7
	topP := 0.9
	maxTokens := 1024

	_, err := p.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:       "gemini-2.5-pro",
		Messages:    []ai.Message{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		Temperature: &temp,
		TopP:        &topP,
		MaxTokens:   &maxTokens,
		Stop:        json.RawMessage(`["STOP1","STOP2"]`),
	}, cfg)
	require.NoError(t, err)

	genCfg := receivedBody["generationConfig"].(map[string]any)
	assert.Equal(t, 0.7, genCfg["temperature"])
	assert.Equal(t, 0.9, genCfg["topP"])
	assert.Equal(t, float64(1024), genCfg["maxOutputTokens"])
	stops := genCfg["stopSequences"].([]any)
	assert.Len(t, stops, 2)
	assert.Equal(t, "STOP1", stops[0])
	assert.Equal(t, "STOP2", stops[1])
}
