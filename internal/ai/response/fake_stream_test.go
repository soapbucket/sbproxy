package response

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestFakeStream_SSEFormat(t *testing.T) {
	finishReason := "stop"
	resp := &ai.ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []ai.Choice{
			{
				Index: 0,
				Message: ai.Message{
					Role:    "assistant",
					Content: json.RawMessage(strconv.Quote("Hello world")),
				},
				FinishReason: &finishReason,
			},
		},
		Usage: &ai.Usage{
			PromptTokens:     5,
			CompletionTokens: 2,
			TotalTokens:      7,
		},
	}

	w := httptest.NewRecorder()

	err := FakeStream(context.Background(), w, resp, nil, &FakeStreamConfig{
		ChunkSize: 3,
		Interval:  1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("FakeStream failed: %v", err)
	}

	result := w.Body.String()

	// Check SSE headers
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("expected Cache-Control no-cache, got %q", cc)
	}

	// Verify SSE format: must start with "data: " lines
	lines := strings.Split(result, "\n")
	dataLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") {
			dataLines++
		}
	}
	if dataLines < 3 {
		t.Errorf("expected at least 3 data lines (role + content chunks + final + done), got %d", dataLines)
	}

	// Must end with [DONE]
	if !strings.Contains(result, "data: [DONE]") {
		t.Error("expected [DONE] terminator in SSE output")
	}
}

func TestFakeStream_UsageInFinalChunk(t *testing.T) {
	finishReason := "stop"
	resp := &ai.ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []ai.Choice{
			{
				Index: 0,
				Message: ai.Message{
					Role:    "assistant",
					Content: json.RawMessage(strconv.Quote("Hi")),
				},
				FinishReason: &finishReason,
			},
		},
		Usage: &ai.Usage{
			PromptTokens:     10,
			CompletionTokens: 1,
			TotalTokens:      11,
		},
	}

	metadata := &ai.SbMetadata{
		CostUSD:  0.001,
		Provider: "openai",
		Model:    "gpt-4o",
	}

	w := httptest.NewRecorder()
	err := FakeStream(context.Background(), w, resp, metadata, &FakeStreamConfig{
		ChunkSize: 10,
		Interval:  1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("FakeStream failed: %v", err)
	}

	// Parse SSE events to find the final chunk with usage
	body := w.Body.String()
	lines := strings.Split(body, "\n")

	var lastChunk *ai.StreamChunk
	for _, line := range lines {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			continue
		}
		var chunk ai.StreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err == nil {
			lastChunk = &chunk
		}
	}

	if lastChunk == nil {
		t.Fatal("expected to find at least one chunk")
	}

	if lastChunk.Usage == nil {
		t.Fatal("expected usage in final chunk")
	}
	if lastChunk.Usage.TotalTokens != 11 {
		t.Errorf("expected 11 total tokens in final chunk, got %d", lastChunk.Usage.TotalTokens)
	}

	if lastChunk.SbMetadata == nil {
		t.Fatal("expected sb_metadata in final chunk")
	}
	if lastChunk.SbMetadata.Provider != "openai" {
		t.Errorf("expected provider 'openai', got %q", lastChunk.SbMetadata.Provider)
	}
}

func TestFakeStream_ClientDisconnect(t *testing.T) {
	finishReason := "stop"

	// Build a long response to ensure streaming takes time
	longText := strings.Repeat("word ", 500)
	resp := &ai.ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []ai.Choice{
			{
				Index: 0,
				Message: ai.Message{
					Role:    "assistant",
					Content: json.RawMessage(strconv.Quote(longText)),
				},
				FinishReason: &finishReason,
			},
		},
	}

	// Create a cancellable context to simulate client disconnect
	ctx, cancel := context.WithCancel(context.Background())

	w := httptest.NewRecorder()

	done := make(chan error, 1)
	go func() {
		done <- FakeStream(ctx, w, resp, nil, &FakeStreamConfig{
			ChunkSize: 2,
			Interval:  10 * time.Millisecond,
		})
	}()

	// Cancel after a short delay
	time.Sleep(30 * time.Millisecond)
	cancel()

	err := <-done
	if err == nil {
		t.Error("expected error from context cancellation")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestFakeStream_EmptyResponse(t *testing.T) {
	finishReason := "stop"
	resp := &ai.ChatCompletionResponse{
		ID:      "chatcmpl-empty",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []ai.Choice{
			{
				Index: 0,
				Message: ai.Message{
					Role:    "assistant",
					Content: json.RawMessage(`""`),
				},
				FinishReason: &finishReason,
			},
		},
	}

	w := httptest.NewRecorder()
	err := FakeStream(context.Background(), w, resp, nil, &FakeStreamConfig{
		Interval: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("FakeStream failed on empty response: %v", err)
	}

	result := w.Body.String()
	if !strings.Contains(result, "data: [DONE]") {
		t.Error("expected [DONE] even for empty response")
	}
}

func TestFakeStream_HTTPStatusCode(t *testing.T) {
	resp := &ai.ChatCompletionResponse{
		ID:      "chatcmpl-test",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4o",
		Choices: []ai.Choice{
			{
				Index: 0,
				Message: ai.Message{
					Role:    "assistant",
					Content: json.RawMessage(`"ok"`),
				},
			},
		},
	}

	w := httptest.NewRecorder()
	_ = FakeStream(context.Background(), w, resp, nil, &FakeStreamConfig{
		Interval: 1 * time.Millisecond,
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
