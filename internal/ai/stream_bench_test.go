package ai

import (
	"strings"
	"testing"
)

func BenchmarkSSEParser_ReadEvent(b *testing.B) {
	// Simulate a typical OpenAI streaming response with 100 chunks
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(`data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`)
		sb.WriteString("\n\n")
	}
	sb.WriteString("data: [DONE]\n\n")
	payload := sb.String()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := NewSSEParser(strings.NewReader(payload), 0)
		for {
			event, err := parser.ReadEvent()
			if err != nil {
				break
			}
			done := IsDone(event.Data)
			ReleaseSSEEvent(event)
			if done {
				break
			}
		}
		parser.Close()
	}
}

func BenchmarkSSEParser_AnthropicEvents(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"model\":\"claude-3-5-sonnet\"}}\n\n")
	for i := 0; i < 100; i++ {
		sb.WriteString("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n")
	}
	sb.WriteString("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":50}}\n\n")
	sb.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	payload := sb.String()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := NewSSEParser(strings.NewReader(payload), 0)
		for {
			event, err := parser.ReadEvent()
			if err != nil {
				break
			}
			ReleaseSSEEvent(event)
		}
		parser.Close()
	}
}

func BenchmarkSSEParser_SingleEvent(b *testing.B) {
	payload := `data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}` + "\n\n"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := NewSSEParser(strings.NewReader(payload), 0)
		event, _ := parser.ReadEvent()
		ReleaseSSEEvent(event)
		parser.Close()
	}
}

func BenchmarkBestEffortStreamingScanThreshold(b *testing.B) {
	text := strings.Repeat("x", 64)
	chunk := &StreamChunk{
		ID:    "bench",
		Model: "gpt-4o",
		Choices: []StreamChoice{{
			Index: 0,
			Delta: StreamDelta{Content: &text},
		}},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc := NewStreamAccumulator()
		lastScan := 0
		for j := 0; j < 32; j++ {
			acc.AddChunk(chunk)
			if shouldRunBestEffortStreamingScan(chunk, acc, lastScan) {
				_ = strings.TrimSpace(acc.BuildOutputContent())
				lastScan = acc.ContentLen()
			}
		}
	}
}
