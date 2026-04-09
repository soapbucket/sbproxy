// Package response provides AI response processing utilities including fake streaming and spend metrics.
package response

import (
	"context"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/soapbucket/sbproxy/internal/ai"
)

const (
	// defaultFakeStreamChunkSize is the number of characters per chunk.
	defaultFakeStreamChunkSize = 4
	// defaultFakeStreamInterval is the delay between chunks.
	defaultFakeStreamInterval = 20 * time.Millisecond
)

// FakeStreamConfig controls the behavior of the fake streamer.
type FakeStreamConfig struct {
	// ChunkSize is the number of characters emitted per chunk. Default 4.
	ChunkSize int
	// Interval is the delay between chunks. Default 20ms.
	Interval time.Duration
}

// FakeStream converts a non-streaming ChatCompletionResponse into SSE chunks
// written to the ResponseWriter. It uses a time.NewTicker for pacing and
// respects ctx.Done() for client disconnect handling.
func FakeStream(ctx context.Context, w http.ResponseWriter, resp *ai.ChatCompletionResponse, metadata *ai.SbMetadata, cfg *FakeStreamConfig) error {
	chunkSize := defaultFakeStreamChunkSize
	interval := defaultFakeStreamInterval
	if cfg != nil {
		if cfg.ChunkSize > 0 {
			chunkSize = cfg.ChunkSize
		}
		if cfg.Interval > 0 {
			interval = cfg.Interval
		}
	}

	sw := ai.NewSSEWriter(w)
	defer ai.ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	// Extract the full text from the response
	var fullText string
	var finishReason *string
	if len(resp.Choices) > 0 {
		fullText = resp.Choices[0].Message.ContentString()
		finishReason = resp.Choices[0].FinishReason
	}

	// Send role chunk first
	roleChunk := &ai.StreamChunk{
		ID:      resp.ID,
		Object:  "chat.completion.chunk",
		Created: resp.Created,
		Model:   resp.Model,
		Choices: []ai.StreamChoice{
			{
				Index: 0,
				Delta: ai.StreamDelta{
					Role: "assistant",
				},
			},
		},
	}
	if err := sw.WriteChunk(roleChunk); err != nil {
		return err
	}

	// Stream the content in chunks using a ticker
	if fullText != "" {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		offset := 0
		for offset < len(fullText) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				// Extract next chunk, respecting UTF-8 boundaries
				end := offset
				for i := 0; i < chunkSize && end < len(fullText); i++ {
					_, size := utf8.DecodeRuneInString(fullText[end:])
					end += size
				}

				chunk := fullText[offset:end]
				offset = end

				contentChunk := &ai.StreamChunk{
					ID:      resp.ID,
					Object:  "chat.completion.chunk",
					Created: resp.Created,
					Model:   resp.Model,
					Choices: []ai.StreamChoice{
						{
							Index: 0,
							Delta: ai.StreamDelta{
								Content: &chunk,
							},
						},
					},
				}
				if err := sw.WriteChunk(contentChunk); err != nil {
					return err
				}
			}
		}
	}

	// Send the final chunk with finish_reason and usage/metadata
	finalChunk := &ai.StreamChunk{
		ID:      resp.ID,
		Object:  "chat.completion.chunk",
		Created: resp.Created,
		Model:   resp.Model,
		Choices: []ai.StreamChoice{
			{
				Index:        0,
				Delta:        ai.StreamDelta{},
				FinishReason: finishReason,
			},
		},
		Usage:      resp.Usage,
		SbMetadata: metadata,
	}
	if err := sw.WriteChunk(finalChunk); err != nil {
		return err
	}

	return sw.WriteDone()
}
