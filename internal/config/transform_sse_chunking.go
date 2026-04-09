// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformSSEChunking] = NewSSEChunkingTransform
}

// SSEChunkingTransformConfig is the runtime config for SSE stream processing.
type SSEChunkingTransformConfig struct {
	SSEChunkingTransform

	filterSet map[string]bool
}

// NewSSEChunkingTransform creates a new SSE chunking transformer.
func NewSSEChunkingTransform(data []byte) (TransformConfig, error) {
	cfg := &SSEChunkingTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("sse_chunking: %w", err)
	}

	if cfg.Provider == "" {
		cfg.Provider = "generic"
	}

	// Build filter set for O(1) lookup
	cfg.filterSet = make(map[string]bool, len(cfg.FilterEvents))
	for _, event := range cfg.FilterEvents {
		cfg.filterSet[event] = true
	}

	cfg.tr = transformer.Func(cfg.processSSE)

	return cfg, nil
}

func (c *SSEChunkingTransformConfig) processSSE(resp *http.Response) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		// Not an SSE stream — pass through
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Parse and process SSE events
	events := parseSSEEvents(body)
	chunkCount := len(events)

	// Filter events if configured
	if len(c.filterSet) > 0 {
		var filtered []sseEvent
		for _, event := range events {
			if !c.filterSet[event.eventType] {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	// Reconstruct SSE body
	var buf bytes.Buffer
	for _, event := range events {
		if event.eventType != "" {
			buf.WriteString("event: ")
			buf.WriteString(event.eventType)
			buf.WriteByte('\n')
		}
		if event.data != "" {
			buf.WriteString("data: ")
			buf.WriteString(event.data)
			buf.WriteByte('\n')
		}
		buf.WriteByte('\n')
	}

	result := buf.Bytes()
	resp.Body = io.NopCloser(bytes.NewReader(result))
	resp.Header.Set("Content-Length", strconv.Itoa(len(result)))
	resp.Header.Set("X-Stream-Chunks", strconv.Itoa(chunkCount))

	return nil
}

type sseEvent struct {
	eventType string
	data      string
}

func parseSSEEvents(body []byte) []sseEvent {
	var events []sseEvent
	var current sseEvent
	var dataLines []string

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")

		if line == "" {
			// Empty line marks end of event
			if len(dataLines) > 0 {
				current.data = strings.Join(dataLines, "\n")
				events = append(events, current)
				current = sseEvent{}
				dataLines = nil
			}
			continue
		}

		if strings.HasPrefix(line, "event:") {
			current.eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}

	// Handle trailing event without final newline
	if len(dataLines) > 0 {
		current.data = strings.Join(dataLines, "\n")
		events = append(events, current)
	}

	return events
}
