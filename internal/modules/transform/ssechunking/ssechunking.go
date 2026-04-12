// Package ssechunking registers the sse_chunking transform.
package ssechunking

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("sse_chunking", New)
}

// Config holds configuration for the sse_chunking transform.
type Config struct {
	Type         string   `json:"type"`
	Provider     string   `json:"provider,omitempty"`
	FilterEvents []string `json:"filter_events,omitempty"`
	BufferChunks int      `json:"buffer_chunks,omitempty"`
}

// sseChunkingTransform implements plugin.TransformHandler.
type sseChunkingTransform struct {
	provider  string
	filterSet map[string]bool
}

// New creates a new sse_chunking transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("sse_chunking: %w", err)
	}

	if cfg.Provider == "" {
		cfg.Provider = "generic"
	}

	filterSet := make(map[string]bool, len(cfg.FilterEvents))
	for _, event := range cfg.FilterEvents {
		filterSet[event] = true
	}

	return &sseChunkingTransform{
		provider:  cfg.Provider,
		filterSet: filterSet,
	}, nil
}

func (c *sseChunkingTransform) Type() string { return "sse_chunking" }
func (c *sseChunkingTransform) Apply(resp *http.Response) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
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

	events := parseSSEEvents(body)
	chunkCount := len(events)

	if len(c.filterSet) > 0 {
		var filtered []sseEvent
		for _, event := range events {
			if !c.filterSet[event.eventType] {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

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

	if len(dataLines) > 0 {
		current.data = strings.Join(dataLines, "\n")
		events = append(events, current)
	}

	return events
}
