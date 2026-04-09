// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bufio"
	"bytes"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"net/http"
	"strings"
	"sync"
)

var sseEventPool = sync.Pool{
	New: func() any { return &SSEEvent{} },
}

var scannerBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

var sseWriterPool = sync.Pool{
	New: func() any { return &SSEWriter{} },
}

// SSEEvent represents a parsed Server-Sent Event.
type SSEEvent struct {
	Event string // event type (e.g., "message_start" for Anthropic)
	Data  string // data payload
	ID    string // event id
}

// ReleaseSSEEvent returns an SSEEvent to the pool for reuse.
func ReleaseSSEEvent(evt *SSEEvent) {
	if evt == nil {
		return
	}
	evt.Event = ""
	evt.Data = ""
	evt.ID = ""
	sseEventPool.Put(evt)
}

// SSEParser reads SSE events from an io.Reader.
// It handles both OpenAI format (data-only) and Anthropic format (event + data).
type SSEParser struct {
	scanner   *bufio.Scanner
	event     string // accumulated event type
	data      strings.Builder
	id        string
	pooledBuf bool
	buf       []byte
}

// NewSSEParser creates a new SSE parser.
// bufSize controls the scanner buffer size (default 64KB if 0).
func NewSSEParser(r io.Reader, bufSize int) *SSEParser {
	if bufSize <= 0 {
		bufSize = 64 * 1024
	}
	var buf []byte
	pooled := false
	if bufSize == 64*1024 {
		bp := scannerBufPool.Get().(*[]byte)
		buf = *bp
		pooled = true
	} else {
		buf = make([]byte, bufSize)
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(buf, bufSize)
	return &SSEParser{
		scanner:   scanner,
		pooledBuf: pooled,
		buf:       buf,
	}
}

// Close returns pooled resources. Must be called when done with the parser.
func (p *SSEParser) Close() {
	if p.pooledBuf && p.buf != nil {
		bp := &p.buf
		scannerBufPool.Put(bp)
		p.buf = nil
	}
}

// ReadEvent reads the next SSE event. Returns io.EOF when the stream ends.
// Per the SSE spec, an event is dispatched when a blank line is encountered.
func (p *SSEParser) ReadEvent() (*SSEEvent, error) {
	p.event = ""
	p.data.Reset()
	p.id = ""
	hasData := false

	for p.scanner.Scan() {
		line := p.scanner.Text()

		// Blank line = dispatch event
		if line == "" {
			if !hasData {
				continue // skip empty events
			}
			data := p.data.String()
			// Remove trailing newline if present
			if len(data) > 0 && data[len(data)-1] == '\n' {
				data = data[:len(data)-1]
			}
			evt := sseEventPool.Get().(*SSEEvent)
			evt.Event = p.event
			evt.Data = data
			evt.ID = p.id
			return evt, nil
		}

		// Comment lines start with ':'
		if line[0] == ':' {
			continue
		}

		// Parse field:value
		field, value, _ := strings.Cut(line, ":")
		// Per spec, strip single leading space from value
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}

		switch field {
		case "event":
			p.event = value
		case "data":
			hasData = true
			if p.data.Len() > 0 {
				p.data.WriteByte('\n')
			}
			p.data.WriteString(value)
		case "id":
			p.id = value
		case "retry":
			// ignored
		}
	}

	if err := p.scanner.Err(); err != nil {
		return nil, fmt.Errorf("sse scanner: %w", err)
	}
	return nil, io.EOF
}

// IsDone returns true if the SSE data indicates end of stream.
func IsDone(data string) bool {
	return data == "[DONE]"
}

// SSEWriter writes OpenAI-format SSE events to an http.ResponseWriter.
type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	buf     bytes.Buffer
}

// NewSSEWriter creates a new SSE writer. The ResponseWriter must support http.Flusher.
func NewSSEWriter(w http.ResponseWriter) *SSEWriter {
	flusher, _ := w.(http.Flusher)
	sw := sseWriterPool.Get().(*SSEWriter)
	sw.w = w
	sw.flusher = flusher
	sw.buf.Reset()
	return sw
}

// ReleaseSSEWriter returns the SSEWriter to the pool for reuse.
func ReleaseSSEWriter(sw *SSEWriter) {
	if sw == nil {
		return
	}
	sw.w = nil
	sw.flusher = nil
	sw.buf.Reset()
	sseWriterPool.Put(sw)
}

// WriteHeaders sets the SSE response headers.
func (sw *SSEWriter) WriteHeaders() {
	sw.w.Header().Set("Content-Type", "text/event-stream")
	sw.w.Header().Set("Cache-Control", "no-cache")
	sw.w.Header().Set("Connection", "keep-alive")
	sw.w.Header().Set("X-Accel-Buffering", "no")
	sw.w.WriteHeader(http.StatusOK)
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
}

// WriteChunk writes a StreamChunk as an SSE event.
func (sw *SSEWriter) WriteChunk(chunk *StreamChunk) error {
	sw.buf.Reset()
	sw.buf.WriteString("data: ")
	if err := json.NewEncoder(&sw.buf).Encode(chunk); err != nil {
		return fmt.Errorf("marshal stream chunk: %w", err)
	}
	// json.Encoder adds \n, SSE needs \n\n
	sw.buf.WriteByte('\n')

	if _, err := sw.w.Write(sw.buf.Bytes()); err != nil {
		return fmt.Errorf("write sse chunk: %w", err)
	}
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}

// WriteDone writes the [DONE] terminator.
func (sw *SSEWriter) WriteDone() error {
	_, err := fmt.Fprint(sw.w, "data: [DONE]\n\n")
	if err != nil {
		return err
	}
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}

// WriteComment writes an SSE comment line.
func (sw *SSEWriter) WriteComment(comment string) error {
	if _, err := fmt.Fprintf(sw.w, ": %s\n\n", comment); err != nil {
		return err
	}
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}

// WriteEvent writes a structured SSE event preserving the event name.
func (sw *SSEWriter) WriteEvent(evt *SSEEvent) error {
	if evt == nil {
		return nil
	}
	sw.buf.Reset()
	if evt.Event != "" {
		sw.buf.WriteString("event: ")
		sw.buf.WriteString(evt.Event)
		sw.buf.WriteByte('\n')
	}
	if evt.ID != "" {
		sw.buf.WriteString("id: ")
		sw.buf.WriteString(evt.ID)
		sw.buf.WriteByte('\n')
	}
	for _, line := range strings.Split(evt.Data, "\n") {
		sw.buf.WriteString("data: ")
		sw.buf.WriteString(line)
		sw.buf.WriteByte('\n')
	}
	sw.buf.WriteByte('\n')
	if _, err := sw.w.Write(sw.buf.Bytes()); err != nil {
		return err
	}
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}

// WriteRaw writes raw SSE data directly (for passthrough mode).
func (sw *SSEWriter) WriteRaw(data []byte) error {
	if _, err := sw.w.Write(data); err != nil {
		return err
	}
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}

// WriteError writes an error as the final SSE event.
func (sw *SSEWriter) WriteError(aiErr *AIError) error {
	sw.buf.Reset()
	sw.buf.WriteString("data: ")
	errResp := ErrorResponse{Error: *aiErr}
	if err := json.NewEncoder(&sw.buf).Encode(errResp); err != nil {
		return err
	}
	sw.buf.WriteByte('\n')
	if _, err := sw.w.Write(sw.buf.Bytes()); err != nil {
		return err
	}
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}
