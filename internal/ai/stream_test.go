package ai

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSEParser_OpenAIFormat(t *testing.T) {
	input := "data: {\"id\":\"1\"}\n\ndata: {\"id\":\"2\"}\n\ndata: [DONE]\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, `{"id":"1"}`, event.Data)
	assert.Equal(t, "", event.Event)
	ReleaseSSEEvent(event)

	event, err = parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, `{"id":"2"}`, event.Data)
	ReleaseSSEEvent(event)

	event, err = parser.ReadEvent()
	require.NoError(t, err)
	assert.True(t, IsDone(event.Data))
	ReleaseSSEEvent(event)
}

func TestSSEParser_AnthropicFormat(t *testing.T) {
	input := "event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "message_start", event.Event)
	assert.Contains(t, event.Data, "message_start")
	ReleaseSSEEvent(event)

	event, err = parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "content_block_delta", event.Event)
	ReleaseSSEEvent(event)

	event, err = parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "message_stop", event.Event)
	ReleaseSSEEvent(event)
}

func TestSSEParser_SkipsComments(t *testing.T) {
	input := ": this is a comment\ndata: hello\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "hello", event.Data)
	ReleaseSSEEvent(event)
}

func TestSSEParser_MultilineData(t *testing.T) {
	input := "data: line1\ndata: line2\ndata: line3\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "line1\nline2\nline3", event.Data)
	ReleaseSSEEvent(event)
}

func TestSSEParser_EventID(t *testing.T) {
	input := "id: 42\ndata: hello\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "42", event.ID)
	assert.Equal(t, "hello", event.Data)
	ReleaseSSEEvent(event)
}

func TestSSEParser_EmptyEvents(t *testing.T) {
	input := "\n\ndata: actual\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "actual", event.Data)
	ReleaseSSEEvent(event)
}

func TestSSEParser_EOF(t *testing.T) {
	input := "data: last\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	ReleaseSSEEvent(event)

	_, err = parser.ReadEvent()
	assert.Equal(t, io.EOF, err)
}

func TestSSEParser_StripLeadingSpace(t *testing.T) {
	input := "data: hello\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "hello", event.Data)
	ReleaseSSEEvent(event)
}

func TestSSEParser_NoSpace(t *testing.T) {
	input := "data:hello\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	defer parser.Close()

	event, err := parser.ReadEvent()
	require.NoError(t, err)
	assert.Equal(t, "hello", event.Data)
	ReleaseSSEEvent(event)
}

func TestIsDone(t *testing.T) {
	assert.True(t, IsDone("[DONE]"))
	assert.False(t, IsDone("not done"))
	assert.False(t, IsDone(""))
}

func TestSSEWriter_WriteChunk(t *testing.T) {
	w := httptest.NewRecorder()
	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))

	text := "Hello"
	chunk := &StreamChunk{
		ID:     "chatcmpl-1",
		Object: "chat.completion.chunk",
		Model:  "gpt-4",
		Choices: []StreamChoice{{
			Index: 0,
			Delta: StreamDelta{Content: &text},
		}},
	}

	err := sw.WriteChunk(chunk)
	require.NoError(t, err)

	body := w.Body.String()
	assert.Contains(t, body, "data: ")
	assert.Contains(t, body, "chatcmpl-1")
}

func TestSSEWriter_WriteDone(t *testing.T) {
	w := httptest.NewRecorder()
	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	err := sw.WriteDone()
	require.NoError(t, err)

	body := w.Body.String()
	assert.Contains(t, body, "data: [DONE]")
}

func TestSSEWriter_WriteError(t *testing.T) {
	w := httptest.NewRecorder()
	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	err := sw.WriteError(ErrInternal("something broke"))
	require.NoError(t, err)

	body := w.Body.String()
	assert.Contains(t, body, "something broke")
	assert.Contains(t, body, "server_error")
}
