// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	json "github.com/goccy/go-json"
)

// LegacyCompletionRequest matches the OpenAI /v1/completions API spec.
type LegacyCompletionRequest struct {
	Model            string          `json:"model"`
	Prompt           json.RawMessage `json:"prompt,omitempty"`
	Suffix           *string         `json:"suffix,omitempty"`
	MaxTokens        *int            `json:"max_tokens,omitempty"`
	Temperature      *float64        `json:"temperature,omitempty"`
	TopP             *float64        `json:"top_p,omitempty"`
	N                *int            `json:"n,omitempty"`
	Stream           *bool           `json:"stream,omitempty"`
	Logprobs         *int            `json:"logprobs,omitempty"`
	Echo             *bool           `json:"echo,omitempty"`
	Stop             json.RawMessage `json:"stop,omitempty"`
	PresencePenalty  *float64        `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float64        `json:"frequency_penalty,omitempty"`
	BestOf           *int            `json:"best_of,omitempty"`
	User             string          `json:"user,omitempty"`
}

// LegacyCompletionResponse matches the OpenAI /v1/completions response.
type LegacyCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []LegacyCompletionChoice `json:"choices"`
	Usage   *Usage                 `json:"usage,omitempty"`
}

// LegacyCompletionChoice represents a choice in a legacy completion response.
type LegacyCompletionChoice struct {
	Text         string  `json:"text"`
	Index        int     `json:"index"`
	Logprobs     any     `json:"logprobs"`
	FinishReason *string `json:"finish_reason"`
}

// LegacyStreamChunk matches the OpenAI /v1/completions streaming chunk format.
type LegacyStreamChunk struct {
	ID      string                       `json:"id"`
	Object  string                       `json:"object"`
	Created int64                        `json:"created"`
	Model   string                       `json:"model"`
	Choices []LegacyStreamCompletionChoice `json:"choices"`
	Usage   *Usage                       `json:"usage,omitempty"`
}

// LegacyStreamCompletionChoice represents a streaming choice in a legacy completion.
type LegacyStreamCompletionChoice struct {
	Text         string  `json:"text"`
	Index        int     `json:"index"`
	Logprobs     any     `json:"logprobs"`
	FinishReason *string `json:"finish_reason"`
}

// parsePromptToMessages converts a legacy prompt (string or []string) into chat messages.
func parsePromptToMessages(raw json.RawMessage) ([]Message, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("prompt is required")
	}

	// Try string first.
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []Message{mustTextMessage("user", single)}, nil
	}

	// Try []string.
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		if len(arr) == 0 {
			return nil, fmt.Errorf("prompt array must not be empty")
		}
		msgs := make([]Message, 0, len(arr))
		for _, s := range arr {
			msgs = append(msgs, mustTextMessage("user", s))
		}
		return msgs, nil
	}

	return nil, fmt.Errorf("prompt must be a string or array of strings")
}

// legacyToChatRequest converts a LegacyCompletionRequest into a ChatCompletionRequest.
func legacyToChatRequest(req *LegacyCompletionRequest) (*ChatCompletionRequest, error) {
	msgs, err := parsePromptToMessages(req.Prompt)
	if err != nil {
		return nil, err
	}

	chat := &ChatCompletionRequest{
		Model:            req.Model,
		Messages:         msgs,
		MaxTokens:        req.MaxTokens,
		Temperature:      req.Temperature,
		TopP:             req.TopP,
		N:                req.N,
		Stream:           req.Stream,
		Stop:             req.Stop,
		PresencePenalty:  req.PresencePenalty,
		FrequencyPenalty: req.FrequencyPenalty,
		User:             req.User,
	}

	// Log unsupported params that were provided.
	if req.Suffix != nil {
		slog.Debug("legacy completions: suffix parameter dropped (not supported)")
	}
	if req.Logprobs != nil {
		slog.Debug("legacy completions: logprobs parameter dropped (not supported)")
	}
	if req.Echo != nil {
		slog.Debug("legacy completions: echo parameter dropped (not supported)")
	}
	if req.BestOf != nil {
		slog.Debug("legacy completions: best_of parameter dropped (not supported)")
	}

	return chat, nil
}

// chatResponseToLegacy converts a ChatCompletionResponse to a LegacyCompletionResponse.
func chatResponseToLegacy(resp *ChatCompletionResponse) (*LegacyCompletionResponse, error) {
	id := resp.ID
	if len(id) > 9 && id[:9] == "chatcmpl-" {
		id = "cmpl-" + id[9:]
	} else if id == "" {
		var err error
		id, err = generateID("cmpl-")
		if err != nil {
			return nil, err
		}
	}

	choices := make([]LegacyCompletionChoice, len(resp.Choices))
	for i, c := range resp.Choices {
		choices[i] = LegacyCompletionChoice{
			Text:         c.Message.ContentString(),
			Index:        c.Index,
			Logprobs:     c.Logprobs,
			FinishReason: c.FinishReason,
		}
	}

	return &LegacyCompletionResponse{
		ID:      id,
		Object:  "text_completion",
		Created: resp.Created,
		Model:   resp.Model,
		Choices: choices,
		Usage:   resp.Usage,
	}, nil
}

// chatStreamChunkToLegacy converts a StreamChunk to a LegacyStreamChunk.
func chatStreamChunkToLegacy(chunk *StreamChunk) *LegacyStreamChunk {
	id := chunk.ID
	if len(id) > 9 && id[:9] == "chatcmpl-" {
		id = "cmpl-" + id[9:]
	}

	choices := make([]LegacyStreamCompletionChoice, len(chunk.Choices))
	for i, c := range chunk.Choices {
		text := ""
		if c.Delta.Content != nil {
			text = *c.Delta.Content
		}
		choices[i] = LegacyStreamCompletionChoice{
			Text:         text,
			Index:        c.Index,
			Logprobs:     c.Logprobs,
			FinishReason: c.FinishReason,
		}
	}

	return &LegacyStreamChunk{
		ID:      id,
		Object:  "text_completion",
		Created: chunk.Created,
		Model:   chunk.Model,
		Choices: choices,
		Usage:   chunk.Usage,
	}
}

// handleCompletions handles /v1/completions by translating to/from the chat completions format.
func (h *Handler) handleCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var legacyReq LegacyCompletionRequest
	if err := json.NewDecoder(body).Decode(&legacyReq); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	chatReq, err := legacyToChatRequest(&legacyReq)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	if chatReq.Model == "" && h.config.DefaultModel != "" {
		chatReq.Model = h.config.DefaultModel
	}
	if chatReq.Model == "" {
		WriteError(w, ErrInvalidRequest("model is required"))
		return
	}

	if err := h.validateModelAccess(r.Context(), chatReq.Model); err != nil {
		WriteError(w, err)
		return
	}

	streaming := chatReq.IsStreaming()

	// Route to a provider.
	exclude := make(map[string]bool)
	maxAttempts := h.router.MaxAttempts()

	for attempt := 0; attempt < maxAttempts; attempt++ {
		pcfg, routeErr := h.router.Route(r.Context(), chatReq.Model, exclude)
		if routeErr != nil {
			if aiErr, ok := routeErr.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(routeErr.Error()))
			}
			return
		}

		entry, ok := h.providers[pcfg.Name]
		if !ok {
			exclude[pcfg.Name] = true
			continue
		}

		// Concurrency limiter: acquire a slot before dispatching to the provider.
		if h.ConcurrencyLimiter != nil {
			acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
			if acqErr != nil || !acquired {
				exclude[pcfg.Name] = true
				continue
			}
		}

		if streaming {
			h.handleLegacyStreamingCompletion(w, r, chatReq, entry)
			if h.ConcurrencyLimiter != nil {
				h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
			}
			return
		}

		resp, chatErr := entry.provider.ChatCompletion(r.Context(), chatReq, entry.config)

		// Release concurrency slot after dispatch completes.
		if h.ConcurrencyLimiter != nil {
			h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
		}

		if chatErr != nil {
			if aiErr, ok := chatErr.(*AIError); ok && h.router.ShouldRetry(aiErr.StatusCode) && attempt < maxAttempts-1 {
				exclude[pcfg.Name] = true
				continue
			}
			if aiErr, ok := chatErr.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(chatErr.Error()))
			}
			return
		}

		if resp.Object == "" {
			resp.Object = "chat.completion"
		}
		if resp.Created == 0 {
			resp.Created = time.Now().Unix()
		}

		legacy, err := chatResponseToLegacy(resp)
		if err != nil {
			WriteError(w, ErrInternal("failed to generate response ID"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		respBytes, _ := json.Marshal(legacy)
		w.Write(respBytes)
		return
	}

	WriteError(w, ErrInternal("all providers unavailable"))
}

// handleLegacyStreamingCompletion streams a legacy completion response by wrapping the chat streaming path.
func (h *Handler) handleLegacyStreamingCompletion(w http.ResponseWriter, r *http.Request, chatReq *ChatCompletionRequest, entry providerEntry) {
	if !entry.provider.SupportsStreaming() {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("provider %q does not support streaming", entry.config.Name)))
		return
	}

	stream, err := entry.provider.ChatCompletionStream(r.Context(), chatReq, entry.config)
	if err != nil {
		if aiErr, ok := err.(*AIError); ok {
			WriteError(w, aiErr)
		} else {
			WriteError(w, ErrInternal(err.Error()))
		}
		return
	}
	defer stream.Close()

	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	for {
		chunk, readErr := stream.Read()
		if readErr != nil {
			if readErr == io.EOF {
				sw.WriteDone()
				return
			}
			sw.WriteError(ErrInternal(readErr.Error()))
			return
		}

		if chunk.Object == "" {
			chunk.Object = "chat.completion.chunk"
		}
		if chunk.Created == 0 {
			chunk.Created = time.Now().Unix()
		}

		legacy := chatStreamChunkToLegacy(chunk)
		h.writeLegacySSEChunk(sw, legacy)
	}
}

// writeLegacySSEChunk writes a LegacyStreamChunk as an SSE data event.
func (h *Handler) writeLegacySSEChunk(sw *SSEWriter, chunk *LegacyStreamChunk) {
	data, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	fmt.Fprintf(sw.w, "data: %s\n\n", data)
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
}

// writeSSELegacyDone writes the [DONE] terminator for legacy completions streaming.
func writeSSELegacyDone(sw *SSEWriter) {
	sw.WriteDone()
}

// legacyCompletionIDPrefix returns the ID prefix for legacy completion responses.
func legacyCompletionIDPrefix() string {
	return "cmpl-"
}

// registerCompletionsRoute is a helper comment showing how to register the route.
// In ServeHTTP: case path == "completions": h.handleCompletions(w, r)
//
// This is done by adding a case to the switch in ServeHTTP.
func init() {
	// Registration happens in ServeHTTP switch statement.
	// See the Edit to handler.go that adds: case path == "completions"
}

// convertLegacyID converts a chat completion ID to a legacy completion ID.
func convertLegacyID(id string) (string, error) {
	if len(id) > 9 && id[:9] == "chatcmpl-" {
		return "cmpl-" + id[9:], nil
	}
	if id == "" {
		return generateID("cmpl-")
	}
	return id, nil
}

// WriteLegacyChunkJSON marshals and returns a legacy stream chunk as a JSON byte slice.
func WriteLegacyChunkJSON(chunk *LegacyStreamChunk) ([]byte, error) {
	return json.Marshal(chunk)
}

// isLegacyCompletionID reports whether the given ID has the legacy completion prefix.
func isLegacyCompletionID(id string) bool {
	return len(id) >= 5 && id[:5] == "cmpl-"
}

// NewLegacyCompletionResponse creates a LegacyCompletionResponse from parts.
func NewLegacyCompletionResponse(model string, text string, finishReason string, usage *Usage) (*LegacyCompletionResponse, error) {
	id, err := generateID("cmpl-")
	if err != nil {
		return nil, err
	}
	return &LegacyCompletionResponse{
		ID:      id,
		Object:  "text_completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []LegacyCompletionChoice{{
			Text:         text,
			Index:        0,
			FinishReason: &finishReason,
		}},
		Usage: usage,
	}, nil
}

// legacyCompletionMaxTokensDefault is the default max_tokens for legacy completions
// when not explicitly specified (matches OpenAI behavior).
const legacyCompletionMaxTokensDefault = 16
