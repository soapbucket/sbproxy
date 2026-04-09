// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	json "github.com/goccy/go-json"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	responseCacheNamespace = "ai:response"
	responseCacheTTL       = time.Hour
)

// ResponseContextCache stores and retrieves conversation context for the Responses API
// using the cacher.Cacher interface. Keys are response IDs; values are JSON-encoded
// message arrays representing the conversation history.
type ResponseContextCache struct {
	cache cacher.Cacher
	ttl   time.Duration
}

// NewResponseContextCache creates a new cache backed by a Cacher implementation.
func NewResponseContextCache(c cacher.Cacher) *ResponseContextCache {
	return &ResponseContextCache{
		cache: c,
		ttl:   responseCacheTTL,
	}
}

// StoreContext persists the conversation messages for a given response ID.
func (rc *ResponseContextCache) StoreContext(ctx context.Context, responseID string, messages []Message) error {
	data, err := json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("marshal response context: %w", err)
	}
	return rc.cache.PutWithExpires(ctx, responseCacheNamespace, responseID, bytes.NewReader(data), rc.ttl)
}

// LoadContext retrieves the conversation messages for a given response ID.
// Returns nil messages and nil error if the key does not exist.
func (rc *ResponseContextCache) LoadContext(ctx context.Context, responseID string) ([]Message, error) {
	reader, err := rc.cache.Get(ctx, responseCacheNamespace, responseID)
	if err != nil {
		// Cache miss is not an error
		return nil, nil
	}
	if reader == nil {
		return nil, nil
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read response context: %w", err)
	}

	var msgs []Message
	if err := json.Unmarshal(data, &msgs); err != nil {
		return nil, fmt.Errorf("unmarshal response context: %w", err)
	}
	return msgs, nil
}

// ResponsesBridge converts a CreateResponseRequest into a ChatCompletionRequest,
// resolving previous_response_id from the context cache for multi-turn support.
// For OpenAI providers, this is a passthrough (the Responses API is native).
// For other providers, it translates to the chat completions format.
type ResponsesBridge struct {
	contextCache *ResponseContextCache
	store        ResponseStore
}

// NewResponsesBridge creates a new bridge with optional context cache.
func NewResponsesBridge(contextCache *ResponseContextCache, respStore ResponseStore) *ResponsesBridge {
	return &ResponsesBridge{
		contextCache: contextCache,
		store:        respStore,
	}
}

// ToChatCompletion translates a CreateResponseRequest to a ChatCompletionRequest,
// resolving multi-turn context from the cache when previous_response_id is set.
func (b *ResponsesBridge) ToChatCompletion(ctx context.Context, req *CreateResponseRequest) (*ChatCompletionRequest, error) {
	chatReq := &ChatCompletionRequest{
		Model:       req.Model,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Tools:       req.Tools,
	}

	if req.MaxOutputTokens > 0 {
		chatReq.MaxTokens = &req.MaxOutputTokens
	}

	if req.Stream {
		stream := true
		chatReq.Stream = &stream
	}

	var messages []Message

	// Prepend instructions as system message
	if req.Instructions != "" {
		messages = append(messages, mustTextMessage("system", req.Instructions))
	}

	// Resolve multi-turn context from cache
	if req.PreviousResponseID != "" && b.contextCache != nil {
		prevMsgs, err := b.contextCache.LoadContext(ctx, req.PreviousResponseID)
		if err != nil {
			slog.Warn("failed to load previous response context from cache",
				"previous_response_id", req.PreviousResponseID,
				"error", err)
		}
		if len(prevMsgs) > 0 {
			messages = append(messages, prevMsgs...)
		} else if b.store != nil {
			// Fall back to response store lookup
			prev, err := b.store.Get(ctx, req.PreviousResponseID)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch previous response %q: %w", req.PreviousResponseID, err)
			}
			if prev != nil {
				prevMessages := responsesToMessages(prev)
				messages = append(messages, prevMessages...)
			}
		}
	}

	// Parse input
	inputMessages, err := parseResponseInput(req.Input)
	if err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	messages = append(messages, inputMessages...)

	chatReq.Messages = messages
	return chatReq, nil
}

// StoreConversationContext saves the full conversation context (input messages + assistant response)
// so that future requests with previous_response_id can retrieve it.
func (b *ResponsesBridge) StoreConversationContext(ctx context.Context, responseID string, inputMessages []Message, assistantText string) {
	if b.contextCache == nil {
		return
	}

	allMessages := make([]Message, len(inputMessages))
	copy(allMessages, inputMessages)

	if assistantText != "" {
		allMessages = append(allMessages, mustTextMessage("assistant", assistantText))
	}

	if err := b.contextCache.StoreContext(ctx, responseID, allMessages); err != nil {
		slog.Warn("failed to store response context in cache",
			"response_id", responseID,
			"error", err)
	}
}
