// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"sync"

	tiktoken "github.com/pkoukk/tiktoken-go"
)

// TokenCounter provides token counting for different reqctx.
type TokenCounter struct{}

// NewTokenCounter creates a new token counter.
func NewTokenCounter() *TokenCounter {
	return &TokenCounter{}
}

// Thread-safe tiktoken encoding cache.
var (
	tiktokenMu    sync.RWMutex
	tiktokenCache = make(map[string]*tiktoken.Tiktoken)
)

// getEncoding returns a cached tiktoken encoding for the given encoding name.
func getEncoding(name string) *tiktoken.Tiktoken {
	tiktokenMu.RLock()
	enc, ok := tiktokenCache[name]
	tiktokenMu.RUnlock()
	if ok {
		return enc
	}

	tiktokenMu.Lock()
	defer tiktokenMu.Unlock()
	// Double-check after acquiring write lock
	if enc, ok = tiktokenCache[name]; ok {
		return enc
	}
	enc, err := tiktoken.GetEncoding(name)
	if err != nil {
		return nil
	}
	tiktokenCache[name] = enc
	return enc
}

// CountText returns the token count for the given text and model.
// Uses tiktoken for known model families, falls back to character-based estimation.
func (tc *TokenCounter) CountText(text string, model string) int {
	if len(text) == 0 {
		return 0
	}
	family := TokenizerForModel(model)
	if family != "estimate" {
		if enc := getEncoding(family); enc != nil {
			return len(enc.Encode(text, nil, nil))
		}
	}
	return (len(text) + 3) / 4
}

// CountMessages counts tokens for a chat message array including overhead.
// Each message has ~4 tokens of overhead (role, separators).
func (tc *TokenCounter) CountMessages(messages []Message, model string) int {
	total := 0
	for _, msg := range messages {
		total += 4 // per-message overhead
		total += tc.CountText(msg.Role, model)
		total += tc.CountText(msg.ContentString(), model)
		if msg.Name != "" {
			total += tc.CountText(msg.Name, model) + 1 // name adds ~1 token overhead
		}
		for _, tc2 := range msg.ToolCalls {
			total += tc.CountText(tc2.Function.Name, model)
			total += tc.CountText(tc2.Function.Arguments, model)
		}
	}
	total += 2 // every reply is primed with <|start|>assistant<|message|>
	return total
}

// EstimateTokens is a quick estimation without model-specific logic.
func EstimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	return (len(text) + 3) / 4
}

// EstimateMessagesTokens gives a rough estimate of total tokens for messages.
func EstimateMessagesTokens(messages []Message) int {
	total := 0
	for _, msg := range messages {
		total += 4 + EstimateTokens(msg.ContentString())
		if msg.Role != "" {
			total += 1
		}
	}
	return total + 2
}
