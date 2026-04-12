// Package mcp implements the Model Context Protocol (MCP) for AI tool and resource integration.
package mcp

import (
	"sync"
	"time"
)

// ToolRateLimitConfig configures rate limiting for a tool.
type ToolRateLimitConfig struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	TokensPerMinute   int `json:"tokens_per_minute,omitempty"`
}

// ToolRateLimiter limits tool call rates per consumer.
type ToolRateLimiter struct {
	limits   map[string]*ToolRateLimitConfig
	counters map[string]*toolCounter
	mu       sync.RWMutex
	nowFunc  func() time.Time // injectable clock for testing
}

type toolCounter struct {
	count   int
	resetAt time.Time
}

// NewToolRateLimiter creates a new ToolRateLimiter with the given per-tool limits.
func NewToolRateLimiter(limits map[string]*ToolRateLimitConfig) *ToolRateLimiter {
	if limits == nil {
		limits = make(map[string]*ToolRateLimitConfig)
	}
	return &ToolRateLimiter{
		limits:   limits,
		counters: make(map[string]*toolCounter),
		nowFunc:  time.Now,
	}
}

// Allow returns true if the tool call is within rate limits for the given consumer.
// If no limit is configured for the tool, access is always allowed.
func (rl *ToolRateLimiter) Allow(toolName string, consumerID string) bool {
	limit, ok := rl.limits[toolName]
	if !ok {
		return true // No limit configured
	}

	if limit.RequestsPerMinute <= 0 {
		return true // No request limit
	}

	key := toolName + ":" + consumerID

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFunc()

	counter, ok := rl.counters[key]
	if !ok || now.After(counter.resetAt) {
		// Start a new window
		rl.counters[key] = &toolCounter{
			count:   1,
			resetAt: now.Add(time.Minute),
		}
		return true
	}

	if counter.count >= limit.RequestsPerMinute {
		return false // Rate limit exceeded
	}

	counter.count++
	return true
}

// Remaining returns how many requests remain in the current window for a tool/consumer pair.
// Returns -1 if no limit is configured.
func (rl *ToolRateLimiter) Remaining(toolName string, consumerID string) int {
	limit, ok := rl.limits[toolName]
	if !ok {
		return -1
	}

	if limit.RequestsPerMinute <= 0 {
		return -1
	}

	key := toolName + ":" + consumerID

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := rl.nowFunc()

	counter, ok := rl.counters[key]
	if !ok || now.After(counter.resetAt) {
		return limit.RequestsPerMinute
	}

	remaining := limit.RequestsPerMinute - counter.count
	if remaining < 0 {
		return 0
	}
	return remaining
}
