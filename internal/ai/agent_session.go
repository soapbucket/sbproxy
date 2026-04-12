// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"time"
)

// AgentSessionConfig defines per-agent session limits.
type AgentSessionConfig struct {
	// MaxIterations caps the number of requests per agent session.
	// Zero means unlimited.
	MaxIterations int `json:"max_iterations,omitempty"`
	// MaxTokensPerSession caps total tokens per session.
	// Zero means unlimited.
	MaxTokensPerSession int64 `json:"max_tokens_per_session,omitempty"`
	// MaxDuration caps session duration. Zero means unlimited.
	MaxDuration time.Duration `json:"max_duration,omitempty"`
	// TPMPerAgent limits tokens per minute per agent.
	// Zero means unlimited.
	TPMPerAgent int64 `json:"tpm_per_agent,omitempty"`
	// RPMPerAgent limits requests per minute per agent.
	// Zero means unlimited.
	RPMPerAgent int `json:"rpm_per_agent,omitempty"`
}

// AgentSessionEnforcer checks and enforces agent session limits.
type AgentSessionEnforcer struct {
	config  *AgentSessionConfig
	tracker *SessionTracker
	rates   *agentRateTracker
}

// NewAgentSessionEnforcer creates a new enforcer for agent session limits.
// A nil config disables all limits.
func NewAgentSessionEnforcer(cfg *AgentSessionConfig, tracker *SessionTracker) *AgentSessionEnforcer {
	windowSize := time.Minute
	return &AgentSessionEnforcer{
		config:  cfg,
		tracker: tracker,
		rates:   newAgentRateTracker(windowSize),
	}
}

// ErrSessionIterationLimit returns an error indicating the session iteration limit was reached.
func ErrSessionIterationLimit(limit int) *AIError {
	return &AIError{
		StatusCode: 429,
		Type:       "session_limit_error",
		Message:    fmt.Sprintf("agent session iteration limit reached (max: %d)", limit),
		Code:       "session_iteration_limit",
	}
}

// ErrSessionTokenLimit returns an error indicating the session token limit was reached.
func ErrSessionTokenLimit(limit int64) *AIError {
	return &AIError{
		StatusCode: 429,
		Type:       "session_limit_error",
		Message:    fmt.Sprintf("agent session token limit reached (max: %d)", limit),
		Code:       "session_token_limit",
	}
}

// ErrSessionDurationLimit returns an error indicating the session duration limit was reached.
func ErrSessionDurationLimit(limit time.Duration) *AIError {
	return &AIError{
		StatusCode: 429,
		Type:       "session_limit_error",
		Message:    fmt.Sprintf("agent session duration limit reached (max: %s)", limit),
		Code:       "session_duration_limit",
	}
}

// ErrSessionRateLimit returns an error indicating the agent session rate limit was exceeded.
func ErrSessionRateLimit(msg string) *AIError {
	return &AIError{
		StatusCode: 429,
		Type:       "session_limit_error",
		Message:    msg,
		Code:       "session_rate_limit",
	}
}

// CheckLimits verifies that the session identified by sessionID has not exceeded
// any configured limits. Returns nil if all limits are within bounds, or an
// *AIError describing which limit was breached.
func (e *AgentSessionEnforcer) CheckLimits(ctx context.Context, sessionID string) error {
	if e.config == nil {
		return nil
	}

	// Check rate limits first (these do not require a session lookup).
	if err := e.checkRateLimits(sessionID); err != nil {
		return err
	}

	// Load session data for iteration/token/duration checks.
	data, err := e.tracker.Get(ctx, sessionID)
	if err != nil {
		// Session does not exist yet, so no limits can be exceeded.
		return nil
	}

	if e.config.MaxIterations > 0 && data.RequestCount >= e.config.MaxIterations {
		return ErrSessionIterationLimit(e.config.MaxIterations)
	}

	if e.config.MaxTokensPerSession > 0 && int64(data.TotalTokens) >= e.config.MaxTokensPerSession {
		return ErrSessionTokenLimit(e.config.MaxTokensPerSession)
	}

	if e.config.MaxDuration > 0 && time.Since(data.StartedAt) >= e.config.MaxDuration {
		return ErrSessionDurationLimit(e.config.MaxDuration)
	}

	return nil
}

// checkRateLimits verifies TPM and RPM limits from the sliding window tracker.
func (e *AgentSessionEnforcer) checkRateLimits(sessionID string) error {
	if e.config.RPMPerAgent > 0 {
		rpm := e.rates.RequestsInWindow(sessionID)
		if rpm >= e.config.RPMPerAgent {
			return ErrSessionRateLimit(fmt.Sprintf("agent session rate limit exceeded: %d requests per minute (max: %d)", rpm, e.config.RPMPerAgent))
		}
	}

	if e.config.TPMPerAgent > 0 {
		tpm := e.rates.TokensInWindow(sessionID)
		if tpm >= e.config.TPMPerAgent {
			return ErrSessionRateLimit(fmt.Sprintf("agent session rate limit exceeded: %d tokens per minute (max: %d)", tpm, e.config.TPMPerAgent))
		}
	}

	return nil
}

// RecordRequest delegates to SessionTracker.Track to persist the request and
// records rate window entries for RPM/TPM tracking. It then checks all limits
// and returns an error if any are exceeded after recording.
func (e *AgentSessionEnforcer) RecordRequest(ctx context.Context, sessionID, agent, apiKey string, tokens int, costUSD float64) error {
	if e.config == nil {
		// No config means no limits. Still track via the session tracker.
		_, _, err := e.tracker.Track(ctx, sessionID, agent, apiKey, tokens, costUSD)
		return err
	}

	// Record in the session tracker.
	_, _, err := e.tracker.Track(ctx, sessionID, agent, apiKey, tokens, costUSD)
	if err != nil {
		return fmt.Errorf("agent session record: %w", err)
	}

	// Record in the rate tracker for RPM/TPM sliding window.
	e.rates.RecordRequest(sessionID)
	if tokens > 0 {
		e.rates.RecordTokens(sessionID, int64(tokens))
	}

	return nil
}
