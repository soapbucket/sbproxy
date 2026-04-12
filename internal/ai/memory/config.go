// Package memory manages conversational memory and context persistence for AI sessions.
package memory

// MemoryConfig controls AI memory capture for an ai_proxy action.
type MemoryConfig struct {
	// Enabled is the master toggle for memory capture.
	Enabled bool `json:"enabled"`

	// CaptureScope controls what content is stored.
	// "full" (default) stores messages + response, "metadata" stores tokens/cost only,
	// "summary" stores auto-generated summaries.
	CaptureScope string `json:"capture_scope,omitempty"`

	// SampleRate is the probability (0.0-1.0) of capturing each request. Default 1.0.
	SampleRate float64 `json:"sample_rate,omitempty"`

	// MinTokens skips exchanges below this token count. Default 0.
	MinTokens int `json:"min_tokens,omitempty"`

	// CaptureStreaming controls whether streaming responses are captured. Default true.
	CaptureStreaming *bool `json:"capture_streaming,omitempty"`

	// RedactPII runs a PII scanner before writing to ClickHouse.
	RedactPII bool `json:"redact_pii,omitempty"`

	// ExcludeSystemPrompts strips system messages from stored content.
	ExcludeSystemPrompts bool `json:"exclude_system_prompts,omitempty"`

	// ExcludeToolResults strips tool result bodies (keeps tool names).
	ExcludeToolResults bool `json:"exclude_tool_results,omitempty"`

	// RetentionDays is the ClickHouse TTL for this origin's entries. Default 365.
	RetentionDays int `json:"retention_days,omitempty"`

	// MaxEntriesPerSession caps entries per session as a safety valve. Default 1000.
	MaxEntriesPerSession int `json:"max_entries_per_session,omitempty"`
}

// Defaults returns a MemoryConfig with default values applied.
func (c *MemoryConfig) Defaults() *MemoryConfig {
	out := *c
	if out.CaptureScope == "" {
		out.CaptureScope = ScopeFull
	}
	if out.SampleRate <= 0 {
		out.SampleRate = 1.0
	}
	if out.CaptureStreaming == nil {
		t := true
		out.CaptureStreaming = &t
	}
	if out.RetentionDays <= 0 {
		out.RetentionDays = 365
	}
	if out.MaxEntriesPerSession <= 0 {
		out.MaxEntriesPerSession = 1000
	}
	return &out
}

// ShouldCaptureStreaming returns true if streaming responses should be captured.
func (c *MemoryConfig) ShouldCaptureStreaming() bool {
	if c.CaptureStreaming == nil {
		return true
	}
	return *c.CaptureStreaming
}

// Capture scope constants.
const (
	// ScopeFull is a constant for scope full.
	ScopeFull = "full"
	// ScopeMetadata is a constant for scope metadata.
	ScopeMetadata = "metadata"
	// ScopeSummary is a constant for scope summary.
	ScopeSummary = "summary"
)
