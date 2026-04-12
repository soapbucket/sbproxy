// Package memory manages conversational memory and context persistence for AI sessions.
package memory

// Entry represents a single AI memory record matching the ClickHouse ai_memory table.
type Entry struct {
	// Identity
	ID        string `json:"id,omitempty"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`

	// Workspace/origin
	WorkspaceID string `json:"workspace_id"`
	OriginID    string `json:"origin_id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`

	// Session grouping
	SessionID       string `json:"session_id"`
	SessionSequence uint32 `json:"session_sequence,omitempty"`

	// User attribution (from auth framework)
	AuthType       string `json:"auth_type,omitempty"`
	AuthIdentifier string `json:"auth_identifier,omitempty"`
	AuthKeyHash    string `json:"auth_key_hash,omitempty"`

	// Agent identity
	Agent string            `json:"agent,omitempty"`
	Tags  map[string]string `json:"tags,omitempty"`

	// Request metadata
	Provider    string `json:"provider"`
	Model       string `json:"model"`
	IsStreaming bool   `json:"is_streaming,omitempty"`
	StopReason  string `json:"stop_reason,omitempty"`

	// Token usage
	InputTokens  uint32  `json:"input_tokens,omitempty"`
	OutputTokens uint32  `json:"output_tokens,omitempty"`
	TotalTokens  uint32  `json:"total_tokens,omitempty"`
	CachedTokens uint32  `json:"cached_tokens,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`

	// Timing
	LatencyMS uint32 `json:"latency_ms,omitempty"`
	TtftMS    uint32 `json:"ttft_ms,omitempty"`

	// Conversation content (JSON strings)
	SystemPrompt  string `json:"system_prompt,omitempty"`
	InputMessages string `json:"input_messages,omitempty"`
	OutputContent string `json:"output_content,omitempty"`

	// Tool tracking
	ToolsAvailable []string `json:"tools_available,omitempty"`
	ToolsCalled    []string `json:"tools_called,omitempty"`
	HasToolUse     bool     `json:"has_tool_use,omitempty"`

	// Classification
	Error             string `json:"error,omitempty"`
	InputMessageCount uint16 `json:"input_message_count,omitempty"`
	CaptureScope      string `json:"capture_scope,omitempty"`

	// Compliance
	PromptHash   string `json:"prompt_hash,omitempty"`
	ResponseHash string `json:"response_hash,omitempty"`
}
