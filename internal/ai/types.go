// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"strings"

	json "github.com/goccy/go-json"
	"strconv"
	"time"
)

// ChatCompletionRequest matches the OpenAI chat completion API spec.
type ChatCompletionRequest struct {
	Model               string            `json:"model"`
	Messages            []Message         `json:"messages"`
	Temperature         *float64          `json:"temperature,omitempty"`
	TopP                *float64          `json:"top_p,omitempty"`
	N                   *int              `json:"n,omitempty"`
	Stream              *bool             `json:"stream,omitempty"`
	StreamOptions       *StreamOptions    `json:"stream_options,omitempty"`
	Stop                json.RawMessage   `json:"stop,omitempty"`
	MaxTokens           *int              `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int              `json:"max_completion_tokens,omitempty"`
	PresencePenalty     *float64          `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64          `json:"frequency_penalty,omitempty"`
	LogitBias           map[string]int    `json:"logit_bias,omitempty"`
	User                string            `json:"user,omitempty"`
	Tools               []Tool            `json:"tools,omitempty"`
	ToolChoice          json.RawMessage   `json:"tool_choice,omitempty"`
	ResponseFormat      *ResponseFormat   `json:"response_format,omitempty"`
	Seed                *int64            `json:"seed,omitempty"`
	PromptID            string            `json:"prompt_id,omitempty"`
	PromptEnvironment   string            `json:"prompt_environment,omitempty"`
	PromptVersion       *int              `json:"prompt_version,omitempty"`
	PromptVariables     map[string]string `json:"prompt_variables,omitempty"`

	// Thinking/reasoning parameters (provider passthrough)
	Thinking        *ThinkingConfig `json:"thinking,omitempty"`
	ReasoningEffort string          `json:"reasoning_effort,omitempty"`

	// SoapBucket extensions (not forwarded to providers)
	SBTags         map[string]string `json:"sb_tags,omitempty"`
	SBCacheControl *CacheControl     `json:"sb_cache_control,omitempty"`
	SBPriority     *int              `json:"sb_priority,omitempty"`
}

// ThinkingConfig controls extended thinking for models that support it (e.g. Anthropic).
type ThinkingConfig struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

// ThinkingBlock represents a thinking/reasoning content block in a response.
type ThinkingBlock struct {
	Type      string `json:"type"`
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// IsStreaming returns true if the request is for a streaming response.
func (r *ChatCompletionRequest) IsStreaming() bool {
	return r.Stream != nil && *r.Stream
}

// GetModel returns the model, defaulting to the provided fallback.
func (r *ChatCompletionRequest) GetModel(fallback string) string {
	if r.Model != "" {
		return r.Model
	}
	return fallback
}

// Message represents a chat message.
type Message struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name,omitempty"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

// ContentString returns the message content as a string.
// If content is an array of content parts, it concatenates the text parts.
func (m *Message) ContentString() string {
	if len(m.Content) == 0 {
		return ""
	}

	switch m.Content[0] {
	case '"':
		var s string
		if err := json.Unmarshal(m.Content, &s); err == nil {
			return s
		}
	case '[':
		var parts []ContentPart
		if err := json.Unmarshal(m.Content, &parts); err == nil {
			var b strings.Builder
			for _, p := range parts {
				if p.Type == "text" {
					b.WriteString(p.Text)
				}
			}
			return b.String()
		}
	}
	return ""
}

// ContentPart represents a multimodal content part.
type ContentPart struct {
	Type         string              `json:"type"`
	Text         string              `json:"text,omitempty"`
	ImageURL     *ImageURL           `json:"image_url,omitempty"`
	CacheControl *CacheControlConfig `json:"cache_control,omitempty"`
}

// CacheControlConfig controls provider-level prompt caching (e.g. Anthropic cache_control).
type CacheControlConfig struct {
	Type string `json:"type"`
}

// ImageURL represents an image URL in a content part.
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// Tool represents a tool definition.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction defines a function tool.
type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ToolCall represents a tool call from the assistant.
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction represents the function details of a tool call.
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// StreamOptions controls streaming behavior.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// ResponseFormat specifies the output format.
type ResponseFormat struct {
	Type       string          `json:"type"`
	JSONSchema json.RawMessage `json:"json_schema,omitempty"`
}

// CacheControl is a SoapBucket extension for cache behavior.
type CacheControl struct {
	NoCache    bool   `json:"no_cache,omitempty"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	CacheKey   string `json:"cache_key,omitempty"`
}

// ChatCompletionResponse matches the OpenAI chat completion response.
type ChatCompletionResponse struct {
	ID                string   `json:"id"`
	Object            string   `json:"object"`
	Created           int64    `json:"created"`
	Model             string   `json:"model"`
	Choices           []Choice `json:"choices"`
	Usage             *Usage   `json:"usage,omitempty"`
	SystemFingerprint string   `json:"system_fingerprint,omitempty"`
}

// Choice represents a completion choice.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason *string `json:"finish_reason"`
	Logprobs     any     `json:"logprobs,omitempty"`
}

// Usage tracks token usage.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`

	// Provider cache token tracking
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`

	// Detailed breakdowns (OpenAI-style)
	PromptTokensDetails     *PromptTokensDetails     `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *CompletionTokensDetails `json:"completion_tokens_details,omitempty"`

	// SoapBucket extensions
	PromptTokensCached int     `json:"prompt_tokens_cached,omitempty"`
	CostUSD            float64 `json:"cost_usd,omitempty"`
	TtftMS             int64   `json:"ttft_ms,omitempty"`
	AvgItlMS           int64   `json:"avg_itl_ms,omitempty"`
}

// PromptTokensDetails provides a breakdown of prompt token usage.
type PromptTokensDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

// CompletionTokensDetails provides a breakdown of completion token usage.
type CompletionTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

// StreamChunk matches the OpenAI streaming chunk format.
type StreamChunk struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	Choices           []StreamChoice `json:"choices"`
	Usage             *Usage         `json:"usage,omitempty"`
	SystemFingerprint string         `json:"system_fingerprint,omitempty"`
	SbMetadata        *SbMetadata    `json:"sb_metadata,omitempty"`
}

// SbMetadata holds SoapBucket-specific metadata injected into the final
// streaming chunk. Since HTTP headers are sent before the body in streaming
// responses, cost and latency data are delivered inline via this field.
type SbMetadata struct {
	CostUSD           float64 `json:"cost_usd"`
	Provider          string  `json:"provider"`
	Model             string  `json:"model"`
	InputTokens       int     `json:"input_tokens"`
	OutputTokens      int     `json:"output_tokens"`
	TotalTokens       int     `json:"total_tokens"`
	CacheHit          bool    `json:"cache_hit"`
	LatencyMs         int64   `json:"latency_ms"`
	RequestID         string  `json:"request_id"`
	ProviderRequestID string  `json:"provider_request_id,omitempty"`
}

// StreamChoice represents a streaming choice delta.
type StreamChoice struct {
	Index        int         `json:"index"`
	Delta        StreamDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
	Logprobs     any         `json:"logprobs,omitempty"`
}

// StreamDelta represents the incremental content in a stream chunk.
type StreamDelta struct {
	Role      string          `json:"role,omitempty"`
	Content   *string         `json:"content,omitempty"`
	ToolCalls []ToolCallDelta `json:"tool_calls,omitempty"`
}

// ToolCallDelta represents an incremental tool call in streaming.
type ToolCallDelta struct {
	Index    int               `json:"index"`
	ID       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Function *ToolCallFunction `json:"function,omitempty"`
}

// EmbeddingRequest matches the OpenAI embeddings API.
type EmbeddingRequest struct {
	Input          any    `json:"input"`
	Model          string `json:"model"`
	EncodingFormat string `json:"encoding_format,omitempty"`
	Dimensions     *int   `json:"dimensions,omitempty"`
	User           string `json:"user,omitempty"`
}

// EmbeddingResponse matches the OpenAI embeddings response.
type EmbeddingResponse struct {
	Object string          `json:"object"`
	Data   []EmbeddingData `json:"data"`
	Model  string          `json:"model"`
	Usage  *EmbeddingUsage `json:"usage,omitempty"`
}

// EmbeddingData represents a single embedding.
type EmbeddingData struct {
	Object    string    `json:"object"`
	Embedding []float32 `json:"embedding"`
	Index     int       `json:"index"`
}

// EmbeddingUsage tracks embedding token usage.
type EmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// ModelInfo represents a model entry from the models endpoint.
type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// ModelListResponse matches the OpenAI models list response.
type ModelListResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

// ResponsesRequest matches the subset of the OpenAI Responses API we need for
// routing, telemetry, and memory capture.
type ResponsesRequest struct {
	Model             string            `json:"model"`
	Input             json.RawMessage   `json:"input,omitempty"`
	Instructions      string            `json:"instructions,omitempty"`
	Stream            *bool             `json:"stream,omitempty"`
	Tools             []Tool            `json:"tools,omitempty"`
	User              string            `json:"user,omitempty"`
	PromptID          string            `json:"prompt_id,omitempty"`
	PromptEnvironment string            `json:"prompt_environment,omitempty"`
	PromptVersion     *int              `json:"prompt_version,omitempty"`
	PromptVariables   map[string]string `json:"prompt_variables,omitempty"`

	// SoapBucket extensions (not forwarded to providers)
	SBTags         map[string]string `json:"sb_tags,omitempty"`
	SBCacheControl *CacheControl     `json:"sb_cache_control,omitempty"`
	SBPriority     *int              `json:"sb_priority,omitempty"`
}

// IsStreaming reports whether the ResponsesRequest is streaming.
func (r *ResponsesRequest) IsStreaming() bool {
	return r.Stream != nil && *r.Stream
}

// ResponsesResponse represents the response from a responses operation.
type ResponsesResponse struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Model   string          `json:"model,omitempty"`
	Output  json.RawMessage `json:"output,omitempty"`
	Usage   *ResponseUsage  `json:"usage,omitempty"`
	Status  string          `json:"status,omitempty"`
	Created int64           `json:"created,omitempty"`
}

// ResponseUsage represents a response usage.
type ResponseUsage struct {
	InputTokens  int                        `json:"input_tokens"`
	OutputTokens int                        `json:"output_tokens"`
	TotalTokens  int                        `json:"total_tokens"`
	InputDetails *ResponseUsageInputDetails `json:"input_tokens_details,omitempty"`
}

// ResponseUsageInputDetails represents a response usage input details.
type ResponseUsageInputDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

// ToUsage performs the to usage operation on the ResponseUsage.
func (u *ResponseUsage) ToUsage() *Usage {
	if u == nil {
		return nil
	}
	return &Usage{
		PromptTokens:       u.InputTokens,
		CompletionTokens:   u.OutputTokens,
		TotalTokens:        u.TotalTokens,
		PromptTokensCached: u.CachedTokens(),
	}
}

// CachedTokens performs the cached tokens operation on the ResponseUsage.
func (u *ResponseUsage) CachedTokens() int {
	if u == nil || u.InputDetails == nil {
		return 0
	}
	return u.InputDetails.CachedTokens
}

// ResponsesOutputText performs the responses output text operation.
func ResponsesOutputText(output json.RawMessage) string {
	if len(output) == 0 {
		return ""
	}

	var items []map[string]any
	if err := json.Unmarshal(output, &items); err != nil {
		return ""
	}

	var b strings.Builder
	for _, item := range items {
		content, _ := item["content"].([]any)
		for _, rawPart := range content {
			part, _ := rawPart.(map[string]any)
			if part == nil {
				continue
			}
			switch part["type"] {
			case "output_text", "text":
				if s, ok := part["text"].(string); ok {
					b.WriteString(s)
				}
			}
		}
	}
	return b.String()
}

// ResponsesInputMessages performs the responses input messages operation.
func ResponsesInputMessages(input json.RawMessage, instructions string) []Message {
	var msgs []Message
	if instructions != "" {
		msgs = append(msgs, mustTextMessage("system", instructions))
	}
	if len(input) == 0 {
		return msgs
	}

	var rawString string
	if err := json.Unmarshal(input, &rawString); err == nil {
		msgs = append(msgs, mustTextMessage("user", rawString))
		return msgs
	}

	var messageList []map[string]any
	if err := json.Unmarshal(input, &messageList); err == nil {
		for _, item := range messageList {
			role, _ := item["role"].(string)
			if role == "" {
				role = "user"
			}
			switch content := item["content"].(type) {
			case string:
				msgs = append(msgs, mustTextMessage(role, content))
			case []any:
				raw, err := json.Marshal(content)
				if err == nil {
					msgs = append(msgs, Message{Role: role, Content: raw})
				}
			case map[string]any:
				raw, err := json.Marshal(content)
				if err == nil {
					msgs = append(msgs, Message{Role: role, Content: raw})
				}
			}
		}
	}

	return msgs
}

func mustTextMessage(role, text string) Message {
	return Message{Role: role, Content: json.RawMessage(strconv.Quote(text))}
}

// RequestMetadata holds internal metadata about a request for metrics/logging.
type RequestMetadata struct {
	StartTime       time.Time
	Provider        string
	Model           string
	Streaming       bool
	CacheHit        bool
	CacheType       string
	GuardrailsRun   []string
	FallbackUsed    bool
	FromProvider    string
	ToProvider      string
	RoutingStrategy string
	Tags            map[string]string
}

// GuardrailCheckResult is a normalized standalone guardrail check result.
type GuardrailCheckResult struct {
	Type      string         `json:"type"`
	Passed    bool           `json:"passed"`
	Action    string         `json:"action,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Score     float64        `json:"score,omitempty"`
	LatencyMS float64        `json:"latency_ms,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}
