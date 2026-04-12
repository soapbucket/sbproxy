// sampling.go defines types for MCP sampling/createMessage requests.
package mcp

import (
	"encoding/json"
)

// SamplingCreateMessageParams contains the parameters for sampling/createMessage.
// The server sends this request to the client to request LLM inference.
type SamplingCreateMessageParams struct {
	Messages         []SamplingMessage      `json:"messages"`
	ModelPreferences *ModelPreferences      `json:"modelPreferences,omitempty"`
	SystemPrompt     string                 `json:"systemPrompt,omitempty"`
	IncludeContext   string                 `json:"includeContext,omitempty"` // "none", "thisServer", "allServers"
	Temperature      *float64               `json:"temperature,omitempty"`
	MaxTokens        int                    `json:"maxTokens"`
	StopSequences    []string               `json:"stopSequences,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// SamplingMessage is a message in a sampling request.
type SamplingMessage struct {
	Role    string  `json:"role"` // "user" or "assistant"
	Content Content `json:"content"`
}

// ModelPreferences expresses the server's model preference to the client.
type ModelPreferences struct {
	Hints                []ModelHint `json:"hints,omitempty"`
	CostPriority         *float64    `json:"costPriority,omitempty"`
	SpeedPriority        *float64    `json:"speedPriority,omitempty"`
	IntelligencePriority *float64    `json:"intelligencePriority,omitempty"`
}

// ModelHint is a hint about which model to use.
type ModelHint struct {
	Name string `json:"name,omitempty"`
}

// SamplingCreateMessageResult contains the result of sampling/createMessage from the client.
type SamplingCreateMessageResult struct {
	Role       string  `json:"role"`
	Content    Content `json:"content"`
	Model      string  `json:"model"`
	StopReason string  `json:"stopReason,omitempty"` // "endTurn", "stopSequence", "maxTokens"
}

// BuildSamplingRequest creates a JSON-RPC request for sampling/createMessage.
// This is sent from the MCP server to the client (reverse direction).
func BuildSamplingRequest(id interface{}, params *SamplingCreateMessageParams) ([]byte, error) {
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "sampling/createMessage",
		Params:  paramsBytes,
	}

	return json.Marshal(req)
}
