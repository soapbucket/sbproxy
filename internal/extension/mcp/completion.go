package mcp

import (
	"encoding/json"
	"strings"
)

// CompletionParams contains the parameters for completion/complete.
type CompletionParams struct {
	Ref      CompletionRef `json:"ref"`
	Argument struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"argument"`
}

// CompletionRef identifies what is being completed.
type CompletionRef struct {
	Type string `json:"type"` // "ref/prompt" or "ref/resource"
	Name string `json:"name,omitempty"` // Prompt name
	URI  string `json:"uri,omitempty"`  // Resource URI
}

// CompletionResult contains the result of completion/complete.
type CompletionResult struct {
	Completion CompletionValues `json:"completion"`
}

// CompletionValues contains the completion suggestions.
type CompletionValues struct {
	Values  []string `json:"values"`
	HasMore bool     `json:"hasMore,omitempty"`
	Total   int      `json:"total,omitempty"`
}

// CompletePromptArgument generates completions for a prompt argument.
func CompletePromptArgument(registry *PromptRegistry, promptName, argName, prefix string) *CompletionResult {
	prompt, err := registry.Get(promptName)
	if err != nil {
		return &CompletionResult{Completion: CompletionValues{Values: []string{}}}
	}

	// Find the argument
	var found bool
	for _, arg := range prompt.Arguments {
		if arg.Name == argName {
			found = true
			break
		}
	}

	if !found {
		return &CompletionResult{Completion: CompletionValues{Values: []string{}}}
	}

	// For static arguments, we can suggest from known values.
	// For dynamic arguments, return empty (requires external data).
	return &CompletionResult{Completion: CompletionValues{Values: []string{}}}
}

// CompleteResourceURI generates completions for resource URIs.
func CompleteResourceURI(resources []ResourceConfig, prefix string) *CompletionResult {
	var matches []string
	for _, r := range resources {
		if strings.HasPrefix(r.URI, prefix) {
			matches = append(matches, r.URI)
		}
	}
	if matches == nil {
		matches = []string{}
	}

	return &CompletionResult{
		Completion: CompletionValues{
			Values: matches,
			Total:  len(matches),
		},
	}
}

// ParseCompletionParams parses the params for a completion/complete request.
func (r *JSONRPCRequest) ParseCompletionParams() (*CompletionParams, *MCPError) {
	if r.Params == nil {
		return nil, NewProtocolError(CodeInvalidParams, "params required for completion/complete", nil)
	}

	var params CompletionParams
	if err := json.Unmarshal(r.Params, &params); err != nil {
		return nil, NewProtocolError(CodeInvalidParams, "invalid completion params", err.Error())
	}

	return &params, nil
}
