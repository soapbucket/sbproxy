// prompts.go manages MCP prompt registration, lookup, and template rendering.
package mcp

import (
	"context"
	"fmt"

	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

// PromptRegistry manages prompt registration and lookup.
type PromptRegistry struct {
	prompts    map[string]*PromptConfig
	promptList []Prompt
}

// NewPromptRegistry creates a new prompt registry.
func NewPromptRegistry() *PromptRegistry {
	return &PromptRegistry{
		prompts:    make(map[string]*PromptConfig),
		promptList: []Prompt{},
	}
}

// Register registers a prompt configuration.
func (r *PromptRegistry) Register(prompt PromptConfig) error {
	if prompt.Name == "" {
		return fmt.Errorf("prompt name is required")
	}
	if _, exists := r.prompts[prompt.Name]; exists {
		return fmt.Errorf("prompt %s already registered", prompt.Name)
	}

	r.prompts[prompt.Name] = &prompt
	r.promptList = append(r.promptList, Prompt{
		Name:        prompt.Name,
		Description: prompt.Description,
		Arguments:   prompt.Arguments,
	})

	return nil
}

// Get returns a prompt by name.
func (r *PromptRegistry) Get(name string) (*PromptConfig, error) {
	prompt, ok := r.prompts[name]
	if !ok {
		return nil, fmt.Errorf("prompt not found: %s", name)
	}
	return prompt, nil
}

// List returns all registered prompts.
func (r *PromptRegistry) List() []Prompt {
	return r.promptList
}

// RenderPrompt renders a prompt with the given arguments.
func RenderPrompt(ctx context.Context, prompt *PromptConfig, args map[string]string) (*GetPromptResult, error) {
	// Validate required arguments
	for _, arg := range prompt.Arguments {
		if arg.Required {
			if _, ok := args[arg.Name]; !ok {
				return nil, fmt.Errorf("missing required argument: %s", arg.Name)
			}
		}
	}

	// Build template context
	templateCtx := map[string]interface{}{
		"arguments": args,
	}

	// Render each message
	messages := make([]PromptResultMessage, 0, len(prompt.Messages))
	for _, msg := range prompt.Messages {
		rendered, err := templateresolver.ResolveWithContext(msg.Content, templateCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to render message: %w", err)
		}

		messages = append(messages, PromptResultMessage{
			Role: msg.Role,
			Content: Content{
				Type: "text",
				Text: rendered,
			},
		})
	}

	return &GetPromptResult{
		Description: prompt.Description,
		Messages:    messages,
	}, nil
}
