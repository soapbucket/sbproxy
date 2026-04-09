package prompts

import (
	"time"
)

// PromptTemplate represents a managed prompt template with version history.
type PromptTemplate struct {
	ID          string            `json:"id"`
	WorkspaceID string            `json:"workspace_id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Messages    []PromptMessage   `json:"messages"`
	Variables   []VariableDef     `json:"variables,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
}

// PromptMessage represents a single message in a prompt template.
// Content may contain {{variable}} Mustache placeholders.
type PromptMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// VariableDef defines a variable that can be used in a prompt template.
type VariableDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// PromptVersion represents a specific version of a prompt template.
type PromptVersion struct {
	Version   int             `json:"version"`
	Template  *PromptTemplate `json:"template"`
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by,omitempty"`
}

// RenderedMessage is the result of rendering a prompt message with variables.
type RenderedMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Prompt is kept for backward compatibility with existing code (injection, resolver, A/B testing).
type Prompt struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	ActiveVersion int               `json:"active_version"`
	Versions      []LegacyVersion   `json:"versions"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// LegacyVersion represents a specific version of a prompt (legacy format).
type LegacyVersion struct {
	Version   int       `json:"version"`
	Template  string    `json:"template"`
	Model     string    `json:"model,omitempty"`
	Variables []string  `json:"variables,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ResolvedPrompt is the result of resolving a prompt with variables.
type ResolvedPrompt struct {
	Content  string `json:"content"`
	Model    string `json:"model,omitempty"`
	PromptID string `json:"prompt_id"`
	Version  int    `json:"version"`
}

// ABTestConfig configures prompt A/B testing.
type ABTestConfig struct {
	Variants []ABTestVariant `json:"variants"`
}

// ABTestVariant represents a single variant in an A/B test.
type ABTestVariant struct {
	PromptID string `json:"prompt_id"`
	Version  int    `json:"version,omitempty"` // 0 means active version
	Weight   int    `json:"weight"`            // Relative weight (e.g., 70, 30)
}

// ABTestResult records which variant was selected.
type ABTestResult struct {
	PromptID string `json:"prompt_id"`
	Version  int    `json:"version"`
	Variant  int    `json:"variant_index"`
}
