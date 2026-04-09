package prompts

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cbroglie/mustache"
)

// variablePattern matches Mustache variable references like {{varName}}.
var variablePattern = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)

// TemplateRenderer renders PromptTemplate messages using Mustache.
type TemplateRenderer struct{}

// NewTemplateRenderer creates a new TemplateRenderer.
func NewTemplateRenderer() *TemplateRenderer {
	return &TemplateRenderer{}
}

// Render validates required variables and renders each message's Content using Mustache.
func (tr *TemplateRenderer) Render(template *PromptTemplate, variables map[string]string) ([]RenderedMessage, error) {
	if err := ValidateVariables(template, variables); err != nil {
		return nil, err
	}

	// Build the context map with defaults applied.
	ctx := buildContext(template, variables)

	rendered := make([]RenderedMessage, len(template.Messages))
	for i, msg := range template.Messages {
		content, err := renderMustache(msg.Content, ctx)
		if err != nil {
			return nil, fmt.Errorf("rendering message %d (role=%s): %w", i, msg.Role, err)
		}
		rendered[i] = RenderedMessage{
			Role:    msg.Role,
			Content: content,
		}
	}
	return rendered, nil
}

// ValidateVariables checks that all required variables are provided.
// Variables with defaults are not required to be in the input map.
func ValidateVariables(template *PromptTemplate, variables map[string]string) error {
	var missing []string
	for _, v := range template.Variables {
		if !v.Required {
			continue
		}
		if _, ok := variables[v.Name]; !ok {
			if v.Default == "" {
				missing = append(missing, v.Name)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ExtractVariables extracts {{var}} names from a Mustache template string.
func ExtractVariables(content string) []string {
	matches := variablePattern.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}
	return result
}

// buildContext merges default values with provided variables.
func buildContext(template *PromptTemplate, variables map[string]string) map[string]string {
	ctx := make(map[string]string)
	// Apply defaults first.
	for _, v := range template.Variables {
		if v.Default != "" {
			ctx[v.Name] = v.Default
		}
	}
	// Override with provided variables.
	for k, v := range variables {
		ctx[k] = v
	}
	return ctx
}

// renderMustache renders a single template string with the given context.
func renderMustache(tmplStr string, ctx map[string]string) (string, error) {
	tmpl, err := mustache.ParseString(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	// Convert map[string]string to map[string]interface{} for mustache.
	data := make(map[string]interface{}, len(ctx))
	for k, v := range ctx {
		data[k] = v
	}
	result, err := tmpl.Render(data)
	if err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}
	return result, nil
}
