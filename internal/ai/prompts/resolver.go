package prompts

import (
	"context"
	"fmt"
	"strings"
)

// Resolver resolves prompt templates with variables.
type Resolver struct {
	store Store
}

// NewResolver creates a new prompt resolver.
func NewResolver(store Store) *Resolver {
	return &Resolver{store: store}
}

// Resolve looks up a prompt by ID, gets the active version (or specified version),
// and replaces {{variable_name}} placeholders with provided values.
func (r *Resolver) Resolve(ctx context.Context, id string, version *int, variables map[string]string) (*ResolvedPrompt, error) {
	prompt, err := r.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	targetVersion := prompt.ActiveVersion
	if version != nil {
		targetVersion = *version
	}

	var pv *LegacyVersion
	for _, v := range prompt.Versions {
		if v.Version == targetVersion {
			cp := v
			pv = &cp
			break
		}
	}
	if pv == nil {
		return nil, fmt.Errorf("version %d not found for prompt %s", targetVersion, id)
	}

	content := substituteVariables(pv.Template, variables)

	return &ResolvedPrompt{
		Content:  content,
		Model:    pv.Model,
		PromptID: id,
		Version:  pv.Version,
	}, nil
}

// substituteVariables replaces {{variable_name}} placeholders with values.
func substituteVariables(template string, variables map[string]string) string {
	if len(variables) == 0 {
		return template
	}
	oldnew := make([]string, 0, len(variables)*2)
	for k, v := range variables {
		oldnew = append(oldnew, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(oldnew...).Replace(template)
}
