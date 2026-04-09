// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

var (
	aiEnvOnce sync.Once
	aiEnvVal  *cel.Env
	aiEnvErr  error
)

// AIContextVars holds the AI-specific variable values for CEL evaluation.
type AIContextVars struct {
	Model          string            // request model name
	Provider       string            // currently selected provider
	Messages       []map[string]any  // simplified message list
	MessageCount   int               // number of messages
	TokenEstimate  int               // estimated input tokens
	HasTools       bool              // whether request has tool calls
	IsStreaming     bool              // whether request is streaming
	Tags           map[string]string // request tags
	Budget         map[string]any    // budget utilization info
	ProviderHealth map[string]any    // provider health status
}

// GetAIEnv returns the shared CEL environment for AI routing expressions.
// This is a superset of the request env, adding ai, budget, and provider_health variables.
func GetAIEnv() (*cel.Env, error) {
	aiEnvOnce.Do(func() {
		opts := append(requestEnvOpts(),
			cel.Variable("ai", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("budget", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("provider_health", cel.MapType(cel.StringType, cel.DynType)),
			ext.Strings(),
		)
		aiEnvVal, aiEnvErr = cel.NewEnv(opts...)
	})
	return aiEnvVal, aiEnvErr
}

// BuildAIActivation builds the activation map for CEL evaluation from AI context variables
// and optional request variables. The returned map can be passed directly to cel.Program.Eval().
func BuildAIActivation(vars *AIContextVars, requestVars map[string]any) map[string]any {
	if vars == nil {
		vars = &AIContextVars{}
	}

	aiMap := map[string]any{
		"model":          vars.Model,
		"provider":       vars.Provider,
		"message_count":  int64(vars.MessageCount),
		"token_estimate": int64(vars.TokenEstimate),
		"has_tools":      vars.HasTools,
		"is_streaming":   vars.IsStreaming,
	}

	budgetMap := make(map[string]any)
	if vars.Budget != nil {
		for k, v := range vars.Budget {
			budgetMap[k] = v
		}
	}
	// Provide defaults if not set
	if _, ok := budgetMap["utilization"]; !ok {
		budgetMap["utilization"] = 0.0
	}
	if _, ok := budgetMap["remaining_tokens"]; !ok {
		budgetMap["remaining_tokens"] = int64(0)
	}
	if _, ok := budgetMap["period"]; !ok {
		budgetMap["period"] = ""
	}

	providerHealthMap := make(map[string]any)
	if vars.ProviderHealth != nil {
		for k, v := range vars.ProviderHealth {
			providerHealthMap[k] = v
		}
	}

	activation := map[string]any{
		"ai":              aiMap,
		"budget":          budgetMap,
		"provider_health": providerHealthMap,
	}

	// Merge request variables (request, session, origin, server, vars, features, client, ctx)
	if requestVars != nil {
		for k, v := range requestVars {
			activation[k] = v
		}
	}

	// Ensure all standard request env variables exist to avoid CEL runtime errors
	for _, key := range []string{"request", "session", "origin", "server", "vars", "features", "client", "ctx"} {
		if _, ok := activation[key]; !ok {
			activation[key] = map[string]any{}
		}
	}

	return activation
}
