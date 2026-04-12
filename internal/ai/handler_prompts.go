// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

type promptRenderResult struct {
	Rendered     string   `json:"rendered"`
	SystemPrompt string   `json:"system_prompt"`
	Model        string   `json:"model"`
	Temperature  *float64 `json:"temperature"`
	MaxTokens    *int     `json:"max_tokens"`
	VersionNumber int     `json:"version_number"`
}

func (h *Handler) resolvePromptForChat(ctx context.Context, req *ChatCompletionRequest) error {
	if req == nil || req.PromptID == "" || h.config.PromptRegistryURL == "" {
		return nil
	}
	rendered, err := h.fetchPrompt(ctx, req.PromptID, req.PromptEnvironment, req.PromptVersion, req.PromptVariables)
	if err != nil {
		return err
	}
	h.annotatePromptUsage(ctx, req.PromptID, req.PromptEnvironment, rendered.VersionNumber)
	if req.Model == "" && rendered.Model != "" {
		req.Model = rendered.Model
	}
	if req.Temperature == nil && rendered.Temperature != nil {
		req.Temperature = rendered.Temperature
	}
	if req.MaxTokens == nil && rendered.MaxTokens != nil {
		req.MaxTokens = rendered.MaxTokens
	}
	if len(req.Messages) == 0 {
		if rendered.SystemPrompt != "" {
			req.Messages = append(req.Messages, mustTextMessage("system", rendered.SystemPrompt))
		}
		req.Messages = append(req.Messages, mustTextMessage("user", rendered.Rendered))
	}
	return nil
}

func (h *Handler) resolvePromptForResponses(ctx context.Context, req *ResponsesRequest) error {
	if req == nil || req.PromptID == "" || h.config.PromptRegistryURL == "" {
		return nil
	}
	rendered, err := h.fetchPrompt(ctx, req.PromptID, req.PromptEnvironment, req.PromptVersion, req.PromptVariables)
	if err != nil {
		return err
	}
	h.annotatePromptUsage(ctx, req.PromptID, req.PromptEnvironment, rendered.VersionNumber)
	if req.Model == "" && rendered.Model != "" {
		req.Model = rendered.Model
	}
	if req.Instructions == "" && rendered.SystemPrompt != "" {
		req.Instructions = rendered.SystemPrompt
	}
	if len(req.Input) == 0 {
		req.Input = mustMarshalMessages([]Message{mustTextMessage("user", rendered.Rendered)})
	}
	return nil
}

func (h *Handler) fetchPrompt(ctx context.Context, promptID string, environment string, version *int, variables map[string]string) (*promptRenderResult, error) {
	if h.config.PromptRegistryURL == "" {
		return nil, fmt.Errorf("prompt registry URL not configured")
	}
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.Config == nil {
		return nil, fmt.Errorf("request config unavailable for prompt resolution")
	}
	callbackSecret := ""
	if rd.Secrets != nil {
		callbackSecret = rd.Secrets["CALLBACK_SECRET"]
	}
	if callbackSecret == "" {
		return nil, fmt.Errorf("CALLBACK_SECRET not available for prompt resolution")
	}
	workspaceID := reqctx.ConfigParams(rd.Config).GetWorkspaceID()
	body := map[string]any{
		"workspace_id": workspaceID,
		"prompt_id":    promptID,
		"variables":    variables,
		"environment":  environment,
	}
	if version != nil {
		body["version"] = *version
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.config.PromptRegistryURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Callback-Secret", callbackSecret)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("prompt registry returned status %d", resp.StatusCode)
	}
	var rendered promptRenderResult
	if err := json.NewDecoder(resp.Body).Decode(&rendered); err != nil {
		return nil, err
	}
	rendered.Rendered = strings.TrimSpace(rendered.Rendered)
	return &rendered, nil
}

func (h *Handler) annotatePromptUsage(ctx context.Context, promptID, environment string, versionNumber int) {
	if rd := reqctx.GetRequestData(ctx); rd != nil {
		if promptID != "" {
			rd.AddDebugHeader("X-Sb-Prompt-Id", promptID)
		}
		if environment != "" {
			rd.AddDebugHeader("X-Sb-Prompt-Environment", environment)
		}
		if versionNumber > 0 {
			rd.AddDebugHeader("X-Sb-Prompt-Version", fmt.Sprintf("%d", versionNumber))
		}
	}
}
