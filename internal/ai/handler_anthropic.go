// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// handleAnthropicMessages handles Anthropic Messages API requests at /v1/messages.
// It translates the incoming Anthropic request to OpenAI format, processes it through
// the standard chat completion pipeline, then translates the response back to Anthropic format.
func (h *Handler) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteAnthropicError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var anthropicReq AnthropicRequest
	if err := json.NewDecoder(body).Decode(&anthropicReq); err != nil {
		WriteAnthropicError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	// Validate required Anthropic fields
	if anthropicReq.Model == "" {
		WriteAnthropicError(w, ErrInvalidRequest("model is required"))
		return
	}
	if anthropicReq.MaxTokens <= 0 {
		WriteAnthropicError(w, ErrInvalidRequest("max_tokens is required and must be > 0"))
		return
	}
	if len(anthropicReq.Messages) == 0 {
		WriteAnthropicError(w, ErrInvalidRequest("messages is required"))
		return
	}

	// Translate Anthropic request to OpenAI format
	openAIReq, err := AnthropicToOpenAI(&anthropicReq)
	if err != nil {
		WriteAnthropicError(w, ErrInvalidRequest(fmt.Sprintf("request translation error: %v", err)))
		return
	}

	// Apply default model if needed
	if openAIReq.Model == "" && h.config.DefaultModel != "" {
		openAIReq.Model = h.config.DefaultModel
	}

	// Echo X-Request-ID back to the caller for SDK correlation
	compat := NewCompatLayer()
	compat.EchoRequestID(r, w)

	// Set Anthropic-specific response headers
	w.Header().Set("X-SB-API-Format", "anthropic")

	// Validate model access
	if aiErr := h.validateModelAccess(r.Context(), openAIReq.Model); aiErr != nil {
		WriteAnthropicError(w, aiErr)
		return
	}

	// Track user from metadata
	if anthropicReq.Metadata != nil && anthropicReq.Metadata.UserID != "" {
		if rd := reqctx.GetRequestData(r.Context()); rd != nil {
			rd.AddDebugHeader("X-Sb-AI-User", anthropicReq.Metadata.UserID)
		}
	}

	// Run input guardrails
	if h.config.Guardrails != nil && h.config.Guardrails.HasInput() {
		msgs, block, gerr := h.config.Guardrails.CheckInput(r.Context(), openAIReq.Messages, openAIReq.Model)
		if gerr != nil {
			WriteAnthropicError(w, ErrInternal(fmt.Sprintf("guardrail error: %v", gerr)))
			return
		}
		if block != nil {
			WriteAnthropicError(w, ErrGuardrailBlocked(block.Name, block.Reason))
			return
		}
		openAIReq.Messages = msgs
	}

	// Budget enforcement
	if h.config.Budget != nil {
		scopeValues := h.budgetScopeValues(r.Context(), openAIReq.Model, openAIReq.SBTags)
		if downModel, snapshot, ok := h.config.Budget.ShouldDowngradeScopes(r.Context(), scopeValues, openAIReq.Model); ok {
			originalModel := openAIReq.Model
			openAIReq.Model = downModel
			if rd := reqctx.GetRequestData(r.Context()); rd != nil {
				rd.AddDebugHeader("X-Sb-Original-Model", originalModel)
			}
			utilization := 0.0
			if snapshot != nil {
				utilization = snapshot.Utilization
			}
			h.emitModelDowngraded(r.Context(), originalModel, downModel, utilization)
		}
		if decision, budgetErr := h.config.Budget.CheckScopes(r.Context(), scopeValues, 0); budgetErr != nil {
			scope := "workspace"
			scopeValue := ""
			period := ""
			currentUSD := 0.0
			limitUSD := 0.0
			if decision != nil {
				scope = decision.Limit.Scope
				scopeValue = decision.ScopeValue
				period = decision.Limit.Period
				limitUSD = decision.Limit.MaxCostUSD
				if decision.Usage != nil {
					currentUSD = decision.Usage.CostUSD
				}
			}
			h.emitBudgetExceeded(r.Context(), scope, scopeValue, period, currentUSD, limitUSD, "reject")
			if aiErr, ok := budgetErr.(*AIError); ok {
				WriteAnthropicError(w, aiErr)
			} else {
				WriteAnthropicError(w, ErrInternal(fmt.Sprintf("budget check error: %v", budgetErr)))
			}
			return
		}
	}

	// Route to provider and process
	maxAttempts := h.router.MaxAttempts()
	exclude := make(map[string]bool)
	var prevProvider string

	for attempt := 0; attempt < maxAttempts; attempt++ {
		baseExclude, _ := h.providerExclusionsWithReasons(r.Context())
		for k, v := range baseExclude {
			exclude[k] = v
		}
		pcfg, routeErr := h.router.Route(r.Context(), openAIReq.Model, exclude)
		if routeErr != nil {
			WriteAnthropicError(w, routeErr.(*AIError))
			return
		}

		AIRoutingDecision(h.router.Strategy(), pcfg.Name, openAIReq.Model)

		if prevProvider != "" && prevProvider != pcfg.Name {
			AIFallback(prevProvider, pcfg.Name)
		}
		prevProvider = pcfg.Name

		entry, ok := h.providers[pcfg.Name]
		if !ok {
			exclude[pcfg.Name] = true
			continue
		}

		// Check for per-request provider key overrides
		providerCfg := entry.config
		if rd := reqctx.GetRequestData(r.Context()); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil {
			if pkMap, ok := rd.SessionData.AuthData.Data["provider_keys"].(map[string]any); ok {
				if keyVal, ok := pkMap[pcfg.Name].(string); ok && keyVal != "" {
					cfgCopy := *providerCfg
					cfgCopy.APIKey = keyVal
					providerCfg = &cfgCopy
				}
			}
		}
		resolvedEntry := providerEntry{provider: entry.provider, config: providerCfg}

		// Filter unsupported parameters
		NewParamFilter().FilterParams(pcfg.Type, openAIReq)

		// Add debug headers
		if rd := reqctx.GetRequestData(r.Context()); rd != nil {
			rd.AddDebugHeader(httputil.HeaderXSbAIModel, openAIReq.Model)
			rd.AddDebugHeader(httputil.HeaderXSbAIProvider, pcfg.Name)
		}

		// Concurrency limiter: acquire a slot before dispatching to the provider.
		if h.ConcurrencyLimiter != nil {
			acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
			if acqErr != nil || !acquired {
				exclude[pcfg.Name] = true
				continue
			}
		}

		// Track in-flight
		h.router.Tracker().IncrInFlight(pcfg.Name)
		start := time.Now()
		streaming := openAIReq.IsStreaming()

		var usage *Usage
		var writeErr error

		if streaming {
			usage, writeErr = h.handleAnthropicStreaming(w, r, openAIReq, resolvedEntry)
		} else {
			usage, writeErr = h.handleAnthropicNonStreaming(w, r, openAIReq, resolvedEntry)
		}

		latency := time.Since(start)
		h.router.Tracker().DecrInFlight(pcfg.Name)

		// Release concurrency slot after dispatch completes.
		if h.ConcurrencyLimiter != nil {
			h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
		}

		if writeErr != nil {
			h.router.Tracker().RecordError(pcfg.Name)
			errorType := "unknown"
			if aiErr, ok := writeErr.(*AIError); ok {
				errorType = aiErr.Type
			}
			AIProviderError(pcfg.Name, errorType)

			if aiErr, ok := writeErr.(*AIError); ok && h.router.ShouldRetry(aiErr.StatusCode) && attempt < maxAttempts-1 {
				exclude[pcfg.Name] = true
				retryBackoff(r.Context(), attempt, h.router.RetryConfig().BackoffMS)
				continue
			}
			if aiErr, ok := writeErr.(*AIError); ok {
				WriteAnthropicError(w, aiErr)
			} else {
				WriteAnthropicError(w, ErrInternal(writeErr.Error()))
			}
			return
		}

		h.router.Tracker().RecordSuccess(pcfg.Name, latency)
		h.recordUsage(r.Context(), pcfg.Name, openAIReq.Model, usage, streaming, latency, 0, 0)
		return
	}

	WriteAnthropicError(w, ErrAllProvidersUnavailable())
}

// handleAnthropicNonStreaming handles a non-streaming Anthropic request.
func (h *Handler) handleAnthropicNonStreaming(w http.ResponseWriter, r *http.Request, req *ChatCompletionRequest, entry providerEntry) (*Usage, error) {
	start := time.Now()
	resp, err := entry.provider.ChatCompletion(r.Context(), req, entry.config)
	if err != nil {
		return nil, err
	}

	// Fill in defaults
	if resp.Object == "" {
		resp.Object = "chat.completion"
	}
	if resp.Created == 0 {
		resp.Created = time.Now().Unix()
	}

	// Run output guardrails
	if h.config.Guardrails != nil && h.config.Guardrails.HasOutput() {
		var outputMsgs []Message
		for _, choice := range resp.Choices {
			outputMsgs = append(outputMsgs, choice.Message)
		}
		_, block, gerr := h.config.Guardrails.CheckOutput(r.Context(), outputMsgs, req.Model)
		if gerr != nil {
			return nil, ErrInternal(fmt.Sprintf("output guardrail error: %v", gerr))
		}
		if block != nil {
			return nil, ErrGuardrailBlocked(block.Name, block.Reason)
		}
	}

	// Translate response to Anthropic format
	anthropicResp, err := OpenAIToAnthropic(resp)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("response translation error: %v", err))
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Sb-Latency-Ms", strconv.FormatInt(time.Since(start).Milliseconds(), 10))
	respBytes, _ := json.Marshal(anthropicResp)
	w.Write(respBytes)

	return resp.Usage, nil
}

// handleAnthropicStreaming handles a streaming Anthropic request.
func (h *Handler) handleAnthropicStreaming(w http.ResponseWriter, r *http.Request, req *ChatCompletionRequest, entry providerEntry) (*Usage, error) {
	if !entry.provider.SupportsStreaming() {
		return nil, ErrInvalidRequest(fmt.Sprintf("provider %q does not support streaming", entry.config.Name))
	}

	stream, err := entry.provider.ChatCompletionStream(r.Context(), req, entry.config)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	sw := NewSSEWriter(w)
	defer ReleaseSSEWriter(sw)
	sw.WriteHeaders()

	var accumulated *Usage
	isFirst := true
	contentBlockStarted := false

	for {
		chunk, readErr := stream.Read()
		if readErr != nil {
			if readErr == io.EOF {
				return accumulated, nil
			}
			// Write error as Anthropic stream event
			errEvt := AnthropicStreamEvent{
				Type: "error",
			}
			errData, _ := json.Marshal(map[string]interface{}{
				"type": "error",
				"error": map[string]string{
					"type":    "api_error",
					"message": readErr.Error(),
				},
			})
			errEvt.Data = errData
			WriteAnthropicSSEEvent(sw, errEvt)
			return accumulated, nil
		}

		if chunk.Usage != nil {
			accumulated = chunk.Usage
		}
		if chunk.Object == "" {
			chunk.Object = "chat.completion.chunk"
		}
		if chunk.Created == 0 {
			chunk.Created = time.Now().Unix()
		}

		events, newState := OpenAIStreamToAnthropic(chunk, isFirst, contentBlockStarted)
		contentBlockStarted = newState
		isFirst = false

		for _, evt := range events {
			if err := WriteAnthropicSSEEvent(sw, evt); err != nil {
				return accumulated, nil // client disconnected
			}
		}
	}
}
