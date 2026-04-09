// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/keys"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

type passthroughPayload struct {
	Body         []byte
	ContentType  string
	Model        string
	Streaming    bool
	Tags         map[string]string
	RequestInput []Message
}

func (h *Handler) readPassthroughPayload(w http.ResponseWriter, r *http.Request, op Operation) (*passthroughPayload, error) {
	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	payload := &passthroughPayload{
		Body:        raw,
		ContentType: r.Header.Get("Content-Type"),
	}

	mediaType, params, _ := mime.ParseMediaType(payload.ContentType)
	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		if err := populateMultipartPayload(payload, params["boundary"], op); err != nil {
			return nil, err
		}
	case len(raw) > 0:
		if err := populateJSONPayload(payload, op); err != nil {
			return nil, err
		}
	}

	return payload, nil
}

func populateJSONPayload(payload *passthroughPayload, op Operation) error {
	switch op {
	case OperationResponses:
		var req ResponsesRequest
		if err := json.Unmarshal(payload.Body, &req); err != nil {
			return fmt.Errorf("invalid request body: %w", err)
		}
		if req.PromptID != "" {
			payload.Tags = req.SBTags
		}
		payload.Model = req.Model
		payload.Streaming = req.IsStreaming()
		payload.Tags = req.SBTags
		payload.RequestInput = ResponsesInputMessages(req.Input, req.Instructions)

		var raw map[string]any
		if err := json.Unmarshal(payload.Body, &raw); err != nil {
			return fmt.Errorf("invalid request body: %w", err)
		}
		delete(raw, "sb_tags")
		delete(raw, "sb_cache_control")
		delete(raw, "sb_priority")
		normalized, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		payload.Body = normalized
	default:
		var raw map[string]any
		if err := json.Unmarshal(payload.Body, &raw); err != nil {
			return fmt.Errorf("invalid request body: %w", err)
		}
		if model, ok := raw["model"].(string); ok {
			payload.Model = model
		}
		if stream, ok := raw["stream"].(bool); ok {
			payload.Streaming = stream
		}
		if tags, ok := raw["sb_tags"].(map[string]any); ok {
			payload.Tags = stringifyMap(tags)
		}
		delete(raw, "sb_tags")
		delete(raw, "sb_cache_control")
		delete(raw, "sb_priority")
		normalized, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		payload.Body = normalized
	}

	return nil
}

func populateMultipartPayload(payload *passthroughPayload, boundary string, op Operation) error {
	if boundary == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(payload.Body), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if part.FormName() == "model" {
			data, _ := io.ReadAll(part)
			payload.Model = string(data)
			continue
		}
		if part.FormName() == "stream" {
			data, _ := io.ReadAll(part)
			payload.Streaming = strings.EqualFold(string(data), "true")
			continue
		}
		if op == OperationResponses && part.FormName() == "instructions" {
			data, _ := io.ReadAll(part)
			payload.RequestInput = append(payload.RequestInput, mustTextMessage("system", string(data)))
			continue
		}
	}
}

func stringifyMap(raw map[string]any) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(t)
		default:
			out[k] = fmt.Sprint(t)
		}
	}
	return out
}

func passthroughOperationFromPath(path string) Operation {
	switch {
	case strings.HasPrefix(path, "responses"):
		return OperationResponses
	case strings.HasPrefix(path, "moderations"):
		return OperationModerations
	case strings.HasPrefix(path, "batches"):
		return OperationBatches
	case strings.HasPrefix(path, "files"):
		return OperationFiles
	case strings.HasPrefix(path, "images/"):
		return OperationImagesGenerations
	case strings.HasPrefix(path, "audio/speech"):
		return OperationAudioSpeech
	case strings.HasPrefix(path, "audio/transcriptions"):
		return OperationAudioTranscribe
	case strings.HasPrefix(path, "rerank"):
		return OperationRerank
	default:
		return ""
	}
}

func (h *Handler) passthroughProviderConfig(ctx context.Context, base *ProviderConfig) *ProviderConfig {
	if rd := reqctx.GetRequestData(ctx); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil {
		if pkMap, ok := rd.SessionData.AuthData.Data["provider_keys"].(map[string]any); ok {
			if keyVal, ok := pkMap[base.Name].(string); ok && keyVal != "" {
				cfgCopy := *base
				cfgCopy.APIKey = keyVal
				return &cfgCopy
			}
		}
	}
	return base
}

func buildPassthroughURL(cfg *ProviderConfig, op Operation, path string, model string) (string, error) {
	trimmedPath := strings.TrimPrefix(path, "/")
	switch cfg.GetType() {
	case "openai", "generic":
		baseURL := strings.TrimRight(cfg.BaseURL, "/")
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return baseURL + "/" + strings.TrimPrefix(trimmedPath, "v1/"), nil
	case "azure":
		baseURL := strings.TrimRight(cfg.BaseURL, "/")
		if baseURL == "" {
			return "", fmt.Errorf("azure provider requires base_url")
		}
		apiVersion := cfg.APIVersion
		if apiVersion == "" {
			apiVersion = "2024-10-21"
		}
		if op == OperationResponses {
			return fmt.Sprintf("%s/openai/v1/%s", baseURL, strings.TrimPrefix(trimmedPath, "v1/")), nil
		}
		return fmt.Sprintf("%s/openai/%s?api-version=%s", baseURL, strings.TrimPrefix(trimmedPath, "v1/"), apiVersion), nil
	default:
		return "", fmt.Errorf("provider %q does not support %q; supported operations for this provider type: chat/completions, embeddings, models", cfg.GetType(), op)
	}
}

func applyPassthroughHeaders(req *http.Request, original *http.Request, cfg *ProviderConfig) {
	for k, values := range original.Header {
		lower := strings.ToLower(k)
		switch lower {
		case "authorization", "content-length", "host":
			continue
		}
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}

	switch cfg.GetType() {
	case "azure":
		req.Header.Del("Authorization")
		if cfg.APIKey != "" {
			req.Header.Set("api-key", cfg.APIKey)
		}
	default:
		if cfg.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		}
		if cfg.Organization != "" {
			req.Header.Set("OpenAI-Organization", cfg.Organization)
		}
		if cfg.ProjectID != "" {
			req.Header.Set("OpenAI-Project", cfg.ProjectID)
		}
	}

	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
}

func copyPassthroughResponseHeaders(dst http.ResponseWriter, src http.Header) {
	for k, values := range src {
		lower := strings.ToLower(k)
		if lower == "content-length" {
			continue
		}
		for _, v := range values {
			dst.Header().Add(k, v)
		}
	}
}

func parseResponsesUsage(body []byte) (*Usage, string) {
	var resp ResponsesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ""
	}
	return resp.Usage.ToUsage(), ResponsesOutputText(resp.Output)
}

type passthroughStreamResult struct {
	Usage *Usage

	outputTextBuilder strings.Builder
	outputTextValue   string
	outputTextDirty   bool
}

type bufferedPassthroughEvent struct {
	Event string
	Data  string
	ID    string
}

func streamPassthroughSSE(w http.ResponseWriter, body io.ReadCloser) (*passthroughStreamResult, error) {
	defer body.Close()

	parser := NewSSEParser(body, 0)
	defer parser.Close()
	writer := NewSSEWriter(w)
	defer ReleaseSSEWriter(writer)
	writer.WriteHeaders()

	result := &passthroughStreamResult{}

	for {
		evt, err := parser.ReadEvent()
		if err != nil {
			if err == io.EOF {
				return result, nil
			}
			return result, err
		}

		if IsDone(evt.Data) {
			if err := writer.WriteDone(); err != nil {
				ReleaseSSEEvent(evt)
				return result, err
			}
			ReleaseSSEEvent(evt)
			return result, nil
		}

		collectResponsesEvent(result, evt)
		if err := writer.WriteEvent(evt); err != nil {
			ReleaseSSEEvent(evt)
			return result, err
		}
		ReleaseSSEEvent(evt)
	}
}

func (h *Handler) streamResponsesPassthroughSSE(w http.ResponseWriter, r *http.Request, body io.ReadCloser, model string) (*passthroughStreamResult, error) {
	defer body.Close()

	mode := h.streamingGuardrailMode()
	if mode == "request_only" || h.config.Guardrails == nil || !h.config.Guardrails.HasOutput() {
		return streamPassthroughSSE(w, body)
	}

	parser := NewSSEParser(body, 0)
	defer parser.Close()
	result := &passthroughStreamResult{}

	if mode == "buffered_response_scan" {
		events := make([]bufferedPassthroughEvent, 0, 32)
		doneSeen := false
		for {
			evt, err := parser.ReadEvent()
			if err != nil {
				if err == io.EOF {
					break
				}
				return result, err
			}
			if IsDone(evt.Data) {
				doneSeen = true
				ReleaseSSEEvent(evt)
				break
			}
			collectResponsesEvent(result, evt)
			events = append(events, bufferedPassthroughEvent{Event: evt.Event, Data: evt.Data, ID: evt.ID})
			ReleaseSSEEvent(evt)
		}
		if guardrailErr := h.checkResponsesOutputGuardrails(r.Context(), model, result.OutputText()); guardrailErr != nil {
			WriteError(w, guardrailErr)
			return result, guardrailErr
		}
		writer := NewSSEWriter(w)
		defer ReleaseSSEWriter(writer)
		writer.WriteHeaders()
		for _, evt := range events {
			if err := writer.WriteEvent(&SSEEvent{Event: evt.Event, Data: evt.Data, ID: evt.ID}); err != nil {
				return result, err
			}
		}
		if doneSeen {
			if err := writer.WriteDone(); err != nil {
				return result, err
			}
		}
		return result, nil
	}

	writer := NewSSEWriter(w)
	defer ReleaseSSEWriter(writer)
	writer.WriteHeaders()
	lastScannedBytes := 0

	for {
		evt, err := parser.ReadEvent()
		if err != nil {
			if err == io.EOF {
				return result, nil
			}
			return result, err
		}
		if IsDone(evt.Data) {
			if err := writer.WriteDone(); err != nil {
				ReleaseSSEEvent(evt)
				return result, err
			}
			ReleaseSSEEvent(evt)
			return result, nil
		}

		collectResponsesEvent(result, evt)
		if result.OutputTextLen()-lastScannedBytes >= 256 || evt.Event == "response.completed" || evt.Event == "response.done" {
			if guardrailErr := h.checkResponsesOutputGuardrails(r.Context(), model, result.OutputText()); guardrailErr != nil {
				ReleaseSSEEvent(evt)
				_ = writer.WriteError(guardrailErr)
				return result, nil
			}
			lastScannedBytes = result.OutputTextLen()
		}
		if err := writer.WriteEvent(evt); err != nil {
			ReleaseSSEEvent(evt)
			return result, err
		}
		ReleaseSSEEvent(evt)
	}
}

func (h *Handler) checkResponsesOutputGuardrails(ctx context.Context, model, outputText string) *AIError {
	if h.config.Guardrails == nil || !h.config.Guardrails.HasOutput() {
		return nil
	}
	outputText = strings.TrimSpace(outputText)
	if outputText == "" {
		return nil
	}
	_, block, gerr := h.config.Guardrails.CheckOutput(ctx, []Message{mustTextMessage("assistant", outputText)}, model)
	if gerr != nil {
		return ErrInternal(fmt.Sprintf("output guardrail error: %v", gerr))
	}
	if block != nil {
		return ErrGuardrailBlocked(block.Name, block.Reason)
	}
	return nil
}

func collectResponsesEvent(result *passthroughStreamResult, evt *SSEEvent) {
	if evt == nil || result == nil {
		return
	}

	switch evt.Event {
	case "response.output_text.delta":
		var payload struct {
			Delta string `json:"delta"`
		}
		if err := json.Unmarshal([]byte(evt.Data), &payload); err == nil && payload.Delta != "" {
			result.AppendOutputText(payload.Delta)
		}
	case "response.completed", "response.done":
		var payload struct {
			Response *struct {
				Usage  *ResponseUsage  `json:"usage"`
				Output json.RawMessage `json:"output"`
			} `json:"response"`
			Usage  *ResponseUsage  `json:"usage"`
			Output json.RawMessage `json:"output"`
		}
		if err := json.Unmarshal([]byte(evt.Data), &payload); err != nil {
			return
		}
		switch {
		case payload.Response != nil && payload.Response.Usage != nil:
			result.Usage = payload.Response.Usage.ToUsage()
			if result.OutputTextLen() == 0 {
				result.SetOutputText(ResponsesOutputText(payload.Response.Output))
			}
		case payload.Usage != nil:
			result.Usage = payload.Usage.ToUsage()
			if result.OutputTextLen() == 0 {
				result.SetOutputText(ResponsesOutputText(payload.Output))
			}
		}
	}
}

func (r *passthroughStreamResult) AppendOutputText(text string) {
	if r == nil || text == "" {
		return
	}
	r.outputTextBuilder.WriteString(text)
	r.outputTextDirty = true
}

func (r *passthroughStreamResult) SetOutputText(text string) {
	if r == nil {
		return
	}
	r.outputTextBuilder.Reset()
	r.outputTextValue = text
	r.outputTextDirty = false
}

func (r *passthroughStreamResult) OutputText() string {
	if r == nil {
		return ""
	}
	if r.outputTextDirty {
		r.outputTextValue += r.outputTextBuilder.String()
		r.outputTextBuilder.Reset()
		r.outputTextDirty = false
	}
	return r.outputTextValue
}

func (r *passthroughStreamResult) OutputTextLen() int {
	if r == nil {
		return 0
	}
	return len(r.outputTextValue) + r.outputTextBuilder.Len()
}

func (h *Handler) applyPassthroughTags(ctx context.Context, tags map[string]string) {
	if len(tags) == 0 {
		return
	}
	if rd := reqctx.GetRequestData(ctx); rd != nil {
		if agent := tags["agent"]; agent != "" {
			rd.AddDebugHeader("X-Sb-Agent", agent)
		}
		if session := tags["session"]; session != "" {
			rd.AddDebugHeader("X-Sb-Session", session)
		}
		for k, v := range tags {
			if k == "agent" || k == "session" || k == "task" {
				continue
			}
			rd.AddDebugHeader("X-Sb-Tag-"+strings.ToUpper(k[:1])+k[1:], v)
		}
		if task := tags["task"]; task != "" {
			rd.AddDebugHeader("X-Sb-Task", task)
		}
	}
}

func (h *Handler) annotatePassthroughSelection(ctx context.Context, provider, model string) {
	if rd := reqctx.GetRequestData(ctx); rd != nil {
		if model != "" {
			rd.AddDebugHeader(httputil.HeaderXSbAIModel, model)
		}
		if provider != "" {
			rd.AddDebugHeader(httputil.HeaderXSbAIProvider, provider)
		}
	}
}

func (h *Handler) captureResponsesMemory(ctx context.Context, req *ResponsesRequest, usage *Usage, outputText, provider string, streaming bool, latency, ttft time.Duration) {
	if usage == nil {
		return
	}
	chatReq := &ChatCompletionRequest{
		Model:    req.Model,
		Messages: ResponsesInputMessages(req.Input, req.Instructions),
		Tools:    req.Tools,
	}
	assistant := mustTextMessage("assistant", outputText)
	resp := &ChatCompletionResponse{
		ID:      "response-memory",
		Object:  "response",
		Model:   req.Model,
		Choices: []Choice{{Index: 0, Message: assistant}},
		Usage:   usage,
	}
	h.captureMemory(ctx, chatReq, usage, resp, nil, provider, streaming, latency, ttft)
}

func (h *Handler) handleOperationPassthrough(w http.ResponseWriter, r *http.Request, path string) {
	op := passthroughOperationFromPath(path)
	if op == "" {
		WriteError(w, ErrNotFound())
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
	default:
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	payload, err := h.readPassthroughPayload(w, r, op)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	if op == OperationResponses {
		var req ResponsesRequest
		if err := json.Unmarshal(payload.Body, &req); err == nil {
			if err := h.resolvePromptForResponses(r.Context(), &req); err != nil {
				WriteError(w, ErrInvalidRequest(fmt.Sprintf("prompt resolution failed: %v", err)))
				return
			}
			req.PromptID = ""
			req.PromptEnvironment = ""
			req.PromptVersion = nil
			req.PromptVariables = nil
			payload.Model = req.Model
			payload.Streaming = req.IsStreaming()
			payload.Tags = req.SBTags
			payload.RequestInput = ResponsesInputMessages(req.Input, req.Instructions)
			if req.User != "" {
				if rd := reqctx.GetRequestData(r.Context()); rd != nil {
					rd.AddDebugHeader("X-Sb-AI-User", req.User)
				}
			}
			payload.Body, _ = json.Marshal(req)
		}
	}

	h.applyPassthroughTags(r.Context(), payload.Tags)

	if payload.Model != "" {
		if err := h.validateModelAccess(r.Context(), payload.Model); err != nil {
			WriteError(w, err)
			return
		}
	}

	if h.config.Budget != nil {
		scopeValues := h.budgetScopeValues(r.Context(), payload.Model, payload.Tags)
		if decision, err := h.config.Budget.CheckScopes(r.Context(), scopeValues, 0); err != nil {
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
			if aiErr, ok := err.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(fmt.Sprintf("budget check error: %v", err)))
			}
			return
		}
	}

	excludeMap, policyExclusions := h.providerExclusionsWithReasons(r.Context())
	pcfg, routeErr := h.router.RouteOperation(r.Context(), op, payload.Model, excludeMap)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(routeErr.Error()))
		return
	}
	pcfg = h.passthroughProviderConfig(r.Context(), pcfg)
	h.annotatePassthroughSelection(r.Context(), pcfg.Name, payload.Model)
	AIRoutingDecision(h.router.Strategy(), pcfg.Name, payload.Model)

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	url, err := buildPassthroughURL(pcfg, op, path, payload.Model)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	httpReq, err := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(payload.Body))
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	applyPassthroughHeaders(httpReq, r, pcfg)
	if payload.ContentType != "" {
		httpReq.Header.Set("Content-Type", payload.ContentType)
	}

	start := time.Now()
	resp, err := h.client.Do(httpReq)
	if err != nil {
		AIProviderError(pcfg.Name, "transport_error")
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	copyPassthroughResponseHeaders(w, resp.Header)
	latency := time.Since(start)

	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		var (
			streamResult *passthroughStreamResult
			streamErr    error
		)
		if op == OperationResponses {
			streamResult, streamErr = h.streamResponsesPassthroughSSE(w, r, resp.Body, payload.Model)
		} else {
			// Non-responses passthrough streaming uses request_only mode.
			// Output guardrails cannot meaningfully scan structured JSON or binary streaming
			// from moderations, batches, files, images, or audio endpoints.
			streamResult, streamErr = streamPassthroughSSE(w, resp.Body)
		}
		if streamErr != nil {
			WriteError(w, ErrInternal(streamErr.Error()))
			return
		}
		if op == OperationResponses && streamResult.Usage != nil {
			h.recordUsage(r.Context(), pcfg.Name, payload.Model, streamResult.Usage, true, latency, 0, 0)
			h.attachGovernanceMetadata(r.Context(), true, policyExclusions)
			if h.config.Memory != nil && h.effectivePrivacyMode(r.Context()) != "zero_retention" {
				req := &ResponsesRequest{
					Model:        payload.Model,
					Input:        mustMarshalMessages(payload.RequestInput),
					Instructions: "",
				}
				h.captureResponsesMemory(context.WithoutCancel(r.Context()), req, streamResult.Usage, streamResult.OutputText(), pcfg.Name, true, latency, 0)
			}
		} else if op != OperationResponses {
			// For non-responses passthrough, attach governance metadata directly since
			// there is no recordUsage call (no token accounting for these operations).
			if rd := reqctx.GetRequestData(r.Context()); rd != nil {
				if rd.AIUsage == nil {
					rd.AIUsage = &reqctx.AIUsage{
						Provider: pcfg.Name,
						Model:    payload.Model,
					}
				}
				rd.AIUsage.StreamingGuardrailMode = "request_only"
				rd.AIUsage.Streaming = true
			}
			h.attachGovernanceMetadata(r.Context(), true, policyExclusions)
		}
		return
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)

	if resp.StatusCode >= 400 {
		AIProviderError(pcfg.Name, strconv.Itoa(resp.StatusCode))
		return
	}

	if op == OperationResponses {
		usage, outputText := parseResponsesUsage(body)
		if usage != nil {
			h.recordUsage(r.Context(), pcfg.Name, payload.Model, usage, false, latency, 0, 0)
			h.attachGovernanceMetadata(r.Context(), false, policyExclusions)
			if h.config.Memory != nil && h.effectivePrivacyMode(r.Context()) != "zero_retention" {
				req := &ResponsesRequest{
					Model:        payload.Model,
					Input:        mustMarshalMessages(payload.RequestInput),
					Instructions: "",
				}
				h.captureResponsesMemory(context.WithoutCancel(r.Context()), req, usage, outputText, pcfg.Name, false, latency, 0)
			}
		}
	}
}

func mustMarshalMessages(msgs []Message) json.RawMessage {
	if len(msgs) == 0 {
		return nil
	}
	raw, err := json.Marshal(msgs)
	if err != nil {
		return nil
	}
	return raw
}

func (h *Handler) validateModelAccess(ctx context.Context, model string) *AIError {
	if model == "" {
		return nil
	}
	allowedModels := h.config.AllowedModels
	blockedModels := h.config.BlockedModels
	if ent := h.aiEntitlements(ctx); ent != nil {
		if vals := ent.stringSlice("allowed_models"); len(vals) > 0 {
			allowedModels = intersectOrFallback(allowedModels, vals)
		}
		if vals := ent.stringSlice("blocked_models"); len(vals) > 0 {
			blockedModels = append(blockedModels, vals...)
		}
	}
	if len(allowedModels) > 0 {
		allowed := false
		for _, m := range allowedModels {
			if m == model {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrInvalidRequest(fmt.Sprintf("model %q is not in the allowed list", model))
		}
	}
	for _, m := range blockedModels {
		if m == model {
			return ErrInvalidRequest(fmt.Sprintf("model %q is blocked", model))
		}
	}
	return nil
}

// enforceVirtualKey checks model and provider restrictions from a virtual key in context.
func (h *Handler) enforceVirtualKey(ctx context.Context, model string) *AIError {
	vk, ok := keys.FromContext(ctx)
	if !ok {
		return nil // No virtual key in context, pass through
	}
	if model != "" && !vk.IsModelAllowed(model) {
		keys.VKModelBlocked(vk.ID, vk.Name, model)
		return ErrInvalidRequest(fmt.Sprintf("model %q is not allowed by this API key", model))
	}
	return nil
}

func intersectOrFallback(base []string, other []string) []string {
	if len(base) == 0 {
		return other
	}
	set := make(map[string]bool, len(other))
	for _, v := range other {
		set[v] = true
	}
	var out []string
	for _, v := range base {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}

func (h *Handler) providerExclusions(ctx context.Context) map[string]bool {
	exclude := make(map[string]bool)
	allowed := make(map[string]bool)
	hasAllowed := false

	for _, p := range h.config.BlockedProviders {
		exclude[p] = true
	}
	for _, p := range h.config.AllowedProviders {
		allowed[p] = true
		hasAllowed = true
	}
	if ent := h.aiEntitlements(ctx); ent != nil {
		if vals := ent.stringSlice("blocked_providers"); len(vals) > 0 {
			for _, p := range vals {
				exclude[p] = true
			}
		}
		if vals := ent.stringSlice("allowed_providers"); len(vals) > 0 {
			if hasAllowed {
				merged := make(map[string]bool)
				for _, p := range vals {
					if allowed[p] {
						merged[p] = true
					}
				}
				allowed = merged
			} else {
				for _, p := range vals {
					allowed[p] = true
				}
				hasAllowed = true
			}
		}
	}
	if hasAllowed {
		for name := range h.providers {
			if !allowed[name] {
				exclude[name] = true
			}
		}
	}
	if policy := h.effectiveProviderPolicy(ctx); len(policy) > 0 {
		for name, entry := range h.providers {
			if !providerAllowedByPolicy(policy, entry.config) {
				exclude[name] = true
			}
		}
	}
	return exclude
}

// attachGovernanceMetadata sets streaming guardrail mode and policy exclusion data on AIUsage
// after recordUsage has populated the struct.
func (h *Handler) attachGovernanceMetadata(ctx context.Context, streaming bool, exclusions []PolicyExclusion) {
	rd := reqctx.GetRequestData(ctx)
	if rd == nil || rd.AIUsage == nil {
		return
	}
	if streaming {
		rd.AIUsage.StreamingGuardrailMode = h.streamingGuardrailMode()
	}
	if len(exclusions) > 0 {
		converted := make([]reqctx.ProviderExclusion, len(exclusions))
		for i, pe := range exclusions {
			converted[i] = reqctx.ProviderExclusion{
				Provider:  pe.Provider,
				Attribute: pe.Attribute,
				Reason:    pe.Reason,
			}
		}
		rd.AIUsage.ProviderExclusions = converted
	}
}

// providerExclusionsWithReasons returns exclusions alongside policy exclusion reasons for governance reporting.
func (h *Handler) providerExclusionsWithReasons(ctx context.Context) (map[string]bool, []PolicyExclusion) {
	exclude := h.providerExclusions(ctx)
	var reasons []PolicyExclusion
	if policy := h.effectiveProviderPolicy(ctx); len(policy) > 0 {
		for _, entry := range h.providers {
			if _, excl := providerPolicyDecision(policy, entry.config); excl != nil {
				reasons = append(reasons, *excl)
			}
		}
	}
	return exclude, reasons
}

type entitlementsView map[string]any

func (e entitlementsView) stringSlice(key string) []string {
	raw, ok := e[key]
	if !ok {
		return nil
	}
	switch vals := raw.(type) {
	case []string:
		return vals
	case []any:
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (e entitlementsView) stringValue(key string) string {
	if raw, ok := e[key].(string); ok {
		return raw
	}
	return ""
}

func (e entitlementsView) objectValue(key string) map[string]any {
	if raw, ok := e[key].(map[string]any); ok {
		return raw
	}
	return nil
}

func (h *Handler) aiEntitlements(ctx context.Context) entitlementsView {
	if rd := reqctx.GetRequestData(ctx); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil && rd.SessionData.AuthData.Data != nil {
		if raw, ok := rd.SessionData.AuthData.Data["ai_entitlements"].(map[string]any); ok {
			return entitlementsView(raw)
		}
	}
	return nil
}

func (h *Handler) effectivePrivacyMode(ctx context.Context) string {
	if ent := h.aiEntitlements(ctx); ent != nil {
		if mode := ent.stringValue("privacy_mode"); mode != "" {
			return mode
		}
	}
	if h.config.ZeroDataRetention {
		return "zero_retention"
	}
	if h.config.LogPolicy != "" {
		return h.config.LogPolicy
	}
	return "standard"
}
