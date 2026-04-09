// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	json "github.com/goccy/go-json"
)

// ReplayConfig configures the replay system.
type ReplayConfig struct {
	Enabled  bool `json:"enabled"`
	MaxBatch int  `json:"max_batch,omitempty"` // max requests per batch replay (default 100)
}

// maxBatch returns the configured max batch size, defaulting to 100.
func (c *ReplayConfig) maxBatch() int {
	if c == nil || c.MaxBatch <= 0 {
		return 100
	}
	return c.MaxBatch
}

// ReplayRequest represents a request to replay a historical AI call.
type ReplayRequest struct {
	// OriginalRequest is the original chat completion request to replay.
	OriginalRequest *ChatCompletionRequest `json:"original_request"`
	// OriginalResponse is the original response (for diff mode).
	OriginalResponse *ChatCompletionResponse `json:"original_response,omitempty"`
	// Mode: "execute" (default), "dry_run", "diff"
	Mode string `json:"mode,omitempty"`
	// Provider override (optional, use different provider than original).
	Provider string `json:"provider,omitempty"`
	// Model override (optional).
	Model string `json:"model,omitempty"`
}

// ReplayResponse holds the result of a replay operation.
type ReplayResponse struct {
	Mode       string                  `json:"mode"`
	Request    *ChatCompletionRequest  `json:"request"`
	Response   *ChatCompletionResponse `json:"response,omitempty"`
	DryRun     *DryRunResult           `json:"dry_run,omitempty"`
	Diff       *DiffResult             `json:"diff,omitempty"`
	DurationMS int64                   `json:"duration_ms"`
	Provider   string                  `json:"provider"`
	Model      string                  `json:"model"`
}

// DryRunResult shows what would happen without executing.
type DryRunResult struct {
	TargetProvider  string   `json:"target_provider"`
	TargetModel     string   `json:"target_model"`
	WouldBlock      bool     `json:"would_block"`
	BlockReason     string   `json:"block_reason,omitempty"`
	EstimatedTokens int      `json:"estimated_tokens"`
	Warnings        []string `json:"warnings,omitempty"`
}

// DiffResult compares original and replay responses.
type DiffResult struct {
	Match           bool   `json:"match"`
	OriginalContent string `json:"original_content"`
	ReplayContent   string `json:"replay_content"`
	ContentChanged  bool   `json:"content_changed"`
	ModelChanged    bool   `json:"model_changed"`
	TokenDiff       int    `json:"token_diff"`
}

// BatchReplayRequest holds multiple replay requests.
type BatchReplayRequest struct {
	Requests []ReplayRequest `json:"requests"`
}

// BatchReplayResponse holds results for a batch replay.
type BatchReplayResponse struct {
	Results         []*ReplayResponse `json:"results"`
	TotalCount      int               `json:"total_count"`
	SuccessCount    int               `json:"success_count"`
	ErrorCount      int               `json:"error_count"`
	TotalDurationMS int64             `json:"total_duration_ms"`
}

// handleReplay handles POST /v1/replay requests.
func (h *Handler) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	if h.config.Replay == nil || !h.config.Replay.Enabled {
		WriteError(w, ErrNotFound())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req ReplayRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid replay request body: %v", err)))
		return
	}

	if req.OriginalRequest == nil {
		WriteError(w, ErrInvalidRequest("original_request is required"))
		return
	}

	resp, aiErr := h.executeReplay(r.Context(), &req)
	if aiErr != nil {
		WriteError(w, aiErr)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleBatchReplay handles POST /v1/replay/batch requests.
func (h *Handler) handleBatchReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	if h.config.Replay == nil || !h.config.Replay.Enabled {
		WriteError(w, ErrNotFound())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var batchReq BatchReplayRequest
	if err := json.NewDecoder(body).Decode(&batchReq); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid batch replay request body: %v", err)))
		return
	}

	maxBatch := h.config.Replay.maxBatch()
	if len(batchReq.Requests) > maxBatch {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("batch size %d exceeds maximum of %d", len(batchReq.Requests), maxBatch)))
		return
	}

	if len(batchReq.Requests) == 0 {
		WriteError(w, ErrInvalidRequest("requests array is empty"))
		return
	}

	batchStart := time.Now()
	batchResp := &BatchReplayResponse{
		TotalCount: len(batchReq.Requests),
		Results:    make([]*ReplayResponse, 0, len(batchReq.Requests)),
	}

	// Execute replays sequentially to avoid overwhelming providers.
	for i := range batchReq.Requests {
		req := &batchReq.Requests[i]
		if req.OriginalRequest == nil {
			batchResp.ErrorCount++
			batchResp.Results = append(batchResp.Results, &ReplayResponse{
				Mode: normalizeReplayMode(req.Mode),
			})
			continue
		}

		resp, aiErr := h.executeReplay(r.Context(), req)
		if aiErr != nil {
			slog.Warn("batch replay item failed", "index", i, "error", aiErr.Message)
			batchResp.ErrorCount++
			batchResp.Results = append(batchResp.Results, &ReplayResponse{
				Mode: normalizeReplayMode(req.Mode),
			})
			continue
		}

		batchResp.SuccessCount++
		batchResp.Results = append(batchResp.Results, resp)
	}

	batchResp.TotalDurationMS = time.Since(batchStart).Milliseconds()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(batchResp)
}

// executeReplay runs a single replay request and returns the result.
func (h *Handler) executeReplay(ctx context.Context, req *ReplayRequest) (*ReplayResponse, *AIError) {
	start := time.Now()
	mode := normalizeReplayMode(req.Mode)

	// Apply overrides to a copy of the original request.
	chatReq := h.prepareReplayRequest(req)

	// Route to a provider.
	pcfg, routeErr := h.router.Route(ctx, chatReq.Model, nil)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			return nil, aiErr
		}
		return nil, ErrInternal(routeErr.Error())
	}

	// If a specific provider was requested, try to use it.
	if req.Provider != "" {
		if entry, ok := h.providers[req.Provider]; ok {
			pcfg = entry.config
		} else {
			return nil, ErrInvalidRequest(fmt.Sprintf("provider '%s' not found", req.Provider))
		}
	}

	switch mode {
	case "dry_run":
		return h.executeReplayDryRun(ctx, chatReq, pcfg, start)
	case "diff":
		return h.executeReplayDiff(ctx, chatReq, pcfg, req.OriginalResponse, start)
	default:
		return h.executeReplayExecute(ctx, chatReq, pcfg, start)
	}
}

// prepareReplayRequest creates a copy of the original request with overrides applied.
func (h *Handler) prepareReplayRequest(req *ReplayRequest) *ChatCompletionRequest {
	chatReq := *req.OriginalRequest

	// Force non-streaming for replay.
	stream := false
	chatReq.Stream = &stream
	chatReq.StreamOptions = nil

	// Apply model override.
	if req.Model != "" {
		chatReq.Model = req.Model
	}

	// Default model fallback.
	if chatReq.Model == "" {
		chatReq.Model = h.config.DefaultModel
	}

	return &chatReq
}

// executeReplayExecute runs the request against the provider and returns the response.
func (h *Handler) executeReplayExecute(ctx context.Context, chatReq *ChatCompletionRequest, pcfg *ProviderConfig, start time.Time) (*ReplayResponse, *AIError) {
	entry, ok := h.providers[pcfg.Name]
	if !ok {
		return nil, ErrProviderUnavailable(pcfg.Name)
	}

	resp, err := entry.provider.ChatCompletion(ctx, chatReq, pcfg)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("replay execution failed: %v", err))
	}

	return &ReplayResponse{
		Mode:       "execute",
		Request:    chatReq,
		Response:   resp,
		DurationMS: time.Since(start).Milliseconds(),
		Provider:   pcfg.Name,
		Model:      chatReq.Model,
	}, nil
}

// executeReplayDryRun validates the request without executing it.
func (h *Handler) executeReplayDryRun(ctx context.Context, chatReq *ChatCompletionRequest, pcfg *ProviderConfig, start time.Time) (*ReplayResponse, *AIError) {
	dryRun := &DryRunResult{
		TargetProvider:  pcfg.Name,
		TargetModel:     chatReq.Model,
		EstimatedTokens: EstimateMessagesTokens(chatReq.Messages),
	}

	// Check guardrails if configured.
	if h.config.Guardrails != nil && h.config.Guardrails.HasInput() {
		_, block, err := h.config.Guardrails.CheckInput(ctx, chatReq.Messages, chatReq.Model)
		if err != nil {
			dryRun.Warnings = append(dryRun.Warnings, fmt.Sprintf("guardrail check error: %v", err))
		}
		if block != nil {
			dryRun.WouldBlock = true
			dryRun.BlockReason = fmt.Sprintf("guardrail '%s': %s", block.Name, block.Reason)
		}
	}

	// Check if the provider is available.
	if _, ok := h.providers[pcfg.Name]; !ok {
		dryRun.Warnings = append(dryRun.Warnings, fmt.Sprintf("provider '%s' is not available", pcfg.Name))
	}

	return &ReplayResponse{
		Mode:       "dry_run",
		Request:    chatReq,
		DryRun:     dryRun,
		DurationMS: time.Since(start).Milliseconds(),
		Provider:   pcfg.Name,
		Model:      chatReq.Model,
	}, nil
}

// executeReplayDiff executes the request and compares with the original response.
func (h *Handler) executeReplayDiff(ctx context.Context, chatReq *ChatCompletionRequest, pcfg *ProviderConfig, originalResp *ChatCompletionResponse, start time.Time) (*ReplayResponse, *AIError) {
	if originalResp == nil {
		return nil, ErrInvalidRequest("original_response is required for diff mode")
	}

	entry, ok := h.providers[pcfg.Name]
	if !ok {
		return nil, ErrProviderUnavailable(pcfg.Name)
	}

	resp, err := entry.provider.ChatCompletion(ctx, chatReq, pcfg)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("replay execution failed: %v", err))
	}

	diff := buildDiffResult(originalResp, resp)

	return &ReplayResponse{
		Mode:       "diff",
		Request:    chatReq,
		Response:   resp,
		Diff:       diff,
		DurationMS: time.Since(start).Milliseconds(),
		Provider:   pcfg.Name,
		Model:      chatReq.Model,
	}, nil
}

// buildDiffResult compares the original and replay responses.
func buildDiffResult(original, replay *ChatCompletionResponse) *DiffResult {
	originalContent := extractResponseContent(original)
	replayContent := extractResponseContent(replay)

	originalTokens := 0
	replayTokens := 0
	if original.Usage != nil {
		originalTokens = original.Usage.TotalTokens
	}
	if replay.Usage != nil {
		replayTokens = replay.Usage.TotalTokens
	}

	contentChanged := originalContent != replayContent
	modelChanged := original.Model != replay.Model

	return &DiffResult{
		Match:           !contentChanged && !modelChanged,
		OriginalContent: originalContent,
		ReplayContent:   replayContent,
		ContentChanged:  contentChanged,
		ModelChanged:    modelChanged,
		TokenDiff:       replayTokens - originalTokens,
	}
}

// normalizeReplayMode returns a valid replay mode, defaulting to "execute".
func normalizeReplayMode(mode string) string {
	switch mode {
	case "execute", "dry_run", "diff":
		return mode
	default:
		return "execute"
	}
}
