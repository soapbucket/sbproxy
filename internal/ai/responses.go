// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ResponseStatus tracks the lifecycle of a response.
type ResponseStatus string

const (
	// ResponseStatusCompleted indicates the response finished successfully.
	ResponseStatusCompleted ResponseStatus = "completed"
	// ResponseStatusInProgress indicates the response is still being generated.
	ResponseStatusInProgress ResponseStatus = "in_progress"
	// ResponseStatusCancelled indicates the response was cancelled.
	ResponseStatusCancelled ResponseStatus = "cancelled"
	// ResponseStatusFailed indicates the response failed.
	ResponseStatusFailed ResponseStatus = "failed"
)

// ResponseObject represents a stored response in the OpenAI Responses API format.
type ResponseObject struct {
	ID                 string            `json:"id"`
	Object             string            `json:"object"`
	CreatedAt          int64             `json:"created_at"`
	Status             ResponseStatus    `json:"status"`
	Model              string            `json:"model"`
	Output             []OutputItem      `json:"output"`
	Usage              *ResponseUsage    `json:"usage,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	PreviousResponseID string            `json:"previous_response_id,omitempty"`
	Error              *ResponseError    `json:"error,omitempty"`

	// Internal fields (not serialized to client)
	cancelFunc context.CancelFunc `json:"-"`
}

// OutputItem represents a single output item in a response.
type OutputItem struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Role    string        `json:"role,omitempty"`
	Content []ContentItem `json:"content"`
}

// ContentItem represents a piece of content within an output item.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ResponseError describes an error on a response object.
type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// CreateResponseRequest is the input for POST /v1/responses.
type CreateResponseRequest struct {
	Model              string            `json:"model"`
	Input              json.RawMessage   `json:"input"`
	Instructions       string            `json:"instructions,omitempty"`
	MaxOutputTokens    int               `json:"max_output_tokens,omitempty"`
	Temperature        *float64          `json:"temperature,omitempty"`
	TopP               *float64          `json:"top_p,omitempty"`
	Tools              []Tool            `json:"tools,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	PreviousResponseID string            `json:"previous_response_id,omitempty"`
	Stream             bool              `json:"stream,omitempty"`
}

// DeleteResponseResult is the wire format for a delete response result.
type DeleteResponseResult struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Deleted bool   `json:"deleted"`
}

// handleResponses routes /v1/responses requests by method and sub-path.
func (h *Handler) handleResponses(w http.ResponseWriter, r *http.Request, path string) {
	if h.config.ResponseStore == nil {
		// Fall back to passthrough if no response store is configured
		h.handleOperationPassthrough(w, r, path)
		return
	}

	// Trim to get sub-path after "responses"
	sub := strings.TrimPrefix(path, "responses")
	sub = strings.TrimPrefix(sub, "/")

	if sub == "" {
		// /v1/responses
		switch r.Method {
		case http.MethodPost:
			h.createResponse(w, r)
		case http.MethodGet:
			h.listResponses(w, r)
		default:
			WriteError(w, ErrMethodNotAllowed())
		}
		return
	}

	// Check for /v1/responses/{id}/cancel
	if strings.HasSuffix(sub, "/cancel") {
		id := strings.TrimSuffix(sub, "/cancel")
		if r.Method != http.MethodPost {
			WriteError(w, ErrMethodNotAllowed())
			return
		}
		h.cancelResponse(w, r, id)
		return
	}

	// /v1/responses/{id}
	h.handleResponseByID(w, r, sub)
}

// handleResponseByID routes GET and DELETE for a specific response.
func (h *Handler) handleResponseByID(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		h.getResponse(w, r, id)
	case http.MethodDelete:
		h.deleteResponse(w, r, id)
	default:
		WriteError(w, ErrMethodNotAllowed())
	}
}

// createResponse handles POST /v1/responses.
func (h *Handler) createResponse(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req CreateResponseRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}

	if req.Model == "" && h.config.DefaultModel != "" {
		req.Model = h.config.DefaultModel
	}
	if req.Model == "" {
		WriteError(w, ErrInvalidRequest("model is required"))
		return
	}

	// Validate model access
	if err := h.validateModelAccess(r.Context(), req.Model); err != nil {
		WriteError(w, err)
		return
	}

	// Translate to ChatCompletionRequest
	chatReq, err := ResponseToChat(&req, h.config.ResponseStore)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	// Create a cancellable context for in-progress tracking
	ctx, cancel := context.WithCancel(r.Context())

	// Create in-progress response object and store it
	inProgress := &ResponseObject{
		ID:                 generateResponseID(),
		Object:             "response",
		CreatedAt:          time.Now().Unix(),
		Status:             ResponseStatusInProgress,
		Model:              req.Model,
		Metadata:           req.Metadata,
		PreviousResponseID: req.PreviousResponseID,
		cancelFunc:         cancel,
	}
	_ = h.config.ResponseStore.Store(ctx, inProgress)

	// Route to provider
	excludeMap, policyExclusions := h.providerExclusionsWithReasons(ctx)
	pcfg, routeErr := h.router.Route(ctx, chatReq.Model, excludeMap)
	if routeErr != nil {
		cancel()
		h.storeFailedResponse(ctx, inProgress, "routing_error", routeErr.Error())
		WriteError(w, routeErr.(*AIError))
		return
	}

	entry, ok := h.providers[pcfg.Name]
	if !ok {
		cancel()
		h.storeFailedResponse(ctx, inProgress, "provider_not_found", fmt.Sprintf("provider %q not found", pcfg.Name))
		WriteError(w, ErrInternal(fmt.Sprintf("provider %q not found", pcfg.Name)))
		return
	}

	// Check for per-request provider key overrides
	providerCfg := entry.config
	if rd := reqctx.GetRequestData(ctx); rd != nil && rd.SessionData != nil && rd.SessionData.AuthData != nil {
		if pkMap, ok := rd.SessionData.AuthData.Data["provider_keys"].(map[string]any); ok {
			if keyVal, ok := pkMap[pcfg.Name].(string); ok && keyVal != "" {
				cfgCopy := *providerCfg
				cfgCopy.APIKey = keyVal
				providerCfg = &cfgCopy
			}
		}
	}

	// Add debug headers
	if rd := reqctx.GetRequestData(ctx); rd != nil {
		rd.AddDebugHeader(httputil.HeaderXSbAIModel, chatReq.Model)
		rd.AddDebugHeader(httputil.HeaderXSbAIProvider, pcfg.Name)
	}

	AIRoutingDecision(h.router.Strategy(), pcfg.Name, chatReq.Model)

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(ctx, pcfg.Name)
		if acqErr != nil || !acquired {
			cancel()
			h.storeFailedResponse(r.Context(), inProgress, "concurrency_limit", fmt.Sprintf("provider %s is at max concurrency", pcfg.Name))
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
	}

	// Execute via existing provider pipeline
	h.router.Tracker().IncrInFlight(pcfg.Name)
	start := time.Now()
	resp, provErr := entry.provider.ChatCompletion(ctx, chatReq, providerCfg)
	latency := time.Since(start)
	h.router.Tracker().DecrInFlight(pcfg.Name)

	// Release concurrency slot after dispatch completes.
	if h.ConcurrencyLimiter != nil {
		h.ConcurrencyLimiter.Release(ctx, pcfg.Name)
	}

	cancel() // Done with the cancellable context

	if provErr != nil {
		h.router.Tracker().RecordError(pcfg.Name)
		h.storeFailedResponse(r.Context(), inProgress, "provider_error", provErr.Error())
		if aiErr, ok := provErr.(*AIError); ok {
			WriteError(w, aiErr)
		} else {
			WriteError(w, ErrInternal(provErr.Error()))
		}
		return
	}

	h.router.Tracker().RecordSuccess(pcfg.Name, latency)

	// Convert chat response to Responses API format
	responseObj := ChatToResponse(resp, &req)
	responseObj.ID = inProgress.ID
	responseObj.CreatedAt = inProgress.CreatedAt
	responseObj.cancelFunc = nil

	// Store completed response
	_ = h.config.ResponseStore.Store(r.Context(), responseObj)

	// Record usage
	if resp.Usage != nil {
		h.recordUsage(r.Context(), pcfg.Name, chatReq.Model, resp.Usage, false, latency, 0, 0)
		h.attachGovernanceMetadata(r.Context(), false, policyExclusions)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(responseObj)
}

// getResponse handles GET /v1/responses/{id}.
func (h *Handler) getResponse(w http.ResponseWriter, r *http.Request, id string) {
	resp, err := h.config.ResponseStore.Get(r.Context(), id)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	if resp == nil {
		WriteError(w, ErrNotFound())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// cancelResponse handles POST /v1/responses/{id}/cancel.
func (h *Handler) cancelResponse(w http.ResponseWriter, r *http.Request, id string) {
	resp, err := h.config.ResponseStore.Get(r.Context(), id)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	if resp == nil {
		WriteError(w, ErrNotFound())
		return
	}

	if resp.Status == ResponseStatusInProgress {
		if resp.cancelFunc != nil {
			resp.cancelFunc()
		}
		resp.Status = ResponseStatusCancelled
		resp.cancelFunc = nil
		_ = h.config.ResponseStore.Store(r.Context(), resp)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// deleteResponse handles DELETE /v1/responses/{id}.
func (h *Handler) deleteResponse(w http.ResponseWriter, r *http.Request, id string) {
	resp, err := h.config.ResponseStore.Get(r.Context(), id)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	if resp == nil {
		WriteError(w, ErrNotFound())
		return
	}

	_ = h.config.ResponseStore.Delete(r.Context(), id)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DeleteResponseResult{
		ID:      id,
		Object:  "response",
		Deleted: true,
	})
}

// listResponses handles GET /v1/responses.
func (h *Handler) listResponses(w http.ResponseWriter, r *http.Request) {
	limit := 20
	after := r.URL.Query().Get("after")

	results, err := h.config.ResponseStore.List(r.Context(), limit, after)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   results,
	})
}

// storeFailedResponse updates a response object to failed status and stores it.
func (h *Handler) storeFailedResponse(ctx context.Context, resp *ResponseObject, code, message string) {
	resp.Status = ResponseStatusFailed
	resp.Error = &ResponseError{
		Code:    code,
		Message: message,
	}
	resp.cancelFunc = nil
	_ = h.config.ResponseStore.Store(ctx, resp)
}

// generateResponseID creates a unique response identifier.
func generateResponseID() string {
	return fmt.Sprintf("resp_%d", time.Now().UnixNano())
}
