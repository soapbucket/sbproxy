// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// handleImageGeneration handles /v1/images/generations requests with typed parsing
// and provider format translation.
func (h *Handler) handleImageGeneration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req ImageRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}
	if err := req.Validate(); err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	model := req.Model
	if model != "" {
		if err := h.validateModelAccess(r.Context(), model); err != nil {
			WriteError(w, err)
			return
		}
	}

	// Budget check
	if h.config.Budget != nil {
		scopeValues := h.budgetScopeValues(r.Context(), model, nil)
		if _, err := h.config.Budget.CheckScopes(r.Context(), scopeValues, 0); err != nil {
			if aiErr, ok := err.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(fmt.Sprintf("budget check error: %v", err)))
			}
			return
		}
	}

	exclude := h.providerExclusions(r.Context())
	pcfg, routeErr := h.router.RouteOperation(r.Context(), OperationImagesGenerations, model, exclude)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(routeErr.Error()))
		return
	}
	pcfg = h.passthroughProviderConfig(r.Context(), pcfg)
	h.annotatePassthroughSelection(r.Context(), pcfg.Name, model)
	AIRoutingDecision(h.router.Strategy(), pcfg.Name, model)

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	// Translate request for the selected provider.
	translated, err := TranslateImageRequest(pcfg.GetType(), &req)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	reqBody, err := json.Marshal(translated)
	if err != nil {
		WriteError(w, ErrInternal("failed to encode request"))
		return
	}

	url, err := buildPassthroughURL(pcfg, OperationImagesGenerations, "images/generations", model)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyPassthroughHeaders(httpReq, r, pcfg)

	start := time.Now()
	resp, err := h.client.Do(httpReq)
	if err != nil {
		AIProviderError(pcfg.Name, "transport_error")
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	if resp.StatusCode >= 400 {
		AIProviderError(pcfg.Name, strconv.Itoa(resp.StatusCode))
		copyPassthroughResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	// Translate response back to OpenAI format.
	imageResp, err := TranslateImageResponse(pcfg.GetType(), respBody)
	if err != nil {
		// If translation fails, pass through the raw response.
		slog.Warn("image response translation failed, passing through raw",
			"error", err, "provider", pcfg.Name)
		copyPassthroughResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	AIRequestDuration(pcfg.Name, model, "200", "false", latency.Seconds())

	// Record minimal AIUsage for logging.
	if rd := reqctx.GetRequestData(r.Context()); rd != nil {
		rd.AIUsage = &reqctx.AIUsage{
			Provider:        pcfg.Name,
			Model:           model,
			RoutingStrategy: h.router.Strategy(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(imageResp)
}

// handleAudioTranscription handles /v1/audio/transcriptions requests.
// Audio transcription requests use multipart form data, so the body is forwarded
// with metadata extracted for routing purposes.
func (h *Handler) handleAudioTranscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	// Buffer the body so we can extract metadata and still forward it.
	bodyReader := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer bodyReader.Close()
	rawBody, err := io.ReadAll(bodyReader)
	if err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("failed to read request body: %v", err)))
		return
	}

	// Extract metadata from a copy of the body.
	metaReq, _ := http.NewRequest(http.MethodPost, "", bytes.NewReader(rawBody))
	metaReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	meta, err := ExtractMultipartMetadata(metaReq)
	if err != nil {
		// Not multipart or malformed; forward with empty metadata (model from routing default).
		slog.Warn("audio transcription metadata extraction failed, using default routing",
			"error", err)
		meta = &MultipartMetadata{}
	}

	model := meta.Model
	if model != "" {
		if err := h.validateModelAccess(r.Context(), model); err != nil {
			WriteError(w, err)
			return
		}
	}

	exclude := h.providerExclusions(r.Context())
	pcfg, routeErr := h.router.RouteOperation(r.Context(), OperationAudioTranscribe, model, exclude)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(routeErr.Error()))
		return
	}
	pcfg = h.passthroughProviderConfig(r.Context(), pcfg)
	h.annotatePassthroughSelection(r.Context(), pcfg.Name, model)
	AIRoutingDecision(h.router.Strategy(), pcfg.Name, model)

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	url, err := buildPassthroughURL(pcfg, OperationAudioTranscribe, "audio/transcriptions", model)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(rawBody))
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	httpReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	applyPassthroughHeaders(httpReq, r, pcfg)

	start := time.Now()
	resp, err := h.client.Do(httpReq)
	if err != nil {
		AIProviderError(pcfg.Name, "transport_error")
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	if resp.StatusCode >= 400 {
		AIProviderError(pcfg.Name, strconv.Itoa(resp.StatusCode))
		copyPassthroughResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	AIRequestDuration(pcfg.Name, model, "200", "false", latency.Seconds())

	if rd := reqctx.GetRequestData(r.Context()); rd != nil {
		rd.AIUsage = &reqctx.AIUsage{
			Provider:        pcfg.Name,
			Model:           model,
			RoutingStrategy: h.router.Strategy(),
		}
	}

	// Forward response as-is (transcription responses are already in a standard format).
	copyPassthroughResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// handleAudioSpeech handles /v1/audio/speech requests with typed parsing.
func (h *Handler) handleAudioSpeech(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req AudioSpeechRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}
	if err := req.Validate(); err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	model := req.Model
	if model != "" {
		if err := h.validateModelAccess(r.Context(), model); err != nil {
			WriteError(w, err)
			return
		}
	}

	exclude := h.providerExclusions(r.Context())
	pcfg, routeErr := h.router.RouteOperation(r.Context(), OperationAudioSpeech, model, exclude)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(routeErr.Error()))
		return
	}
	pcfg = h.passthroughProviderConfig(r.Context(), pcfg)
	h.annotatePassthroughSelection(r.Context(), pcfg.Name, model)
	AIRoutingDecision(h.router.Strategy(), pcfg.Name, model)

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	reqBody, err := TranslateAudioSpeechRequest(pcfg.GetType(), &req)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		WriteError(w, ErrInternal("failed to encode request"))
		return
	}

	url, err := buildPassthroughURL(pcfg, OperationAudioSpeech, "audio/speech", model)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(reqBytes))
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyPassthroughHeaders(httpReq, r, pcfg)

	start := time.Now()
	resp, err := h.client.Do(httpReq)
	if err != nil {
		AIProviderError(pcfg.Name, "transport_error")
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		AIProviderError(pcfg.Name, strconv.Itoa(resp.StatusCode))
		copyPassthroughResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	AIRequestDuration(pcfg.Name, model, "200", "false", latency.Seconds())

	if rd := reqctx.GetRequestData(r.Context()); rd != nil {
		rd.AIUsage = &reqctx.AIUsage{
			Provider:        pcfg.Name,
			Model:           model,
			RoutingStrategy: h.router.Strategy(),
		}
	}

	// Stream audio response back to client.
	copyPassthroughResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		slog.Error("audio speech: error copying response body", "error", err, "provider", pcfg.Name)
	}
	_ = latency // used above for metrics
}

// handleRerank handles /v1/rerank requests with typed parsing and provider translation.
func (h *Handler) handleRerank(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, ErrMethodNotAllowed())
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.config.MaxRequestBodySize)
	defer body.Close()

	var req RerankRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		WriteError(w, ErrInvalidRequest(fmt.Sprintf("invalid request body: %v", err)))
		return
	}
	if err := req.Validate(); err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	model := req.Model
	if model != "" {
		if err := h.validateModelAccess(r.Context(), model); err != nil {
			WriteError(w, err)
			return
		}
	}

	// Budget check
	if h.config.Budget != nil {
		scopeValues := h.budgetScopeValues(r.Context(), model, nil)
		if _, err := h.config.Budget.CheckScopes(r.Context(), scopeValues, 0); err != nil {
			if aiErr, ok := err.(*AIError); ok {
				WriteError(w, aiErr)
			} else {
				WriteError(w, ErrInternal(fmt.Sprintf("budget check error: %v", err)))
			}
			return
		}
	}

	exclude := h.providerExclusions(r.Context())
	pcfg, routeErr := h.router.RouteOperation(r.Context(), OperationRerank, model, exclude)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(routeErr.Error()))
		return
	}
	pcfg = h.passthroughProviderConfig(r.Context(), pcfg)
	h.annotatePassthroughSelection(r.Context(), pcfg.Name, model)
	AIRoutingDecision(h.router.Strategy(), pcfg.Name, model)

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	// Translate request for the selected provider.
	translated, err := TranslateRerankRequest(pcfg.GetType(), &req)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	reqBody, err := json.Marshal(translated)
	if err != nil {
		WriteError(w, ErrInternal("failed to encode request"))
		return
	}

	url, err := buildPassthroughURL(pcfg, OperationRerank, "rerank", model)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyPassthroughHeaders(httpReq, r, pcfg)

	start := time.Now()
	resp, err := h.client.Do(httpReq)
	if err != nil {
		AIProviderError(pcfg.Name, "transport_error")
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	if resp.StatusCode >= 400 {
		AIProviderError(pcfg.Name, strconv.Itoa(resp.StatusCode))
		copyPassthroughResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	// Translate response back to normalized format.
	rerankResp, err := TranslateRerankResponse(pcfg.GetType(), respBody)
	if err != nil {
		slog.Warn("rerank response translation failed, passing through raw",
			"error", err, "provider", pcfg.Name)
		copyPassthroughResponseHeaders(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}

	AIRequestDuration(pcfg.Name, model, "200", "false", latency.Seconds())

	// Record usage if available.
	if rd := reqctx.GetRequestData(r.Context()); rd != nil {
		aiUsage := &reqctx.AIUsage{
			Provider:        pcfg.Name,
			Model:           model,
			RoutingStrategy: h.router.Strategy(),
		}
		if rerankResp.Usage != nil {
			aiUsage.TotalTokens = rerankResp.Usage.TotalTokens
		}
		rd.AIUsage = aiUsage
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rerankResp)
	_ = latency // used above for metrics
}
