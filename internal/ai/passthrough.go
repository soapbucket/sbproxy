// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// PassthroughConfig controls raw passthrough mode, which forwards requests to the
// upstream provider without body parsing. Only auth, routing, and basic metrics
// remain active. Guardrails, budget, cache, session tracking, and prompt registry
// are all skipped.
type PassthroughConfig struct {
	// Enabled activates passthrough mode for all requests (config-level toggle).
	Enabled bool `json:"enabled,omitempty"`
	// AllowedPaths restricts which v1/* paths may use passthrough. An empty list
	// means all paths are allowed.
	AllowedPaths []string `json:"allowed_paths,omitempty"`
}

// passthroughHeader is the request header clients set to opt in to raw passthrough
// on a per-request basis.
const passthroughHeader = "X-SB-Passthrough"

// isPassthroughRequest returns true when the request should use raw passthrough mode.
// This is determined by the X-SB-Passthrough header being "true" or the handler's
// PassthroughConfig.Enabled flag being set. If AllowedPaths is configured, the
// request path must match one of them.
func (h *Handler) isPassthroughRequest(r *http.Request) bool {
	headerVal := strings.EqualFold(r.Header.Get(passthroughHeader), "true")
	configEnabled := h.config.Passthrough != nil && h.config.Passthrough.Enabled

	if !headerVal && !configEnabled {
		return false
	}

	if h.config.Passthrough != nil && len(h.config.Passthrough.AllowedPaths) > 0 {
		path := strings.TrimPrefix(r.URL.Path, "/")
		path = strings.TrimPrefix(path, "v1/")
		for _, allowed := range h.config.Passthrough.AllowedPaths {
			trimmed := strings.TrimPrefix(allowed, "v1/")
			if strings.HasPrefix(path, trimmed) {
				return true
			}
		}
		return false
	}

	return true
}

// handlePassthrough forwards the request to the upstream provider without parsing
// the request body. Only routing (provider selection) and auth (header injection)
// are applied. The response is streamed back to the caller without inspection.
func (h *Handler) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimPrefix(path, "v1/")

	// Select provider via router (still uses routing strategy).
	exclude := h.providerExclusions(r.Context())
	pcfg, routeErr := h.router.RouteOperation(r.Context(), "", "", exclude)
	if routeErr != nil {
		if aiErr, ok := routeErr.(*AIError); ok {
			WriteError(w, aiErr)
			return
		}
		WriteError(w, ErrInternal(routeErr.Error()))
		return
	}
	pcfg = h.passthroughProviderConfig(r.Context(), pcfg)

	// Annotate debug headers.
	h.annotatePassthroughSelection(r.Context(), pcfg.Name, "")
	AIRoutingDecision(h.router.Strategy(), pcfg.Name, "passthrough")

	// Concurrency limiter: acquire a slot before dispatching to the provider.
	if h.ConcurrencyLimiter != nil {
		acquired, acqErr := h.ConcurrencyLimiter.Acquire(r.Context(), pcfg.Name)
		if acqErr != nil || !acquired {
			WriteError(w, ErrRateLimited("provider "+pcfg.Name+" is at max concurrency"))
			return
		}
		defer h.ConcurrencyLimiter.Release(r.Context(), pcfg.Name)
	}

	// Build upstream URL.
	upstreamURL, err := buildPassthroughUpstreamURL(pcfg, path)
	if err != nil {
		WriteError(w, ErrInvalidRequest(err.Error()))
		return
	}

	// Build the upstream request, forwarding body directly via io.Copy semantics.
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		WriteError(w, ErrInternal(err.Error()))
		return
	}

	// Copy headers from original request, inject provider auth, strip internal headers.
	applyRawPassthroughHeaders(upReq, r, pcfg)

	// Append query string from original request.
	if r.URL.RawQuery != "" {
		if upReq.URL.RawQuery != "" {
			upReq.URL.RawQuery += "&" + r.URL.RawQuery
		} else {
			upReq.URL.RawQuery = r.URL.RawQuery
		}
	}

	// Execute the upstream request.
	resp, err := h.client.Do(upReq)
	if err != nil {
		AIProviderError(pcfg.Name, "transport_error")
		WriteError(w, ErrInternal(err.Error()))
		return
	}
	defer resp.Body.Close()

	// Copy all response headers.
	copyPassthroughResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Stream response body back without parsing.
	if _, err := io.Copy(w, resp.Body); err != nil {
		// The status code header has already been sent, so we can only log the error.
		slog.Error("passthrough: error copying response body", "error", err, "provider", pcfg.Name)
	}

	latency := time.Since(start)

	// Record basic metrics.
	if resp.StatusCode >= 400 {
		AIProviderError(pcfg.Name, fmt.Sprintf("%d", resp.StatusCode))
	}
	AIRequestDuration(pcfg.Name, "passthrough", fmt.Sprintf("%d", resp.StatusCode), "false", latency.Seconds())

	// Populate minimal AIUsage for logging.
	if rd := reqctx.GetRequestData(r.Context()); rd != nil {
		rd.AIUsage = &reqctx.AIUsage{
			Provider:        pcfg.Name,
			Model:           "passthrough",
			RoutingStrategy: h.router.Strategy(),
		}
		rd.AddDebugHeader(httputil.HeaderXSbAIProvider, pcfg.Name)
	}
}

// buildPassthroughUpstreamURL constructs the upstream URL for raw passthrough by
// combining the provider's base URL with the request path.
func buildPassthroughUpstreamURL(cfg *ProviderConfig, path string) (string, error) {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	switch cfg.GetType() {
	case "openai", "generic":
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return baseURL + "/" + path, nil
	case "azure":
		if baseURL == "" {
			return "", fmt.Errorf("azure provider requires base_url")
		}
		apiVersion := cfg.APIVersion
		if apiVersion == "" {
			apiVersion = "2024-10-21"
		}
		return fmt.Sprintf("%s/openai/%s?api-version=%s", baseURL, path, apiVersion), nil
	case "anthropic":
		if baseURL == "" {
			baseURL = "https://api.anthropic.com/v1"
		}
		return baseURL + "/" + path, nil
	default:
		if baseURL == "" {
			return "", fmt.Errorf("provider type %q requires base_url for passthrough", cfg.GetType())
		}
		return baseURL + "/" + path, nil
	}
}

// applyRawPassthroughHeaders copies request headers from the original request to
// the upstream request, injects provider authentication, and strips internal
// X-SB-* headers that should not be forwarded upstream.
func applyRawPassthroughHeaders(upstream *http.Request, original *http.Request, cfg *ProviderConfig) {
	for k, values := range original.Header {
		lower := strings.ToLower(k)
		// Skip hop-by-hop and auth headers that will be overwritten.
		switch lower {
		case "authorization", "content-length", "host", "connection",
			"keep-alive", "proxy-authenticate", "proxy-authorization",
			"te", "trailers", "transfer-encoding", "upgrade":
			continue
		}
		// Strip internal X-SB-* headers.
		if strings.HasPrefix(lower, "x-sb-") {
			continue
		}
		for _, v := range values {
			upstream.Header.Add(k, v)
		}
	}

	// Inject provider-specific auth.
	switch cfg.GetType() {
	case "azure":
		upstream.Header.Del("Authorization")
		if cfg.APIKey != "" {
			upstream.Header.Set("api-key", cfg.APIKey)
		}
	case "anthropic":
		if cfg.APIKey != "" {
			upstream.Header.Set("x-api-key", cfg.APIKey)
		}
	default:
		if cfg.AuthHeader != "" && cfg.APIKey != "" {
			prefix := cfg.AuthPrefix
			if prefix == "" {
				prefix = "Bearer"
			}
			upstream.Header.Set(cfg.AuthHeader, prefix+" "+cfg.APIKey)
		} else if cfg.APIKey != "" {
			upstream.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		}
		if cfg.Organization != "" {
			upstream.Header.Set("OpenAI-Organization", cfg.Organization)
		}
		if cfg.ProjectID != "" {
			upstream.Header.Set("OpenAI-Project", cfg.ProjectID)
		}
	}

	// Apply custom provider headers last so they can override defaults.
	for k, v := range cfg.Headers {
		upstream.Header.Set(k, v)
	}
}
