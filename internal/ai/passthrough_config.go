// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// PassThroughEndpoint defines a single declarative pass-through route.
type PassThroughEndpoint struct {
	// Path is the route pattern (e.g., "/v1/custom/summarize").
	Path string `json:"path"`
	// TargetURL is the upstream URL to forward requests to.
	TargetURL string `json:"target_url"`
	// Methods restricts which HTTP methods are allowed. Empty means all methods.
	Methods []string `json:"methods,omitempty"`
	// Headers are additional headers to inject. Values support ${VAR} variable
	// substitution from environment variables.
	Headers map[string]string `json:"headers,omitempty"`
	// Timeout for the upstream request.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// PassThroughRouter builds HTTP handlers from a list of PassThroughEndpoint configs.
type PassThroughRouter struct {
	endpoints []PassThroughEndpoint
	client    *http.Client
}

// NewPassThroughRouter creates a router from the given endpoint configurations.
func NewPassThroughRouter(endpoints []PassThroughEndpoint) *PassThroughRouter {
	return &PassThroughRouter{
		endpoints: endpoints,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Routes returns the configured endpoints for registration with a router (e.g., chi).
func (ptr *PassThroughRouter) Routes() []PassThroughEndpoint {
	return ptr.endpoints
}

// HandlerFor creates an http.Handler for a specific endpoint.
func (ptr *PassThroughRouter) HandlerFor(ep PassThroughEndpoint) http.Handler {
	resolvedHeaders := resolveHeaders(ep.Headers)
	client := ptr.client
	if ep.Timeout > 0 {
		client = &http.Client{Timeout: ep.Timeout}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Method check.
		if len(ep.Methods) > 0 && !methodAllowed(r.Method, ep.Methods) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Build upstream request.
		upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, ep.TargetURL, r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create upstream request: %v", err), http.StatusBadGateway)
			return
		}

		// Copy original headers.
		for k, values := range r.Header {
			lower := strings.ToLower(k)
			if lower == "host" || lower == "content-length" {
				continue
			}
			for _, v := range values {
				upstreamReq.Header.Add(k, v)
			}
		}

		// Inject configured headers (with resolved variables).
		for k, v := range resolvedHeaders {
			upstreamReq.Header.Set(k, v)
		}

		resp, err := client.Do(upstreamReq)
		if err != nil {
			http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers.
		for k, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

// resolveHeaders performs ${VAR} substitution on header values using
// environment variables.
func resolveHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	resolved := make(map[string]string, len(headers))
	for k, v := range headers {
		resolved[k] = resolveVars(v)
	}
	return resolved
}

// resolveVars replaces ${VAR_NAME} patterns with environment variable values.
func resolveVars(s string) string {
	result := s
	for {
		start := strings.Index(result, "${")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start
		varName := result[start+2 : end]
		varValue := os.Getenv(varName)
		result = result[:start] + varValue + result[end+1:]
	}
	return result
}

// methodAllowed checks if the request method is in the allowed list.
func methodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// ValidatePassThroughEndpoints checks that all endpoints have required fields.
func ValidatePassThroughEndpoints(endpoints []PassThroughEndpoint) error {
	for i, ep := range endpoints {
		if ep.Path == "" {
			return fmt.Errorf("pass_through_endpoints[%d]: path is required", i)
		}
		if ep.TargetURL == "" {
			return fmt.Errorf("pass_through_endpoints[%d]: target_url is required", i)
		}
	}
	return nil
}
