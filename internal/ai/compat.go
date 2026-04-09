// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	json "github.com/goccy/go-json"
	"net/http"
	"strings"
)

// sdkPassthroughHeaders lists headers that SDKs set and should be preserved on the
// outbound request to providers so that organization/version routing works correctly.
var sdkPassthroughHeaders = []string{
	"OpenAI-Organization",
	"OpenAI-Project",
	"Anthropic-Version",
	"Anthropic-Beta",
	"X-Request-ID",
}

// rateLimitHeaderMap maps common provider-specific rate limit headers to a
// normalized format. The normalized names follow the OpenAI convention which
// most SDKs already understand.
var rateLimitHeaderMap = map[string]string{
	"x-ratelimit-limit-requests":     "x-ratelimit-limit-requests",
	"x-ratelimit-limit-tokens":       "x-ratelimit-limit-tokens",
	"x-ratelimit-remaining-requests": "x-ratelimit-remaining-requests",
	"x-ratelimit-remaining-tokens":   "x-ratelimit-remaining-tokens",
	"x-ratelimit-reset-requests":     "x-ratelimit-reset-requests",
	"x-ratelimit-reset-tokens":       "x-ratelimit-reset-tokens",
	// Anthropic uses slightly different names
	"anthropic-ratelimit-requests-limit":     "x-ratelimit-limit-requests",
	"anthropic-ratelimit-requests-remaining": "x-ratelimit-remaining-requests",
	"anthropic-ratelimit-requests-reset":     "x-ratelimit-reset-requests",
	"anthropic-ratelimit-tokens-limit":       "x-ratelimit-limit-tokens",
	"anthropic-ratelimit-tokens-remaining":   "x-ratelimit-remaining-tokens",
	"anthropic-ratelimit-tokens-reset":       "x-ratelimit-reset-tokens",
}

// CompatLayer provides SDK compatibility transformations so that requests and
// responses work seamlessly with the OpenAI Python/Node SDKs, the Anthropic
// SDK, and other popular clients.
type CompatLayer struct{}

// NewCompatLayer creates a new CompatLayer instance.
func NewCompatLayer() *CompatLayer {
	return &CompatLayer{}
}

// ForwardPassthroughHeaders copies SDK-set headers from the inbound request
// into the outbound provider request so that organization routing and version
// pinning work correctly.
func (c *CompatLayer) ForwardPassthroughHeaders(src http.Header, dst http.Header) {
	for _, name := range sdkPassthroughHeaders {
		if v := src.Get(name); v != "" {
			dst.Set(name, v)
		}
	}
}

// MapRateLimitHeaders reads provider-specific rate limit headers from the
// upstream response and writes normalized versions into the client response so
// that SDK retry logic works regardless of which provider served the request.
func (c *CompatLayer) MapRateLimitHeaders(providerResp http.Header, clientResp http.Header) {
	for src, dst := range rateLimitHeaderMap {
		if v := providerResp.Get(src); v != "" {
			clientResp.Set(dst, v)
		}
	}
}

// EchoRequestID copies the X-Request-ID from the inbound request to the
// response so that callers can correlate responses with their requests.
func (c *CompatLayer) EchoRequestID(r *http.Request, w http.ResponseWriter) {
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		w.Header().Set("X-Request-ID", reqID)
	}
}

// EnsureStreamUsage verifies that stream_options.include_usage is respected. If
// the client requested usage data in the stream, this method ensures the final
// chunk carries a non-nil Usage field. If usage is nil a zero-value Usage is
// attached so the SDK does not error on a missing field.
func (c *CompatLayer) EnsureStreamUsage(req *ChatCompletionRequest, finalChunk *StreamChunk) {
	if req.StreamOptions == nil || !req.StreamOptions.IncludeUsage {
		return
	}
	if finalChunk == nil {
		return
	}
	if finalChunk.Usage == nil {
		finalChunk.Usage = &Usage{}
	}
}

// NormalizeErrorResponse takes an arbitrary error body from a provider and
// re-encodes it in the standard OpenAI error envelope. If the body is already
// in the correct format it is returned unchanged.
func (c *CompatLayer) NormalizeErrorResponse(statusCode int, body []byte) []byte {
	// Try to parse as the standard format first.
	var standard ErrorResponse
	if err := json.Unmarshal(body, &standard); err == nil && standard.Error.Message != "" {
		return body
	}

	// Try Anthropic format: {"type":"error","error":{"type":"...","message":"..."}}
	var anthropicErr struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &anthropicErr); err == nil && anthropicErr.Error.Message != "" {
		normalized := ErrorResponse{
			Error: AIError{
				StatusCode: statusCode,
				Type:       mapErrorType(anthropicErr.Error.Type),
				Message:    anthropicErr.Error.Message,
				Code:       anthropicErr.Error.Type,
			},
		}
		out, _ := json.Marshal(normalized)
		return out
	}

	// Try a flat {"message":"...","code":...} format used by some providers.
	var flat struct {
		Message string `json:"message"`
		Code    any    `json:"code"`
	}
	if err := json.Unmarshal(body, &flat); err == nil && flat.Message != "" {
		normalized := ErrorResponse{
			Error: AIError{
				StatusCode: statusCode,
				Type:       httpStatusToErrorType(statusCode),
				Message:    flat.Message,
			},
		}
		out, _ := json.Marshal(normalized)
		return out
	}

	// Fallback: wrap the raw body string as the message.
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(statusCode)
	}
	normalized := ErrorResponse{
		Error: AIError{
			StatusCode: statusCode,
			Type:       httpStatusToErrorType(statusCode),
			Message:    msg,
		},
	}
	out, _ := json.Marshal(normalized)
	return out
}

// mapErrorType converts a provider error type string to the OpenAI convention.
func mapErrorType(providerType string) string {
	switch providerType {
	case "not_found_error":
		return "invalid_request_error"
	case "authentication_error":
		return "authentication_error"
	case "permission_error":
		return "permission_error"
	case "rate_limit_error":
		return "rate_limit_error"
	case "overloaded_error", "api_error":
		return "server_error"
	default:
		return "server_error"
	}
}

// httpStatusToErrorType derives an OpenAI error type from an HTTP status code.
func httpStatusToErrorType(code int) string {
	switch {
	case code == http.StatusUnauthorized:
		return "authentication_error"
	case code == http.StatusForbidden:
		return "permission_error"
	case code == http.StatusTooManyRequests:
		return "rate_limit_error"
	case code == http.StatusBadRequest, code == http.StatusNotFound, code == http.StatusConflict:
		return "invalid_request_error"
	default:
		return "server_error"
	}
}
