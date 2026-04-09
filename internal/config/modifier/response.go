// Package modifier provides request and response modification capabilities for header, body, and URL transformations.
package modifier

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
)

// StreamingConfigProvider provides access to streaming configuration
// This interface breaks the import cycle between config and modifier packages
// Config.GetStreamingConfig() implements this interface
type StreamingConfigProvider interface {
	GetStreamingConfig() StreamingConfig
}

// StreamingConfig matches config.StreamingConfigValues to avoid import cycle
type StreamingConfig struct {
	Enabled              bool
	MaxBufferedBodySize  int64
	MaxProcessableBodySize int64
	ModifierThreshold    int64
	TransformThreshold   int64
	SignatureThreshold   int64
	CallbackThreshold    int64
}

// ResponseModifier represents a response modifier.
type ResponseModifier struct {
	Status  *StatusModifications `json:"status,omitempty"`
	Headers *HeaderModifications `json:"headers,omitempty"`
	Body    *BodyModifications   `json:"body,omitempty"`

	Rules rule.ResponseRules `json:"rules,omitempty"`

	LuaScript string `json:"lua_script,omitempty"`

	luamodifier       lua.ResponseModifier `json:"-"`
}

// StatusModifications provides control over response status modifications
type StatusModifications struct {
	Code int    `json:"code,omitempty"` // Set status code
	Text string `json:"text,omitempty"` // Set status text (overrides default, format: "200 Custom Text")
}

// UnmarshalJSON implements the json.Unmarshaler interface for ResponseModifier.
func (m *ResponseModifier) UnmarshalJSON(data []byte) error {
	// Check for deprecated cel_expr field
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err == nil {
		if _, hasCEL := raw["cel_expr"]; hasCEL {
			return fmt.Errorf("cel_expr is no longer supported in response modifiers; use lua_script instead")
		}
	}

	type Alias ResponseModifier
	alias := (*Alias)(m)
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	if m.LuaScript != "" {
		luamodifier, err := lua.NewResponseModifier(m.LuaScript)
		if err != nil {
			return err
		}
		m.luamodifier = luamodifier
	}

	return nil
}

// Match performs the match operation on the ResponseModifier.
func (m *ResponseModifier) Match(resp *http.Response) bool {
	if len(m.Rules) == 0 || m.Rules.Match(resp) {
		return true
	}
	return false
}

// Apply performs the apply operation on the ResponseModifier.
func (m *ResponseModifier) Apply(resp *http.Response) error {
	if !m.Match(resp) {
		return nil
	}

	// Apply Lua modifier (if present)
	if m.luamodifier != nil {
		if err := m.luamodifier.ModifyResponse(resp); err != nil {
			slog.Debug("Lua modifier error", "error", err)
			// No-op on error - continue processing
		}
	}

	// Modify status
	if m.Status != nil {
		if m.Status.Code != 0 {
			resp.StatusCode = m.Status.Code
		}
		// Set status text if provided
		// Format: "200 OK" or custom like "200 Custom Text"
		// Template variables are supported in status text (e.g., {{request.id}})
		if m.Status.Text != "" {
			// Resolve template variables in status text
			var req *http.Request
			if resp.Request != nil {
				req = resp.Request
			}
			resolvedText := resolveTemplateVariables(m.Status.Text, req)
			
			if m.Status.Code != 0 {
				resp.Status = fmt.Sprintf("%d %s", m.Status.Code, resolvedText)
			} else {
				// If only text provided, prepend the current status code
				resp.Status = fmt.Sprintf("%d %s", resp.StatusCode, resolvedText)
			}
		} else if m.Status.Code != 0 {
			// If only code provided, use default status text
			resp.Status = fmt.Sprintf("%d %s", m.Status.Code, http.StatusText(m.Status.Code))
		}
	}

	// Modify headers
	if m.Headers != nil {
		// Pass request to allow template variable resolution (e.g., {{request.data.key}})
		var req *http.Request
		if resp.Request != nil {
			req = resp.Request
		}
		applyHeaderModificationsWithRequest(resp.Header, m.Headers, req)
	}

	// Modify body
	if m.Body != nil {
		if err := applyResponseBodyModifications(resp, m.Body); err != nil {
			return err
		}
	}

	return nil
}

func applyResponseBodyModifications(resp *http.Response, mods *BodyModifications) error {
	// Get streaming config from request context if available
	var threshold int64 = httputil.DefaultModifierThreshold
	if resp.Request != nil {
		// Try to get streaming config provider from request context
		if provider := getStreamingConfigProviderFromRequest(resp.Request); provider != nil {
			sc := provider.GetStreamingConfig()
			// StreamingConfig already has int64 values, use them directly
			if sc.Enabled {
				threshold = sc.ModifierThreshold
				
				// Check Content-Length before reading
				if resp.ContentLength > 0 && resp.ContentLength > threshold {
					slog.Warn("Response body too large for modifications, skipping",
						"content_length", resp.ContentLength,
						"threshold", threshold)
					return nil // Pass through without modifications
				}
			}
		}
	}

	// Read existing body if present
	var bodyBytes []byte
	if resp.Body != nil {
		// Close body to ensure cleanup (even on error)
		defer resp.Body.Close()
		
		// Wrap body with size tracker to monitor during read
		sizeTracker := httputil.NewSizeTracker(resp.Body, threshold)
		resp.Body = sizeTracker
		
		// Attempt to read (will detect if exceeds threshold)
		body, err := io.ReadAll(sizeTracker)
		if err != nil {
			return err
		}
		
		// Check if threshold was exceeded during read
		if sizeTracker.Exceeded() {
			slog.Warn("Response body exceeded threshold during read, skipping modifications",
				"bytes_read", sizeTracker.BytesRead(),
				"threshold", threshold)
			// Body was consumed during read, create new reader from what we read
			// This allows the response to continue with the original body content
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			return nil
		}
		
		bodyBytes = body
	}

	// Apply modifications (priority: ReplaceBase64 > ReplaceJSON > Replace > Remove)
	if mods.ReplaceBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(mods.ReplaceBase64)
		if err != nil {
			return err
		}
		bodyBytes = decoded
	} else if len(mods.ReplaceJSON) > 0 {
		// Validate JSON (json.RawMessage should already be valid, but we verify)
		if !json.Valid(mods.ReplaceJSON) {
			return fmt.Errorf("invalid JSON")
		}
		// Use the raw message directly (it's already validated JSON)
		bodyBytes = mods.ReplaceJSON
		// Set Content-Type header for JSON
		if resp.Header == nil {
			resp.Header = make(http.Header)
		}
		resp.Header.Set("Content-Type", "application/json")
	} else if mods.Replace != "" {
		// Resolve template variables in body replacement
		var req *http.Request
		if resp.Request != nil {
			req = resp.Request
		}
		resolvedBody := resolveTemplateVariables(mods.Replace, req)
		bodyBytes = []byte(resolvedBody)
	} else if mods.Remove {
		bodyBytes = []byte{}
	}

	// Replace body
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	// Update Content-Length header
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	if len(bodyBytes) == 0 {
		resp.Header.Del("Content-Length")
	} else {
		resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	}

	return nil
}

// streamingConfigProviderContextKey is used to store StreamingConfigProvider in context
// Must match the type in config package
type streamingConfigProviderContextKey struct{}

// getStreamingConfigProviderFromRequest attempts to get streaming config provider from request context
func getStreamingConfigProviderFromRequest(req *http.Request) StreamingConfigProvider {
	if req == nil {
		return nil
	}
	return getStreamingConfigProviderFromContext(req.Context())
}

// getStreamingConfigProviderFromContext retrieves streaming config provider from context
func getStreamingConfigProviderFromContext(ctx context.Context) StreamingConfigProvider {
	// Try to get as interface first
	if provider, ok := ctx.Value(streamingConfigProviderContextKey{}).(StreamingConfigProvider); ok {
		return provider
	}
	// Fallback: try to get as any and type assert
	if val := ctx.Value(streamingConfigProviderContextKey{}); val != nil {
		if provider, ok := val.(StreamingConfigProvider); ok {
			return provider
		}
	}
	return nil
}

// ResponseModifiers is a slice type for response modifiers.
type ResponseModifiers []ResponseModifier

// Apply performs the apply operation on the ResponseModifiers.
func (m ResponseModifiers) Apply(resp *http.Response) error {
	for _, modifier := range m {
		if err := modifier.Apply(resp); err != nil {
			return err
		}
	}
	return nil
}
