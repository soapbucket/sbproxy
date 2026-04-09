// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
	"github.com/soapbucket/sbproxy/internal/security/signature"
)

// respBufPool pools byte buffers for reading callback response bodies.
var respBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// maxPoolBufferSize caps pooled buffers to prevent memory bloat from large responses.
const maxPoolBufferSize = 1 << 20 // 1MB

// defaultMaxResponseSize is the default limit for callback response bodies.
const defaultMaxResponseSize = 10 << 20 // 10MB

// defaultNegativeCacheTTL is the default duration to cache error results.
const defaultNegativeCacheTTL = 5 * time.Second

// callbackFlight deduplicates concurrent callback requests for the same cache key.
var callbackFlight singleflight.Group

// SignatureVerificationConfig configures webhook signature verification
type SignatureVerificationConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Header  string `json:"header,omitempty"` // Header name for signature (default: X-Signature)
	Secret  string `json:"secret,omitempty" secret:"true"` // Secret for HMAC verification

	// Algorithm: hmac-sha256 (default), hmac-sha512, rsa-sha256, rsa-sha512
	Algorithm string `json:"algorithm,omitempty"`

	// PublicKey for RSA verification (PEM format)
	PublicKey string `json:"public_key,omitempty"`

	// Encoding: base64 (default), hex
	Encoding string `json:"encoding,omitempty"`

	// Timestamp validation
	TimestampHeader string `json:"timestamp_header,omitempty"` // Header for timestamp (default: X-Signature-Timestamp)
	MaxAge          int64  `json:"max_age,omitempty"`          // Max age in seconds (default: 300)

	// Headers to include in signature verification
	IncludeHeaders []string `json:"include_headers,omitempty"`

	// Whether to include response body in signature (default: true)
	IncludeBody bool `json:"include_body,omitempty"`

	// Failure mode: "reject" (default), "warn"
	// reject: return error on verification failure
	// warn: log warning but continue
	FailureMode string `json:"failure_mode,omitempty"`
}

// Callback represents a callback.
type Callback struct {
	URL     string      `json:"url,omitempty"`
	Headers http.Header `json:"headers,omitempty"`
	Method  string      `json:"method,omitempty"`
	Timeout int         `json:"timeout,omitempty"`

	// Body is a Mustache template string for the request body.
	// When set, rendered with the callback context and used as request body
	// instead of JSON-marshaling the obj parameter.
	// Mutually exclusive with FormFields.
	Body string `json:"body,omitempty"`

	// ContentType overrides the default Content-Type header (application/json).
	// Examples: "application/x-www-form-urlencoded", "text/xml", "multipart/form-data"
	ContentType string `json:"content_type,omitempty"`

	// FormFields is a map of field name → Mustache template value for building form bodies.
	// When content_type is "multipart/form-data", builds a multipart body with proper boundaries.
	// When content_type is "application/x-www-form-urlencoded" (or unset), builds URL-encoded body.
	// Mutually exclusive with Body.
	FormFields map[string]string `json:"form_fields,omitempty"`

	ExpectedStatusCodes []int `json:"expected_status_codes,omitempty"`

	CELExpr   string `json:"cel_expr,omitempty"`
	LuaScript string `json:"lua_script,omitempty"`

	CacheDuration reqctx.Duration `json:"cache_duration,omitempty"`
	VariableName  string          `json:"variable_name,omitempty"`

	Async bool `json:"async,omitempty"`

	PreserveRequest bool `json:"preserve_request,omitempty"`

	// Append controls merge behavior for callbacks with same variable_name
	// - false (default): Overwrites existing keys (replace)
	// - true: Appends to array if key exists, creates array if doesn't exist
	Append bool `json:"append,omitempty"`

	// SkipTLSVerifyHost disables TLS certificate verification for this callback.
	// Use for self-signed certs or internal services in test/staging environments.
	SkipTLSVerifyHost bool `json:"skip_tls_verify_host,omitempty"`

	// Signature verification configuration
	Signature *SignatureVerificationConfig `json:"signature,omitempty"`

	// Retry configuration for automatic retry on transient failures
	Retry *RetryConfig `json:"retry,omitempty"`

	// OnError controls error handling behavior
	// - "fail" (default): Return error to caller
	// - "warn": Log warning and return empty result
	// - "ignore": Silently ignore error and return empty result
	OnError string `json:"on_error,omitempty"`

	// HTTPAware enables HTTP-aware caching with ETag, Cache-Control, and
	// conditional request support via the DoHTTPAware execution path.
	HTTPAware bool `json:"http_aware,omitempty"`

	// MaxResponseSize limits callback response body size in bytes (default: 10MB).
	MaxResponseSize int64 `json:"max_response_size,omitempty"`

	// NegativeCacheTTL caches error responses for a short duration to prevent
	// retry storms when an upstream is failing. Set to 0 to disable.
	NegativeCacheTTL reqctx.Duration `json:"negative_cache_ttl,omitempty"`

	celExpr   cel.JSONModifier            `json:"-"`
	luaScript lua.JSONModifier            `json:"-"`
	cacheKey  string                      `json:"-"`
	verifier  *signature.ResponseVerifier `json:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for Callback.
func (c *Callback) UnmarshalJSON(data []byte) error {
	// CacheDuration is now handled by reqctx.Duration type's UnmarshalJSON
	type alias Callback
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*c = Callback(aux)

	if c.CELExpr != "" {
		celExpr, err := cel.NewJSONModifier(c.CELExpr)
		if err != nil {
			return err
		}
		c.celExpr = celExpr
	}
	if c.LuaScript != "" {
		luaScript, err := lua.NewJSONModifier(c.LuaScript)
		if err != nil {
			return err
		}
		c.luaScript = luaScript
	}

	// Validate: Body and FormFields are mutually exclusive
	if c.Body != "" && len(c.FormFields) > 0 {
		return fmt.Errorf("callback: body and form_fields are mutually exclusive")
	}

	// Validate: FormFields requires a form-related content_type (or defaults to url-encoded)
	if len(c.FormFields) > 0 && c.ContentType != "" {
		ct := strings.ToLower(c.ContentType)
		if ct != "multipart/form-data" && ct != "application/x-www-form-urlencoded" {
			return fmt.Errorf("callback: form_fields requires content_type to be multipart/form-data or application/x-www-form-urlencoded, got %q", c.ContentType)
		}
	}

	// Initialize signature verifier if configured
	if c.Signature != nil && c.Signature.Enabled {
		verifier, err := c.initializeSignatureVerifier()
		if err != nil {
			return fmt.Errorf("failed to initialize signature verifier: %w", err)
		}
		c.verifier = verifier
	}

	c.cacheKey = crypto.GetHashFromString(fmt.Sprintf("%s:%s:%v:%v:%s:%s:%s:%d:%s:%s:%v:%v", c.URL, c.Method, c.Headers, c.ExpectedStatusCodes, c.VariableName, c.CELExpr, c.LuaScript, c.CacheDuration.Duration, c.Body, c.ContentType, c.FormFields, c.SkipTLSVerifyHost))

	return nil

}

// GetCacheKey returns the cache key for the Callback.
func (c *Callback) GetCacheKey() string {
	return c.cacheKey
}

// GenerateCacheKey generates a deterministic cache key based on the request context.
// Uses sorted-key marshaling to ensure identical inputs always produce identical keys,
// regardless of Go map iteration order.
func (c *Callback) GenerateCacheKey(obj any) string {
	var buf bytes.Buffer
	marshalDeterministic(&buf, obj)
	return crypto.GetHashFromString(fmt.Sprintf("%s:%s", c.cacheKey, buf.String()))
}

// marshalDeterministic writes a deterministic JSON representation of v into buf.
// Map keys are sorted alphabetically at every nesting level.
func marshalDeterministic(buf *bytes.Buffer, v any) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			marshalDeterministic(buf, val[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			marshalDeterministic(buf, item)
		}
		buf.WriteByte(']')
	default:
		b, _ := json.Marshal(val)
		buf.Write(b)
	}
}

// initializeSignatureVerifier initializes the response signature verifier
func (c *Callback) initializeSignatureVerifier() (*signature.ResponseVerifier, error) {
	if c.Signature == nil || !c.Signature.Enabled {
		return nil, nil
	}

	// Set defaults
	algorithm := c.Signature.Algorithm
	if algorithm == "" {
		algorithm = "hmac-sha256"
	}

	encoding := c.Signature.Encoding
	if encoding == "" {
		encoding = "base64"
	}

	signatureHeader := c.Signature.Header
	if signatureHeader == "" {
		signatureHeader = "X-Signature"
	}

	timestampHeader := c.Signature.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = "X-Signature-Timestamp"
	}

	maxAge := c.Signature.MaxAge
	if maxAge == 0 {
		maxAge = 300 // 5 minutes default
	}

	includeBody := c.Signature.IncludeBody
	// Default to true if not explicitly set
	if !c.Signature.IncludeBody && c.Signature.IncludeHeaders == nil {
		includeBody = true
	}

	// Build signature config
	sigConfig := &signature.SignatureConfig{
		Algorithm:        algorithm,
		Secret:           c.Signature.Secret,
		PublicKey:        c.Signature.PublicKey,
		SignatureHeader:  signatureHeader,
		TimestampHeader:  timestampHeader,
		Encoding:         encoding,
		IncludeHeaders:   c.Signature.IncludeHeaders,
		IncludeBody:      includeBody,
		IncludeTimestamp: true, // Always validate timestamp for security
		MaxTimestampAge:  maxAge,
		Verify:           true,
	}

	// Create verifier
	verifier, err := signature.NewResponseVerifier(sigConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create response verifier: %w", err)
	}

	slog.Info("webhook signature verification enabled",
		"url", c.URL,
		"algorithm", algorithm,
		"max_age", maxAge,
		"include_body", includeBody,
		"include_headers", c.Signature.IncludeHeaders)

	return verifier, nil
}

// Execute routes to the appropriate execution path based on callback configuration.
// When HTTPAware is true and an HTTP cache context is available, uses DoHTTPAware.
// Otherwise falls through to the standard Do path.
func (c *Callback) Execute(ctx context.Context, obj any) (map[string]any, error) {
	if c.HTTPAware {
		return c.DoHTTPAware(ctx, obj)
	}
	return c.Do(ctx, obj)
}

// Do performs the do operation on the Callback.
func (c *Callback) Do(ctx context.Context, obj any) (map[string]any, error) {
	slog.Debug("executing callback", "url", c.URL, "headers", c.Headers, "method", c.Method, "expected_status_codes", c.ExpectedStatusCodes, "variable_name", c.VariableName, "cel_expr", c.CELExpr, "lua_script", c.LuaScript, "cache_duration", c.CacheDuration)

	// Get cache from context (if available)
	cache := GetCache(ctx)

	// Check cache if enabled and available
	if cache != nil && c.CacheDuration.Duration > 0 {
		requestCacheKey := c.GenerateCacheKey(obj)

		// Check circuit breaker
		cb := cache.GetCircuitBreaker(c.cacheKey)
		if !cb.CanExecute() {
			slog.Warn("circuit breaker open, attempting cache",
				"url", c.URL,
				"state", cb.GetState())

			// Try to return cached data even if stale during circuit breaker open
			if cached, found, err := cache.Get(ctx, requestCacheKey); err == nil && found {
				slog.Info("returning cached data due to circuit breaker",
					"url", c.URL)
				return c.wrapResult(cached), nil
			}

			return nil, fmt.Errorf("callback: circuit breaker open and no cached data available")
		}

		// Transition circuit breaker if needed
		cb.transitionToHalfOpen()
		if cb.GetState() == circuitStateHalfOpen {
			cb.IncrementHalfOpenAttempts()
		}

		// Check cache
		if cached, found, err := cache.Get(ctx, requestCacheKey); err == nil && found {
			slog.Debug("cache hit",
				"url", c.URL,
				"cache_key", requestCacheKey)
			cb.RecordSuccess()
			return c.wrapResult(cached), nil
		}

		// Cache miss - use singleflight to coalesce concurrent requests for the same key
		type doResult struct {
			data map[string]any
		}
		sfResult, err, _ := callbackFlight.Do(requestCacheKey, func() (any, error) {
			// Double-check cache after acquiring singleflight slot
			if cached, found, cErr := cache.Get(ctx, requestCacheKey); cErr == nil && found {
				cb.RecordSuccess()
				return &doResult{data: cached}, nil
			}

			unwrappedResult, execErr := c.executeCallback(ctx, obj)
			if execErr != nil {
				cb.RecordFailure()
				// Negative caching: cache error responses briefly to prevent retry storms
				negTTL := c.NegativeCacheTTL.Duration
				if negTTL == 0 {
					negTTL = defaultNegativeCacheTTL
				}
				if negTTL > 0 {
					go func() {
						negCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						// Store empty result with short TTL so next request doesn't immediately retry
						_ = cache.Put(negCtx, requestCacheKey+":neg", map[string]any{}, negTTL)
					}()
				}
				return nil, execErr
			}

			cb.RecordSuccess()

			// Store in cache asynchronously
			go func() {
				cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if putErr := cache.Put(cacheCtx, requestCacheKey, unwrappedResult, c.CacheDuration.Duration); putErr != nil {
					slog.Error("failed to cache response",
						"url", c.URL,
						"error", putErr)
				}
			}()

			return &doResult{data: unwrappedResult}, nil
		})

		if err != nil {
			return nil, err
		}

		return c.wrapResult(sfResult.(*doResult).data), nil
	}

	// No caching, execute directly
	result, err := c.executeCallback(ctx, obj)
	if err != nil {
		return nil, err
	}
	return c.wrapResult(result), nil
}

// executeCallback performs the actual HTTP request
func (c *Callback) executeCallback(ctx context.Context, obj any) (map[string]any, error) {
	client := httputil.GetGlobalHTTPClient()
	if c.SkipTLSVerifyHost {
		client = getInsecureHTTPClient()
	}

	// Determine HTTP method: use config method if specified, default to POST
	method := strings.ToUpper(c.Method)
	if method == "" {
		method = http.MethodPost
	}

	// Use the appropriate method for the request
	var resp *http.Response
	var err error

	// Render URL template if it contains template syntax
	templateCtx := objToTemplateContext(obj)
	renderedURL, err := renderBodyTemplate(c.URL, templateCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to render URL template: %w", err)
	}

	// Build request body from config (body template, form_fields, or default JSON marshal)
	bodyReader, contentType, err := c.buildRequestBody(obj)
	if err != nil {
		return nil, err
	}

	// Create request with appropriate method and body
	req, err := http.NewRequestWithContext(ctx, method, renderedURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if c.Headers != nil {
		req.Header = c.Headers.Clone()
	}

	// Set Content-Type from body builder
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Execute request using client's Do method (protected by circuit breaker)
	cb := circuitbreaker.DefaultRegistry.GetOrCreate(
		"callback:"+c.URL, circuitbreaker.DefaultConfig,
	)
	if cbErr := cb.Call(func() error {
		var doErr error
		resp, doErr = client.Do(ctx, req)
		return doErr
	}); cbErr != nil {
		slog.Error("failed to make request", "method", method, "url", c.URL, "error", cbErr)
		return nil, cbErr
	}
	defer resp.Body.Close()

	// Verify signature if configured
	if c.verifier != nil {
		if err := c.verifySignature(resp); err != nil {
			// Check failure mode
			failureMode := "reject"
			if c.Signature != nil && c.Signature.FailureMode != "" {
				failureMode = c.Signature.FailureMode
			}

			if failureMode == "warn" {
				slog.Warn("signature verification failed but continuing due to failure_mode=warn",
					"url", c.URL,
					"error", err)
			} else {
				slog.Error("signature verification failed",
					"url", c.URL,
					"error", err)
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
		} else {
			slog.Debug("signature verification successful", "url", c.URL)
		}
	}

	if c.ExpectedStatusCodes != nil {
		if !slices.Contains(c.ExpectedStatusCodes, resp.StatusCode) {
			return nil, fmt.Errorf("callback: expected status code %d, got %d", c.ExpectedStatusCodes, resp.StatusCode)
		}
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("callback: expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	buf := respBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		// Only return reasonably-sized buffers to the pool to prevent memory bloat
		if buf.Cap() <= maxPoolBufferSize {
			buf.Reset()
			respBufPool.Put(buf)
		}
	}()
	// Limit response body size to prevent OOM from misbehaving upstreams
	maxSize := c.MaxResponseSize
	if maxSize <= 0 {
		maxSize = defaultMaxResponseSize
	}
	_, err = buf.ReadFrom(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		slog.Error("failed to read response body", "error", err)
		return nil, err
	}
	if int64(buf.Len()) > maxSize {
		return nil, fmt.Errorf("callback: response body exceeds max size of %d bytes", maxSize)
	}
	data := buf.Bytes()

	// Parse JSON response - handle all JSON types (object, array, primitive)
	var jsonResult any
	respContentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if len(data) > 0 && strings.EqualFold(respContentType, "application/json") {
		if err = json.Unmarshal(data, &jsonResult); err != nil {
			slog.Error("failed to decode response", "error", err)
			return nil, err
		}

		// Apply CEL/Lua modifications if configured
		// Note: CEL and Lua modifiers need to handle any type, not just map[string]any
		if c.celExpr != nil {
			// Check if result is a map before passing to ModifyJSON
			if resultMap, ok := jsonResult.(map[string]any); ok {
				jsonResult, err = c.celExpr.ModifyJSON(resultMap)
				if err != nil {
					slog.Error("failed to modify response with CEL", "error", err)
					return nil, err
				}
			} else {
				slog.Warn("CEL expression skipped - response is not a JSON object",
					"url", c.URL,
					"type", fmt.Sprintf("%T", jsonResult))
			}
		}
		if c.luaScript != nil {
			// Check if result is a map before passing to ModifyJSON
			if resultMap, ok := jsonResult.(map[string]any); ok {
				jsonResult, err = c.luaScript.ModifyJSON(resultMap)
				if err != nil {
					slog.Error("failed to modify response with Lua", "error", err)
					return nil, err
				}
			} else {
				slog.Warn("Lua script skipped - response is not a JSON object",
					"url", c.URL,
					"type", fmt.Sprintf("%T", jsonResult))
			}
		}
	}

	// Wrap result in map for storage
	// This allows us to store any JSON type consistently
	result := make(map[string]any)
	if jsonResult != nil {
		// If we have a JSON result, store it
		// For objects: already a map, just return it
		// For arrays/primitives: wrap in a "data" field
		if resultMap, ok := jsonResult.(map[string]any); ok {
			result = resultMap
		} else {
			result["data"] = jsonResult
		}
	}

	return result, nil
}

// verifySignature verifies the response signature
func (c *Callback) verifySignature(resp *http.Response) error {
	if c.verifier == nil {
		return nil
	}

	return c.verifier.VerifyResponse(resp)
}

// DoWithRetry executes the callback with retry support based on the retry configuration.
// If retry is not configured or disabled, behaves the same as Do().
func (c *Callback) DoWithRetry(ctx context.Context, obj any) (map[string]any, error) {
	if c.Retry == nil || !c.Retry.Enabled {
		result, err := c.Do(ctx, obj)
		return c.handleError(result, err)
	}

	executor := NewRetryExecutor(c.Retry)
	var result map[string]any

	err := executor.Execute(ctx, func() error {
		var execErr error
		result, execErr = c.Do(ctx, obj)
		if execErr != nil {
			// Wrap HTTP errors with status code for retry classification
			if strings.Contains(execErr.Error(), "expected status code") {
				// Extract status code from error message
				// Format: "callback: expected status code X, got Y"
				var gotCode int
				if _, scanErr := fmt.Sscanf(execErr.Error(), "callback: expected status code %d, got %d", new(int), &gotCode); scanErr == nil {
					return &HTTPStatusError{StatusCode: gotCode, Message: execErr.Error()}
				}
			}
			return execErr
		}
		return nil
	})

	if err != nil {
		return c.handleError(result, err)
	}
	return result, nil
}

// handleError processes callback errors based on on_error configuration
func (c *Callback) handleError(result map[string]any, err error) (map[string]any, error) {
	if err == nil {
		return result, nil
	}

	switch c.OnError {
	case "warn":
		slog.Warn("callback error (continuing due to on_error=warn)",
			"url", c.URL,
			"error", err)
		return c.wrapResult(make(map[string]any)), nil
	case "ignore":
		return c.wrapResult(make(map[string]any)), nil
	default:
		// "fail" or empty - return the error
		return result, err
	}
}

// wrapResult wraps the result with VariableName
// VariableName should be set by the caller (Callbacks.DoSequential) if not provided
func (c *Callback) wrapResult(result map[string]any) map[string]any {
	if c.VariableName == "" {
		// Should not happen - caller should set auto-generated name
		return map[string]any{"callback": result}
	}
	return map[string]any{c.VariableName: result}
}

// FetchResponse represents a raw HTTP response from a callback
type FetchResponse struct {
	Body        []byte
	Headers     http.Header
	StatusCode  int
	ContentType string
}

// Fetch performs a callback and returns raw response data (not just JSON)
// This is useful for fetching HTML pages, images, or other non-JSON content
// while still benefiting from the caching framework
func (c *Callback) Fetch(ctx context.Context, obj any) (*FetchResponse, error) {
	slog.Debug("fetching raw response", "url", c.URL)

	// Get cache from context (if available)
	cache := GetCache(ctx)

	// Check cache if enabled and available
	if cache != nil && c.CacheDuration.Duration > 0 {
		requestCacheKey := c.GenerateCacheKey(obj) + ":fetch"

		// Check circuit breaker
		cb := cache.GetCircuitBreaker(c.cacheKey)
		if !cb.CanExecute() {
			slog.Warn("circuit breaker open, attempting cache",
				"url", c.URL,
				"state", cb.GetState())

			// Try to return cached data even if stale during circuit breaker open
			if fetchResp, found, err := cache.GetFetch(ctx, requestCacheKey); err == nil && found {
				slog.Info("returning cached data due to circuit breaker",
					"url", c.URL)
				return fetchResp, nil
			}

			return nil, fmt.Errorf("callback: circuit breaker open and no cached data available")
		}

		// Transition circuit breaker if needed
		cb.transitionToHalfOpen()
		if cb.GetState() == circuitStateHalfOpen {
			cb.IncrementHalfOpenAttempts()
		}

		// Check cache
		if fetchResp, found, err := cache.GetFetch(ctx, requestCacheKey); err == nil && found {
			slog.Debug("cache hit",
				"url", c.URL,
				"cache_key", requestCacheKey)
			cb.RecordSuccess()
			return fetchResp, nil
		}

		// Cache miss, execute callback
		fetchResp, err := c.executeFetch(ctx, obj)
		if err != nil {
			cb.RecordFailure()
			return nil, err
		}

		cb.RecordSuccess()

		// Store in cache synchronously to ensure it's available for subsequent requests
		// Use a short timeout context for cache storage
		cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := cache.PutFetch(cacheCtx, requestCacheKey, fetchResp, c.CacheDuration.Duration); err != nil {
			slog.Error("failed to cache fetch response",
				"url", c.URL,
				"error", err)
			// Don't fail the request if caching fails
		}

		return fetchResp, nil
	}

	// No caching, execute directly
	return c.executeFetch(ctx, obj)
}

// executeFetch performs the actual HTTP request and returns raw response data
func (c *Callback) executeFetch(ctx context.Context, obj any) (*FetchResponse, error) {
	client := httputil.GetGlobalHTTPClient()
	if c.SkipTLSVerifyHost {
		client = getInsecureHTTPClient()
	}

	// Determine HTTP method: use config method if specified, default to POST
	method := strings.ToUpper(c.Method)
	if method == "" {
		method = http.MethodPost
	}

	// Use the appropriate method for the request
	var resp *http.Response

	// Render URL template if it contains template syntax
	templateCtx := objToTemplateContext(obj)
	renderedURL, err := renderBodyTemplate(c.URL, templateCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to render URL template: %w", err)
	}

	// Build request body from config (body template, form_fields, or default JSON marshal)
	bodyReader, contentType, err := c.buildRequestBody(obj)
	if err != nil {
		return nil, err
	}

	// Create request with appropriate method and body
	req, err := http.NewRequestWithContext(ctx, method, renderedURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if c.Headers != nil {
		req.Header = c.Headers.Clone()
	}

	// Set Content-Type from body builder
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Execute request using client's Do method (protected by circuit breaker)
	fetchCB := circuitbreaker.DefaultRegistry.GetOrCreate(
		"callback:"+c.URL, circuitbreaker.DefaultConfig,
	)
	if cbErr := fetchCB.Call(func() error {
		var doErr error
		resp, doErr = client.Do(ctx, req)
		return doErr
	}); cbErr != nil {
		slog.Error("failed to make fetch request", "method", method, "url", c.URL, "error", cbErr)
		return nil, cbErr
	}
	defer resp.Body.Close()

	// Verify signature if configured
	if c.verifier != nil {
		if err := c.verifySignature(resp); err != nil {
			failureMode := "reject"
			if c.Signature != nil && c.Signature.FailureMode != "" {
				failureMode = c.Signature.FailureMode
			}

			if failureMode == "warn" {
				slog.Warn("signature verification failed but continuing",
					"url", c.URL,
					"error", err)
			} else {
				slog.Error("signature verification failed",
					"url", c.URL,
					"error", err)
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
		}
	}

	// Check status code expectations
	if c.ExpectedStatusCodes != nil {
		if !slices.Contains(c.ExpectedStatusCodes, resp.StatusCode) {
			return nil, fmt.Errorf("callback: expected status code %v, got %d", c.ExpectedStatusCodes, resp.StatusCode)
		}
	} else if resp.StatusCode != http.StatusOK {
		// For Fetch, we allow non-200 status codes since we're fetching raw data
		// The caller can decide what to do with the status code
		slog.Debug("fetch returned non-200 status",
			"url", c.URL,
			"status_code", resp.StatusCode)
	}

	fetchBuf := respBufPool.Get().(*bytes.Buffer)
	fetchBuf.Reset()
	limitedBody := io.LimitReader(resp.Body, settings.Global.MaxCallbackBodyBytes)
	_, err = fetchBuf.ReadFrom(limitedBody)
	if err != nil {
		fetchBuf.Reset()
		respBufPool.Put(fetchBuf)
		slog.Error("failed to read fetch response body", "error", err)
		return nil, err
	}
	// Check if we hit the size limit
	if int64(fetchBuf.Len()) >= settings.Global.MaxCallbackBodyBytes {
		fetchBuf.Reset()
		respBufPool.Put(fetchBuf)
		slog.Error("callback response body exceeds maximum size", "max_bytes", settings.Global.MaxCallbackBodyBytes)
		return nil, fmt.Errorf("callback response body exceeds maximum size of %d bytes", settings.Global.MaxCallbackBodyBytes)
	}
	// Copy data since it will outlive the pooled buffer
	data := make([]byte, fetchBuf.Len())
	copy(data, fetchBuf.Bytes())
	fetchBuf.Reset()
	respBufPool.Put(fetchBuf)

	respContentType := resp.Header.Get("Content-Type")
	// If Content-Type is empty or is the default text/plain, use application/octet-stream
	if respContentType == "" {
		respContentType = "application/octet-stream"
	} else {
		// Parse Content-Type to check if it's the default text/plain
		parsedCT, _, _ := mime.ParseMediaType(respContentType)
		if parsedCT == "text/plain" && resp.StatusCode != http.StatusOK {
			// For non-200 responses without explicit Content-Type, default to octet-stream
			respContentType = "application/octet-stream"
		}
	}

	return &FetchResponse{
		Body:        data,
		Headers:     resp.Header.Clone(),
		StatusCode:  resp.StatusCode,
		ContentType: respContentType,
	}, nil
}

// Callbacks is a slice type for callbacks.
type Callbacks []*Callback

// Do executes all callbacks in parallel with a timeout based on the callbacks' timeout settings.
// Uses the maximum timeout from all callbacks, or defaults to 10 seconds if none are set.
// DEPRECATED: Use DoSequential for better control over execution order and async behavior.
func (c *Callbacks) Do(ctx context.Context, obj any) (map[string]any, error) {
	// Calculate timeout: use max timeout from all callbacks, or default to 10 seconds
	timeout := 10 * time.Second
	for _, cb := range *c {
		if cb.Timeout > 0 {
			cbTimeout := time.Duration(cb.Timeout) * time.Second
			if cbTimeout > timeout {
				timeout = cbTimeout
			}
		}
	}

	// Use context with timeout to prevent goroutine leaks
	callbackCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var wg sync.WaitGroup
	results := make(chan map[string]any, len(*c))
	errs := make(chan error, len(*c))

	for _, cb := range *c {
		wg.Add(1)
		go func(cb *Callback) {
			// Panic recovery to prevent goroutine crashes
			defer func() {
				if r := recover(); r != nil {
					slog.Error("panic in goroutine",
						"url", cb.URL,
						"panic", r)
					errs <- fmt.Errorf("callback panic: %v", r)
				}
			}()
			defer wg.Done()

			// Use the context-aware Do
			result, err := cb.Do(callbackCtx, obj)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}(cb)
	}

	// Wait for all goroutines with timeout protection
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All callbacks completed
	case <-callbackCtx.Done():
		// Context cancelled or timed out
		slog.Warn("context cancelled or timed out",
			"error", callbackCtx.Err())
		return nil, fmt.Errorf("callbacks timed out: %w", callbackCtx.Err())
	}

	// Close channels after all goroutines complete
	close(errs)
	close(results)

	var errArray []error
	for err := range errs {
		errArray = append(errArray, err)
	}

	result := make(map[string]any)
	for r := range results {
		maps.Copy(result, r)
	}

	err := errors.Join(errArray...)
	return result, err
}

// DoSequential executes callbacks sequentially in order.
// If a callback has Async=true, it's executed in the background without waiting.
// If a callback has Async=false (default), it's executed synchronously and we wait for completion.
// Returns the merged results from all synchronous callbacks.
//
// Auto-naming: If variable_name is not specified, uses "callback_<index>" (1-indexed)
// Append mode: If append=true, appends results to array instead of replacing
func (c *Callbacks) DoSequential(ctx context.Context, obj any) (map[string]any, error) {
	return c.DoSequentialWithType(ctx, obj, "callback")
}

// DoSequentialWithType executes callbacks with a specific type prefix for auto-naming
// Type examples: "on_request", "on_session_start", "on_load"
// Auto-generated names: "on_request_1", "on_request_2", etc. (1-indexed)
func (c *Callbacks) DoSequentialWithType(ctx context.Context, obj any, callbackType string) (map[string]any, error) {
	if len(*c) == 0 {
		return make(map[string]any), nil
	}

	result := make(map[string]any)
	var errArray []error

	for i, cb := range *c {
		// Determine variable name without mutating the shared Callback struct.
		// Create a shallow copy with the correct VariableName to avoid data races
		// when multiple goroutines call DoSequentialWithType concurrently.
		varName := cb.VariableName
		if varName == "" {
			varName = fmt.Sprintf("%s_%d", callbackType, i+1)
		}
		cbCopy := *cb
		cbCopy.VariableName = varName

		if cb.Async {
			// Execute asynchronously in background
			go func(localCb Callback, obj any) {
				// Panic recovery to prevent goroutine crashes
				defer func() {
					if r := recover(); r != nil {
						slog.Error("panic in async callback goroutine",
							"url", localCb.URL,
							"panic", r)
					}
				}()

				// Create context with timeout for async callback
				timeout := 10 * time.Second
				if localCb.Timeout > 0 {
					timeout = time.Duration(localCb.Timeout) * time.Second
				}
				asyncCtx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()

				_, err := localCb.Execute(asyncCtx, obj)
				if err != nil {
					slog.Error("async callback failed",
						"url", localCb.URL,
						"error", err)
				} else {
					slog.Debug("async callback completed",
						"url", localCb.URL)
				}
			}(cbCopy, obj)

			slog.Debug("started async callback",
				"url", cb.URL)
		} else {
			// Execute synchronously
			timeout := 10 * time.Second
			if cb.Timeout > 0 {
				timeout = time.Duration(cb.Timeout) * time.Second
			}

			callbackCtx, cancel := context.WithTimeout(ctx, timeout)
			cbResult, err := cbCopy.Execute(callbackCtx, obj)
			cancel()

			if err != nil {
				errArray = append(errArray, err)
				slog.Error("synchronous callback failed",
					"url", cb.URL,
					"error", err)
			} else {
				// Merge results based on append flag
				if cb.Append {
					// Append mode: collect results in arrays
					for key, value := range cbResult {
						if existing, exists := result[key]; exists {
							// Key exists - append to array
							if existingArray, ok := existing.([]any); ok {
								// Already an array, append
								result[key] = append(existingArray, value)
							} else {
								// Convert to array with both values
								result[key] = []any{existing, value}
							}
						} else {
							// New key - store as single value (will become array if more callbacks add to it)
							result[key] = value
						}
					}
				} else {
					// Replace mode (default): overwrite existing keys
					maps.Copy(result, cbResult)
				}

				slog.Debug("synchronous callback completed",
					"url", cb.URL,
					"append", cb.Append)
			}
		}
	}

	err := errors.Join(errArray...)
	return result, err
}

// DoParallelWithType executes all synchronous callbacks concurrently using errgroup,
// then merges results in index order. Async callbacks are still fired in the background.
// This is useful for on_load when callbacks are independent and can run simultaneously.
func (c *Callbacks) DoParallelWithType(ctx context.Context, obj any, callbackType string) (map[string]any, error) {
	if len(*c) == 0 {
		return make(map[string]any), nil
	}

	type indexedResult struct {
		index  int
		data   map[string]any
		append bool
	}

	var asyncCallbacks []Callback
	var syncCallbacks []struct {
		index int
		cb    Callback
	}

	// Separate async and sync callbacks, assign variable names
	for i, cb := range *c {
		varName := cb.VariableName
		if varName == "" {
			varName = fmt.Sprintf("%s_%d", callbackType, i+1)
		}
		cbCopy := *cb
		cbCopy.VariableName = varName

		if cb.Async {
			asyncCallbacks = append(asyncCallbacks, cbCopy)
		} else {
			syncCallbacks = append(syncCallbacks, struct {
				index int
				cb    Callback
			}{index: i, cb: cbCopy})
		}
	}

	// Fire async callbacks in the background
	for _, acb := range asyncCallbacks {
		go func(localCb Callback) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("panic in async callback goroutine",
						"url", localCb.URL, "panic", r)
				}
			}()
			timeout := 10 * time.Second
			if localCb.Timeout > 0 {
				timeout = time.Duration(localCb.Timeout) * time.Second
			}
			asyncCtx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if _, err := localCb.Execute(asyncCtx, obj); err != nil {
				slog.Error("async callback failed", "url", localCb.URL, "error", err)
			}
		}(acb)
	}

	// Execute sync callbacks in parallel
	results := make([]indexedResult, len(syncCallbacks))
	g, gctx := errgroup.WithContext(ctx)

	for idx, sc := range syncCallbacks {
		g.Go(func() error {
			timeout := 10 * time.Second
			if sc.cb.Timeout > 0 {
				timeout = time.Duration(sc.cb.Timeout) * time.Second
			}
			callbackCtx, cancel := context.WithTimeout(gctx, timeout)
			defer cancel()

			cbResult, err := sc.cb.Execute(callbackCtx, obj)
			if err != nil {
				slog.Error("parallel callback failed",
					"url", sc.cb.URL, "error", err)
				return err
			}
			results[idx] = indexedResult{
				index:  sc.index,
				data:   cbResult,
				append: sc.cb.Append,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		// Collect partial results even on error
		merged := make(map[string]any)
		for _, r := range results {
			if r.data != nil {
				maps.Copy(merged, r.data)
			}
		}
		return merged, err
	}

	// Merge results in index order
	merged := make(map[string]any)
	for _, r := range results {
		if r.data == nil {
			continue
		}
		if r.append {
			for key, value := range r.data {
				if existing, exists := merged[key]; exists {
					if existingArray, ok := existing.([]any); ok {
						merged[key] = append(existingArray, value)
					} else {
						merged[key] = []any{existing, value}
					}
				} else {
					merged[key] = value
				}
			}
		} else {
			maps.Copy(merged, r.data)
		}
	}

	return merged, nil
}
