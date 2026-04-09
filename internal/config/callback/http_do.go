// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/platform/circuitbreaker"
)

var (
	insecureHTTPClient     *httputil.HTTPClient
	insecureHTTPClientOnce sync.Once
)

// getInsecureHTTPClient returns a cached HTTP client with TLS verification disabled
func getInsecureHTTPClient() *httputil.HTTPClient {
	insecureHTTPClientOnce.Do(func() {
		config := httputil.DefaultHTTPClientConfig()
		config.SkipTLSVerifyHost = true
		insecureHTTPClient = httputil.NewHTTPClient(config)
	})
	return insecureHTTPClient
}

// DoHTTPAware performs a callback with HTTP-aware caching.
// This method integrates HTTP cache headers, stale-while-revalidate, background refresh,
// and outbound conditional requests (If-None-Match / If-Modified-Since).
func (c *Callback) DoHTTPAware(ctx context.Context, obj any) (map[string]any, error) {
	startTime := time.Now()
	requestCacheKey := c.GenerateCacheKey(obj)

	slog.Debug("starting HTTP-aware callback request",
		"url", c.URL,
		"method", c.Method,
		"cache_key", requestCacheKey,
		"timestamp", startTime)

	// Get HTTP cache context
	httpCtx := GetHTTPCacheContext(ctx)
	if httpCtx == nil || httpCtx.HTTPCache == nil {
		// Fall back to regular caching or direct execution
		slog.Debug("no HTTP cache context, using regular execution",
			"url", c.URL)
		return c.Do(ctx, obj)
	}

	// Extract inbound conditional headers if available
	var ifNoneMatch, ifModifiedSince string
	if reqHeaders, ok := ctx.Value("request_headers").(map[string]string); ok {
		ifNoneMatch, ifModifiedSince = ExtractConditionalHeaders(ctx, reqHeaders)
	}

	// Check circuit breaker
	cb := httpCtx.HTTPCache.GetCircuitBreaker(c.cacheKey)
	if !cb.CanExecute() {
		slog.Warn("circuit breaker open, attempting stale cache",
			"url", c.URL,
			"state", cb.GetState())

		// Try to return stale cached data (even if expired, serve stale if available)
		cached, found, err := httpCtx.HTTPCache.Get(ctx, requestCacheKey)
		if err == nil && found && cached != nil {
			now := time.Now()
			state := cached.GetState(now)
			// Serve stale if available (even expired, as long as it exists and has data)
			if cached.Data != nil && (state == StateStale || state == StateStaleError || state == StateExpired) {
				slog.Info("returning cached data due to circuit breaker",
					"url", c.URL,
					"state", state.String())
				return c.wrapResult(cached.Data), nil
			}
		}

		return nil, fmt.Errorf("callback: circuit breaker open and no usable cached data available")
	}

	// Transition circuit breaker if needed
	cb.transitionToHalfOpen()
	if cb.GetState() == circuitStateHalfOpen {
		cb.IncrementHalfOpenAttempts()
	}

	// Check cache
	cached, found, err := httpCtx.HTTPCache.Get(ctx, requestCacheKey)
	if err != nil {
		slog.Error("cache lookup error",
			"url", c.URL,
			"cache_key", requestCacheKey,
			"error", err)
		cb.RecordFailure()
		// Continue to origin fetch
	}

	now := time.Now()
	if found && cached != nil {
		state := cached.GetState(now)

		// Handle conditional requests
		if ifNoneMatch != "" || ifModifiedSince != "" {
			condResult, handled, err := httpCtx.HTTPCache.HandleConditionalRequest(ctx, requestCacheKey, cached, ifNoneMatch, ifModifiedSince)
			if err == nil && handled && condResult.NotModified {
				slog.Info("conditional request - not modified",
					"url", c.URL,
					"cache_key", requestCacheKey,
					"if_none_match", ifNoneMatch,
					"if_modified_since", ifModifiedSince)
				cb.RecordSuccess()
				// Return empty result to indicate not modified
				return c.wrapResult(map[string]any{}), nil
			}
		}

		// Serve fresh cache
		if state == StateFresh {
			slog.Info("cache hit - serving fresh content",
				"url", c.URL,
				"cache_key", requestCacheKey,
				"age", now.Sub(cached.CachedAt),
				"duration", time.Since(startTime))
			cb.RecordSuccess()
			return c.wrapResult(cached.Data), nil
		}

		// Serve stale cache if allowed
		if state == StateStale || (state == StateStaleError && httpCtx.Config != nil && httpCtx.Config.StaleIfError != nil && httpCtx.Config.StaleIfError.Enabled) {
			slog.Info("cache hit - serving stale content",
				"url", c.URL,
				"cache_key", requestCacheKey,
				"state", state.String(),
				"age", now.Sub(cached.CachedAt),
				"duration", time.Since(startTime))

			// Trigger background refresh if enabled
			if httpCtx.Config != nil && httpCtx.Config.BackgroundRefresh != nil && httpCtx.Config.BackgroundRefresh.Enabled {
				if httpCtx.RefreshQueue != nil && !httpCtx.HTTPCache.IsRevalidating(requestCacheKey) {
					task := &RevalidationTask{
						Key:         requestCacheKey,
						CallbackURL: c.URL,
						Method:      c.Method,
						Headers:     flattenHeaders(c.Headers),
						RequestData: objToMap(obj),
						Timestamp:   now,
					}
					if err := httpCtx.RefreshQueue.Enqueue(task); err != nil {
						slog.Warn("failed to enqueue refresh task",
							"url", c.URL,
							"error", err)
					} else {
						slog.Debug("enqueued background refresh",
							"url", c.URL,
							"cache_key", requestCacheKey)
					}
				}
			}

			cb.RecordSuccess()
			return c.wrapResult(cached.Data), nil
		}
	}

	// Cache miss or expired - fetch from origin
	slog.Debug("cache miss - fetching from origin",
		"url", c.URL,
		"cache_key", requestCacheKey)

	// Execute callback with outbound conditional headers if we have a cached version.
	// This allows the upstream to return 304 Not Modified, saving bandwidth.
	result, resp, err := c.executeCallbackWithConditional(ctx, obj, cached)
	if err != nil {
		cb.RecordFailure()
		slog.Error("origin fetch failed",
			"url", c.URL,
			"cache_key", requestCacheKey,
			"error", err,
			"duration", time.Since(startTime))

		// Try stale-if-error if enabled
		if found && cached != nil && httpCtx.Config != nil && httpCtx.Config.StaleIfError != nil && httpCtx.Config.StaleIfError.Enabled {
			state := cached.GetState(now)
			if state == StateStaleError {
				slog.Warn("origin error, serving stale cache (stale-if-error)",
					"url", c.URL,
					"cache_key", requestCacheKey)
				return c.wrapResult(cached.Data), nil
			}
		}

		return nil, err
	}

	cb.RecordSuccess()

	// Parse HTTP cache metadata from response
	if httpCtx.Parser != nil && resp != nil {
		metadata, err := httpCtx.Parser.ParseResponse(resp)
		if err == nil {
			// Calculate response size
			jsonData, _ := json.Marshal(result)
			size := int64(len(jsonData))

			// Store in cache asynchronously
			go func() {
				cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				headers := make(map[string][]string)
				for k, v := range resp.Header {
					headers[k] = v
				}

				if err := httpCtx.HTTPCache.Put(cacheCtx, requestCacheKey, result, metadata, headers, resp.StatusCode, size); err != nil {
					slog.Error("failed to cache HTTP response",
						"url", c.URL,
						"cache_key", requestCacheKey,
						"error", err)
				} else {
					slog.Debug("cached HTTP response",
						"url", c.URL,
						"cache_key", requestCacheKey,
						"tier", metadata.ExpiresAt,
						"size", size)
				}
			}()
		}
	}

	slog.Info("origin fetch successful",
		"url", c.URL,
		"cache_key", requestCacheKey,
		"duration", time.Since(startTime))

	return c.wrapResult(result), nil
}

// executeCallbackWithConditional wraps executeCallbackWithResponse, adding outbound
// conditional request headers (If-None-Match / If-Modified-Since) when a cached version
// exists. If the upstream returns 304 Not Modified, the cached data is reused.
func (c *Callback) executeCallbackWithConditional(ctx context.Context, obj any, cached *HTTPCachedCallbackResponse) (map[string]any, *http.Response, error) {
	// Build conditional headers from cached response
	var conditionalHeaders map[string]string
	if cached != nil {
		conditionalHeaders = make(map[string]string)
		if cached.ETag != "" {
			conditionalHeaders["If-None-Match"] = `"` + cached.ETag + `"`
		}
		if !cached.LastModified.IsZero() {
			conditionalHeaders["If-Modified-Since"] = cached.LastModified.UTC().Format(http.TimeFormat)
		}
	}

	result, resp, err := c.executeCallbackWithResponse(ctx, obj, conditionalHeaders)
	if err != nil {
		return nil, nil, err
	}

	// Handle 304 Not Modified - reuse cached data, refresh cache TTL
	if resp != nil && resp.StatusCode == http.StatusNotModified && cached != nil && cached.Data != nil {
		slog.Debug("upstream returned 304 Not Modified, reusing cached data",
			"url", c.URL)
		return cached.Data, resp, nil
	}

	return result, resp, err
}

// executeCallbackWithResponse performs the actual HTTP request and returns both result and response.
// conditionalHeaders are optional If-None-Match / If-Modified-Since headers for conditional requests.
func (c *Callback) executeCallbackWithResponse(ctx context.Context, obj any, conditionalHeaders map[string]string) (map[string]any, *http.Response, error) {
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
		return nil, nil, fmt.Errorf("failed to render URL template: %w", err)
	}

	// Build request body from config (body template, form_fields, or default JSON marshal)
	bodyReader, contentType, err := c.buildRequestBody(obj)
	if err != nil {
		return nil, nil, err
	}

	// Create request with appropriate method and body
	req, err := http.NewRequestWithContext(ctx, method, renderedURL, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if c.Headers != nil {
		req.Header = c.Headers.Clone()
	}

	// Set Content-Type from body builder
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Add outbound conditional headers for cache validation
	for k, v := range conditionalHeaders {
		req.Header.Set(k, v)
	}

	// Execute request using client's Do method (protected by circuit breaker)
	httpAwareCB := circuitbreaker.DefaultRegistry.GetOrCreate(
		"callback:"+c.URL, circuitbreaker.DefaultConfig,
	)
	if cbErr := httpAwareCB.Call(func() error {
		var doErr error
		resp, doErr = client.Do(ctx, req)
		return doErr
	}); cbErr != nil {
		slog.Error("failed to make request",
			"method", method,
			"url", c.URL,
			"error", cbErr)
		return nil, nil, cbErr
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified - return early so the caller can reuse cached data
	if resp.StatusCode == http.StatusNotModified {
		return nil, resp, nil
	}

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
				return nil, nil, fmt.Errorf("signature verification failed: %w", err)
			}
		}
	}

	if c.ExpectedStatusCodes != nil {
		if !slices.Contains(c.ExpectedStatusCodes, resp.StatusCode) {
			return nil, nil, fmt.Errorf("callback: expected status code %v, got %d", c.ExpectedStatusCodes, resp.StatusCode)
		}
	} else if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("callback: expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Read response body using pooled buffer with size limit
	buf := respBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= maxPoolBufferSize {
			buf.Reset()
			respBufPool.Put(buf)
		}
	}()
	maxSize := c.MaxResponseSize
	if maxSize <= 0 {
		maxSize = defaultMaxResponseSize
	}
	_, err = buf.ReadFrom(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		slog.Error("failed to read response body",
			"url", c.URL,
			"error", err)
		return nil, nil, err
	}
	if int64(buf.Len()) > maxSize {
		return nil, nil, fmt.Errorf("callback: response body exceeds max size of %d bytes", maxSize)
	}
	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())

	result := make(map[string]any)
	if len(data) > 0 {
		contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if strings.EqualFold(contentType, "application/json") {
			if err = json.Unmarshal(data, &result); err != nil {
				slog.Error("failed to decode response",
					"url", c.URL,
					"error", err)
				return nil, nil, err
			}

			if c.celExpr != nil {
				result, err = c.celExpr.ModifyJSON(result)
				if err != nil {
					slog.Error("failed to modify response with CEL",
						"url", c.URL,
						"error", err)
					return nil, nil, err
				}
				// CEL package now handles conversion to native types internally
			}
			if c.luaScript != nil {
				result, err = c.luaScript.ModifyJSON(result)
				if err != nil {
					slog.Error("failed to modify response with Lua",
						"url", c.URL,
						"error", err)
					return nil, nil, err
				}
				// Lua should already return native types
			}
		}
	}

	return result, resp, nil
}

// Helper functions

func flattenHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}

func objToMap(obj any) map[string]any {
	if m, ok := obj.(map[string]any); ok {
		return m
	}
	// Try to marshal/unmarshal
	data, err := json.Marshal(obj)
	if err != nil {
		return make(map[string]any)
	}
	var result map[string]any
	json.Unmarshal(data, &result)
	return result
}

