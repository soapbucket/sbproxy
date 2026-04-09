// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"net/http/httputil"

	sbhttputil "github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

// Rewrite performs the rewrite operation on the Config.
func (c *Config) Rewrite() RewriteFn {
	return RewriteFn(func(pr *httputil.ProxyRequest) {
		slog.Debug("Rewrite", "origin_config_id", c.ID)

		if c.action.Rewrite() != nil {
			c.action.Rewrite()(pr)
		}

		// apply parent rules
		if c.Parent != nil && !c.DisableApplyParent {
			if fn := c.Parent.Rewrite(); fn != nil {
				fn(pr)
			}
		}

		r := pr.Out

		// Ensure the request context is preserved when applying modifiers
		// The context contains RequestData which is needed for template variable resolution
		// Always use the incoming request's context to ensure RequestData is available
		r = r.WithContext(pr.In.Context())
		pr.Out = r

		// modify request
		if err := c.RequestModifiers.Apply(r); err != nil {
			slog.Error("Error applying request modifiers", "origin_config_id", c.ID, "error", err)
			return
		}
	})
}

// Transport performs the transport operation on the Config.
func (c *Config) Transport() http.RoundTripper {
	// If we have a wrapped cookie jar transport, use it
	if c.cookieJarTransport != nil {
		return c.cookieJarTransport
	}
	return c.action.Transport()
}

// ModifyResponse performs the modify response operation on the Config.
func (c *Config) ModifyResponse() ModifyResponseFn {
	return ModifyResponseFn(func(resp *http.Response) error {
		slog.Debug("ModifyResponse", "origin_config_id", c.ID)

		// Remove Alt-Svc header from origin response to prevent propagation
		resp.Header.Del("Alt-Svc")

		// Check if this is an error status code
		if resp.StatusCode >= 400 && resp.StatusCode < 600 {
			if resp.StatusCode >= 500 {
				emitUpstream5xx(resp.Request.Context(), c, resp.Request, requestURLString(resp.Request), resp.StatusCode, 0)
			}
			// Check fallback origin for on_status trigger before error pages
			if c.FallbackOrigin != nil && c.FallbackOrigin.ShouldTriggerOnStatus(resp.StatusCode) &&
				resp.Request != nil && c.FallbackOrigin.MatchesRequest(resp.Request) {
				slog.Debug("fallback on_status triggered",
					"origin_id", c.ID,
					"status_code", resp.StatusCode,
					"fallback_hostname", c.FallbackOrigin.Hostname)
				if resp.Body != nil {
					resp.Body.Close()
				}
				return fmt.Errorf("fallback_on_status: upstream returned %d, triggering fallback to %s",
					resp.StatusCode, c.FallbackOrigin.Hostname)
			}

			// Try to replace with error page content
			if c.replaceResponseWithErrorPage(resp) {
				slog.Debug("replaced response with error page",
					"origin_id", c.ID,
					"status_code", resp.StatusCode)
				// Error page body has been replaced, continue with modifiers/transforms
			}
		}

		// apply transforms
		origin := c.ID
		if origin == "" {
			origin = "unknown"
		}

		for _, transform := range c.transforms {
			// Measure transform latency
			transformStartTime := time.Now()
			transformType := transform.GetType()
			if transformType == "" {
				transformType = "unknown"
			}

			if err := transform.Apply(resp); err != nil {
				// Record latency even on error
				transformDuration := time.Since(transformStartTime).Seconds()
				metric.TransformLatency(origin, transformType, transformDuration)

				slog.Error("Error applying transform", "origin_config_id", c.ID, "error", err)
				return err
			}

			// Record transform latency
			transformDuration := time.Since(transformStartTime).Seconds()
			metric.TransformLatency(origin, transformType, transformDuration)
		}

		if c.action.ModifyResponse() != nil {
			if err := c.action.ModifyResponse()(resp); err != nil {
				slog.Error("Error applying response modifiers", "origin_config_id", c.ID, "error", err)
				return err
			}
		}

		// apply parent rules
		if c.Parent != nil && !c.DisableApplyParent {
			if fn := c.Parent.ModifyResponse(); fn != nil {
				if err := fn(resp); err != nil {
					slog.Error("Error applying parent response modifiers", "origin_config_id", c.ID, "error", err)
					return err
				}
			}
		}

		// modify response
		if err := c.ResponseModifiers.Apply(resp); err != nil {
			slog.Error("Error applying response modifiers", "origin_config_id", c.ID, "error", err)
			return err
		}

		return nil
	})
}

// replaceResponseWithErrorPage replaces the response body with error page content
// Returns true if error page was found and body was replaced, false otherwise
func (c *Config) replaceResponseWithErrorPage(resp *http.Response) bool {
	// Check if error pages are configured
	if len(c.ErrorPages) == 0 {
		// Check parent config if applicable
		if c.Parent != nil && !c.DisableApplyParent {
			return c.Parent.replaceResponseWithErrorPage(resp)
		}
		return false
	}

	// Find matching error page
	errorPage, found := c.ErrorPages.FindErrorPage(resp.StatusCode)
	if !found {
		return false
	}

	slog.Debug("replacing response with error page",
		"origin_id", c.ID,
		"status_code", resp.StatusCode)

	// If callback is configured, fetch error page from callback
	if errorPage.Callback != nil {
		return c.replaceResponseWithErrorPageFromCallback(resp, errorPage)
	}

	// Set error page headers
	if errorPage.Headers != nil {
		for key, value := range errorPage.Headers {
			resp.Header.Set(key, value)
		}
	}

	// Determine content type
	contentType := errorPage.ContentType
	if contentType == "" {
		contentType = "text/html"
	}
	resp.Header.Set("Content-Type", contentType)

	// Update status code if specified in error page
	if errorPage.StatusCode > 0 {
		resp.StatusCode = errorPage.StatusCode
		resp.Status = fmt.Sprintf("%d %s", errorPage.StatusCode, http.StatusText(errorPage.StatusCode))
	}

	// Determine body content
	var body []byte
	var templateContent string
	var isTemplate bool

	if errorPage.BodyBase64 != "" {
		var decodeErr error
		body, decodeErr = base64.StdEncoding.DecodeString(errorPage.BodyBase64)
		if decodeErr != nil {
			slog.Error("failed to decode base64 error page body",
				"origin_id", c.ID,
				"error", decodeErr)
			return false
		}
		if errorPage.Template {
			templateContent = string(body)
			isTemplate = true
		}
	} else if errorPage.Body != "" {
		if errorPage.Template {
			templateContent = errorPage.Body
			isTemplate = true
		} else {
			body = []byte(errorPage.Body)
		}
	} else if len(errorPage.JSONBody) > 0 {
		if errorPage.Template {
			templateContent = string(errorPage.JSONBody)
			isTemplate = true
		} else {
			// Pretty print JSON if needed
			var jsonData interface{}
			if jsonErr := json.Unmarshal(errorPage.JSONBody, &jsonData); jsonErr == nil {
				body, _ = json.Marshal(jsonData)
				if contentType == "text/html" {
					contentType = "application/json"
					resp.Header.Set("Content-Type", contentType)
				}
			} else {
				body = errorPage.JSONBody
			}
		}
	} else {
		// No body specified, use default error message
		body = []byte(http.StatusText(resp.StatusCode))
	}

	// Render template if needed
	if isTemplate {
		// resp.Request should always be set by ReverseProxy, but check to be safe
		if resp.Request == nil {
			slog.Warn("cannot render error page template: request is nil",
				"origin_id", c.ID)
			body = []byte(http.StatusText(resp.StatusCode))
		} else {
			renderedBody, renderErr := c.renderErrorPageTemplate(templateContent, resp.Request, resp.StatusCode, nil)
			if renderErr != nil {
				slog.Error("failed to render error page template",
					"origin_id", c.ID,
					"error", renderErr)
				// Fall back to default error message
				body = []byte(http.StatusText(resp.StatusCode))
			} else {
				body = []byte(renderedBody)
			}
		}
	}

	// Close existing response body to avoid leaks
	if resp.Body != nil {
		resp.Body.Close()
	}

	// Replace response body
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(body)), 10))

	return true
}

// replaceResponseWithErrorPageFromCallback fetches error page from callback and replaces response
func (c *Config) replaceResponseWithErrorPageFromCallback(resp *http.Response, errorPage *ErrorPage) bool {
	ctx := resp.Request.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Build request data for callback
	requestData := reqctx.GetRequestData(ctx)
	errorMsg := ""
	callbackData := map[string]any{
		"status_code": resp.StatusCode,
		"error":       errorMsg,
		"request": map[string]any{
			"url":    resp.Request.URL.String(),
			"method": resp.Request.Method,
		},
	}

	if requestData != nil {
		callbackData["context"] = requestData.Data
	}

	// For non-template callback pages, try to get from cache first
	if !errorPage.Template && c.l3Cache != nil && errorPage.Callback != nil && errorPage.Callback.CacheDuration.Duration > 0 {
		cacheKey := c.generateCallbackErrorPageCacheKey(errorPage, resp.StatusCode, callbackData)
		cachedReader, cacheErr := c.l3Cache.Get(ctx, errorPageCacheType, cacheKey)
		if cacheErr == nil && cachedReader != nil {
			// Cache hit - read and use cached content
			cachedBody, readErr := io.ReadAll(cachedReader)
			if readErr == nil {
				slog.Debug("serving callback error page from L3 cache in ModifyResponse",
					"origin_id", c.ID,
					"status_code", resp.StatusCode,
					"cache_key", cacheKey)

				// Set headers from error page config
				if errorPage.Headers != nil {
					for key, value := range errorPage.Headers {
						resp.Header.Set(key, value)
					}
				}

				// Determine content type
				contentType := errorPage.ContentType
				if contentType == "" {
					contentType = "text/html"
				}
				resp.Header.Set("Content-Type", contentType)

				// Determine status code - preserve original unless errorPage.StatusCode is set
				responseStatusCode := resp.StatusCode
				if errorPage.StatusCode > 0 {
					responseStatusCode = errorPage.StatusCode
				}
				resp.StatusCode = responseStatusCode
				resp.Status = fmt.Sprintf("%d %s", responseStatusCode, http.StatusText(responseStatusCode))

				// Close existing response body
				if resp.Body != nil {
					resp.Body.Close()
				}

				// Replace response body
				resp.Body = io.NopCloser(bytes.NewReader(cachedBody))
				resp.ContentLength = int64(len(cachedBody))
				resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(cachedBody)), 10))

				return true
			}
			slog.Warn("failed to read cached callback error page, falling back to fetch",
				"origin_id", c.ID,
				"error", readErr)
		}
	}

	// Fetch error page content
	fetchResp, fetchErr := errorPage.Callback.Fetch(ctx, callbackData)
	if fetchErr != nil {
		slog.Error("failed to fetch error page from callback in ModifyResponse",
			"origin_id", c.ID,
			"status_code", resp.StatusCode,
			"error", fetchErr)
		return false
	}

	// Set headers from callback response (but skip Content-Type if we need to override it)
	skipContentType := errorPage.DecodeBase64 && errorPage.ContentType != ""
	for key, values := range fetchResp.Headers {
		if skipContentType && strings.ToLower(key) == "content-type" {
			continue
		}
		for _, value := range values {
			resp.Header.Add(key, value)
		}
	}

	// Set error page headers
	if errorPage.Headers != nil {
		for key, value := range errorPage.Headers {
			resp.Header.Set(key, value)
		}
	}

	// Determine content type
	contentType := fetchResp.ContentType
	if contentType == "" {
		if errorPage.ContentType != "" {
			contentType = errorPage.ContentType
		} else {
			contentType = "text/html"
		}
	}
	if errorPage.DecodeBase64 && errorPage.ContentType != "" {
		contentType = errorPage.ContentType
	}
	if resp.Header.Get("Content-Type") == "" || (errorPage.DecodeBase64 && errorPage.ContentType != "") {
		resp.Header.Set("Content-Type", contentType)
	}

	// Determine status code - preserve original unless errorPage.StatusCode is set
	responseStatusCode := resp.StatusCode
	if errorPage.StatusCode > 0 {
		responseStatusCode = errorPage.StatusCode
	}
	resp.StatusCode = responseStatusCode
	resp.Status = fmt.Sprintf("%d %s", responseStatusCode, http.StatusText(responseStatusCode))

	// Decode base64 if needed
	body := fetchResp.Body
	if errorPage.DecodeBase64 {
		decoded, decodeErr := base64.StdEncoding.DecodeString(string(fetchResp.Body))
		if decodeErr != nil {
			slog.Error("failed to decode base64 error page body from callback",
				"origin_id", c.ID,
				"error", decodeErr)
		} else {
			body = decoded
		}
	}

	// Render template if needed
	if errorPage.Template {
		if resp.Request == nil {
			slog.Warn("cannot render error page template: request is nil",
				"origin_id", c.ID)
			body = []byte(http.StatusText(resp.StatusCode))
		} else {
			renderedBody, renderErr := c.renderErrorPageTemplate(string(body), resp.Request, resp.StatusCode, nil)
			if renderErr != nil {
				slog.Error("failed to render error page template from callback",
					"origin_id", c.ID,
					"error", renderErr)
				body = []byte(http.StatusText(resp.StatusCode))
			} else {
				body = []byte(renderedBody)
			}
		}
	}

	// Cache callback-based error pages in L3 cache if callback has CacheDuration set
	if !errorPage.Template && c.l3Cache != nil && errorPage.Callback != nil && errorPage.Callback.CacheDuration.Duration > 0 {
		cacheKey := c.generateCallbackErrorPageCacheKey(errorPage, resp.StatusCode, callbackData)
		cacheDuration := errorPage.Callback.CacheDuration.Duration
		if err := c.l3Cache.PutWithExpires(ctx, errorPageCacheType, cacheKey, bytes.NewReader(body), cacheDuration); err != nil {
			slog.Warn("failed to cache callback error page in L3 cache (non-fatal)",
				"origin_id", c.ID,
				"status_code", resp.StatusCode,
				"error", err)
		} else {
			slog.Debug("cached callback error page in L3 cache",
				"origin_id", c.ID,
				"status_code", resp.StatusCode,
				"cache_key", cacheKey,
				"duration", cacheDuration)
		}
	}

	// Close existing response body
	if resp.Body != nil {
		resp.Body.Close()
	}

	// Replace response body
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(body)), 10))

	return true
}

// parseSizeToInt64 parses a size string (e.g., "10MB", "100KB") to bytes
// Returns the parsed size and an error if the format is invalid
func parseSizeToInt64WithError(sizeStr string) (int64, error) {
	if sizeStr == "" {
		return 0, fmt.Errorf("empty size string")
	}

	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	// Extract number and unit
	var numStr string
	var unit string
	for i, r := range sizeStr {
		if r >= '0' && r <= '9' {
			numStr += string(r)
		} else {
			unit = sizeStr[i:]
			break
		}
	}

	if numStr == "" {
		return 0, fmt.Errorf("no number found in size string: %q", sizeStr)
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in size string %q: %w", sizeStr, err)
	}

	var multiplier int64
	switch unit {
	case "KB", "K":
		multiplier = 1024
	case "MB", "M":
		multiplier = 1024 * 1024
	case "GB", "G":
		multiplier = 1024 * 1024 * 1024
	case "TB", "T":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "B", "":
		multiplier = 1
	default:
		return 0, fmt.Errorf("invalid unit %q in size string %q (valid units: B, KB/K, MB/M, GB/G, TB/T)", unit, sizeStr)
	}

	return num * multiplier, nil
}

// parseSizeToInt64 parses a size string (e.g., "10MB", "100KB") to bytes
// Returns defaultSize if parsing fails (for backward compatibility)
func parseSizeToInt64(sizeStr string, defaultSize int64) int64 {
	if sizeStr == "" {
		return defaultSize
	}

	size, err := parseSizeToInt64WithError(sizeStr)
	if err != nil {
		return defaultSize
	}

	return size
}

// IsProxy reports whether the Config is proxy.
func (c *Config) IsProxy() bool {
	if c.action == nil {
		slog.Warn("Config.IsProxy() returning false: action is nil",
			"config_id", c.ID,
			"hostname", c.Hostname)
		return false
	}
	result := c.action.IsProxy()
	if !result {
		slog.Warn("Config.IsProxy() returning false",
			"config_id", c.ID,
			"hostname", c.Hostname,
			"action_type", c.action.GetType())
		// Add more details for load balancer
		if lbConfig, ok := c.action.(*LoadBalancerTypedConfig); ok {
			slog.Warn("LoadBalancerTypedConfig details",
				"tr_is_nil", lbConfig.tr == nil,
				"compiled_targets_count", len(lbConfig.compiledTargets))
		}
	}
	return result
}

// Handler performs the handler operation on the Config.
func (c *Config) Handler() http.Handler {
	var handler http.Handler
	if c.action != nil {
		handler = c.action.Handler()
	}

	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slog.Error("Handler", "origin_config_id", c.ID)
			http.NotFound(w, r)
		})
	}

	return handler
}

// ActionConfig performs the action config operation on the Config.
func (c *Config) ActionConfig() ActionConfig {
	return c.action
}

// ErrorHandler performs the error handler operation on the Config.
func (c *Config) ErrorHandler() ErrorHandlerFn {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("ErrorHandler", "origin_config_id", c.ID, "error", err)

		// Determine status code from error or default to 500
		statusCode := http.StatusInternalServerError

		// All targets unhealthy returns 503 Service Unavailable
		if errors.Is(err, ErrAllTargetsUnhealthy) {
			statusCode = http.StatusServiceUnavailable
		}

		// Try to extract status code from context if available
		if status, ok := r.Context().Value(reqctx.ContextKeyErrorStatusCode).(int); ok && status > 0 {
			statusCode = status
		}

		// Record error metric
		origin := c.ID
		if origin == "" {
			origin = "unknown"
		}
		errorType := "unknown"
		errorCategory := "internal_error"
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
				errorType = "timeout"
				errorCategory = "transport_error"
				emitUpstreamTimeout(r.Context(), c, r, requestURLString(r), 0)
			} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "refused") {
				errorType = "connection_error"
				errorCategory = "transport_error"
			} else if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "TLS") {
				errorType = "tls_error"
				errorCategory = "transport_error"
			} else if statusCode >= 400 && statusCode < 500 {
				errorCategory = "client_error"
				errorType = fmt.Sprintf("http_%d", statusCode)
			} else if statusCode >= 500 {
				errorCategory = "server_error"
				errorType = fmt.Sprintf("http_%d", statusCode)
			}
		}
		metric.ErrorTotal(origin, errorType, errorCategory)

		// Check fallback origin before serving error page
		isFallbackOnStatus := err != nil && strings.Contains(err.Error(), "fallback_on_status")
		if c.FallbackOrigin != nil && c.FallbackLoader != nil &&
			(c.FallbackOrigin.ShouldTriggerOnError(err) || isFallbackOnStatus) &&
			c.FallbackOrigin.MatchesRequest(r) {

			fallbackStartTime := time.Now()
			trigger := errorType
			if isFallbackOnStatus {
				trigger = "status"
			}
			metric.FallbackTriggered(origin, c.FallbackOrigin.Hostname, trigger)

			fallbackCfg, loadErr := c.FallbackLoader(r.Context(), r, c.FallbackOrigin)
			if loadErr != nil {
				slog.Error("failed to load fallback config",
					"origin_id", c.ID,
					"fallback_hostname", c.FallbackOrigin.Hostname,
					"error", loadErr)
				metric.FallbackFailure(origin, c.FallbackOrigin.Hostname, "load_error")
			} else {
				// Append fallback to X-Sb-Origin debug chain
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil {
					existing := requestData.DebugHeaders[sbhttputil.HeaderXSbOrigin]
					if existing != "" {
						requestData.AddDebugHeader(sbhttputil.HeaderXSbOrigin,
							existing+", "+fallbackCfg.Hostname+"/"+fallbackCfg.Version)
					}
					if c.FallbackOrigin.AddDebugHeader {
						requestData.AddDebugHeader("X-Fallback-Origin", fallbackCfg.Hostname)
					}
				}

				// Re-execute request against fallback config
				fallbackCfg.ServeHTTP(w, r)

				duration := time.Since(fallbackStartTime).Seconds()
				metric.FallbackLatency(origin, c.FallbackOrigin.Hostname, duration)
				metric.FallbackSuccess(origin, c.FallbackOrigin.Hostname)
				return
			}
		}

		// Try to serve custom error page first
		if c.ServeErrorPage(w, r, statusCode, err) {
			return
		}

		// Fall back to action's error handler or default
		var errHandler ErrorHandlerFn
		if c.action != nil {
			errHandler = c.action.ErrorHandler()
		}

		if errHandler == nil {
			errHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				slog.Error("ErrorHandler", "origin_config_id", c.ID, "error", err)
				http.Error(w, http.StatusText(statusCode), statusCode)
			}
		}

		errHandler(w, r, err)
	}
}

// Authenticate performs the authenticate operation on the Config.
func (c *Config) Authenticate(next http.Handler) http.Handler {
	if c.auth != nil {
		return c.auth.Authenticate(next)
	}

	if c.Parent != nil && !c.DisableApplyParent {
		next = c.Parent.Authenticate(next)
	}

	return next
}

// GetCookieJar returns the cookie jar for the Config.
func (c *Config) GetCookieJar(req *http.Request) http.CookieJar {
	if c.CookieJarFn != nil {
		return c.CookieJarFn(req)
	}
	return nil
}

// wrapActionTransportWithCookieJar wraps the action's transport with cookie jar support
func (c *Config) wrapActionTransportWithCookieJar() {
	if c.action == nil || c.CookieJarFn == nil {
		return
	}

	// Get the current transport function
	baseTrFn := c.action.Transport()
	if baseTrFn == nil {
		return
	}

	// Wrap the base transport with cookie jar transport
	// TransportFn implements http.RoundTripper, so we can wrap it
	wrappedTr := transport.NewCookieJarTransport(baseTrFn, c.CookieJarFn)

	// Convert wrapped transport back to TransportFn
	wrappedTrFn := TransportFn(wrappedTr.RoundTrip)

	// Try to set the transport on actions that support it
	if baseAction, ok := c.action.(interface{ setTransport(http.RoundTripper) }); ok {
		baseAction.setTransport(wrappedTrFn)
	} else {
		// For actions that don't support direct transport setting,
		// we need to override Transport() at the Config level
		// Store the wrapped transport for later use
		c.cookieJarTransport = wrappedTrFn
		slog.Debug("stored wrapped transport at config level",
			"action_type", c.action.GetType(),
			"config_id", c.ID)
	}
}
