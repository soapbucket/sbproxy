// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

// ConditionalRequestResult represents the result of handling a conditional request
type ConditionalRequestResult struct {
	NotModified bool
	Data        map[string]any
}

// HandleConditionalRequest handles If-None-Match and If-Modified-Since conditional requests
func (hcc *HTTPCallbackCache) HandleConditionalRequest(ctx context.Context, cacheKey string, cached *HTTPCachedCallbackResponse, ifNoneMatch, ifModifiedSince string) (*ConditionalRequestResult, bool, error) {
	// Handle If-None-Match (ETag validation)
	if ifNoneMatch != "" && cached.ETag != "" {
		// Remove quotes from ETag if present
		etag := strings.Trim(cached.ETag, `"`)
		noneMatch := strings.Trim(ifNoneMatch, `"`)

		if etag == noneMatch {
			slog.Debug("conditional request: ETag matches, returning not modified",
				"cache_key", cacheKey,
				"etag", etag)

			hcc.metrics.RecordHit(0) // Conditional match - negligible latency
			return &ConditionalRequestResult{
				NotModified: true,
				Data:        nil,
			}, true, nil
		}
	}

	// Handle If-Modified-Since (Last-Modified validation)
	if ifModifiedSince != "" && !cached.LastModified.IsZero() {
		if modifiedSince, err := time.Parse(time.RFC1123, ifModifiedSince); err == nil {
			if !cached.LastModified.After(modifiedSince) {
				slog.Debug("conditional request: Last-Modified indicates not modified",
					"cache_key", cacheKey,
					"last_modified", cached.LastModified,
					"if_modified_since", modifiedSince)

				hcc.metrics.RecordHit(time.Since(time.Now()))
				return &ConditionalRequestResult{
					NotModified: true,
					Data:        nil,
				}, true, nil
			}
		}
	}

	// Not modified conditions not met, return cached data
	return &ConditionalRequestResult{
		NotModified: false,
		Data:        cached.Data,
	}, true, nil
}

// ExtractConditionalHeaders extracts conditional request headers from request context or headers
func ExtractConditionalHeaders(ctx context.Context, headers map[string]string) (ifNoneMatch, ifModifiedSince string) {
	// Try to extract from headers map first
	if headers != nil {
		if etag, ok := headers[httputil.HeaderIfNoneMatch]; ok {
			ifNoneMatch = etag
		}
		if modified, ok := headers[httputil.HeaderIfModifiedSince]; ok {
			ifModifiedSince = modified
		}
	}

	// Could also extract from context if request is stored there
	// For now, we'll rely on headers being passed explicitly

	return ifNoneMatch, ifModifiedSince
}



