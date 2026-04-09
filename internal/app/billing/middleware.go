// Package billing tracks and reports usage metrics for metered billing.
package billing

import (
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// responseWriter wraps http.ResponseWriter to capture status code and bytes written
type billingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

// WriteHeader performs the write header operation on the billingResponseWriter.
func (rw *billingResponseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Write performs the write operation on the billingResponseWriter.
func (rw *billingResponseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// BillingMiddleware creates middleware for billing/metering
func BillingMiddleware(meter *Meter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start timing the request
			startTime := time.Now()

			// Wrap response writer to capture status and bytes
			brw := &billingResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				bytesWritten:   0,
			}

			// Call the next handler
			next.ServeHTTP(brw, r)

			// Record the billing metric
			duration := time.Since(startTime)
			recordBillingMetric(meter, r, brw, duration)
		})
	}
}

// recordBillingMetric records a single request's usage for billing
func recordBillingMetric(meter *Meter, r *http.Request, rw *billingResponseWriter, duration time.Duration) {
	// Extract context from request
	workspaceID := ""
	originID := ""
	originHostname := ""
	providerName := ""

	// Prefer typed request data contract.
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
		params := reqctx.ConfigParams(requestData.Config)
		workspaceID = params.GetWorkspaceID()
		originID = params.GetConfigID()
		originHostname = params.GetConfigHostname()
	}

	if val := r.Context().Value(reqctx.ContextKeyProviderName); val != nil {
		if name, ok := val.(string); ok {
			providerName = name
		}
	}

	// Skip recording if no workspace or origin (misconfigured request)
	if workspaceID == "" || originID == "" {
		return
	}

	// Determine status group
	status := formatStatus(rw.statusCode)

	// Get request size from Content-Length
	bytesIn := int64(0)
	if r.ContentLength > 0 {
		bytesIn = r.ContentLength
	}

	// Get response size (captured during response writing)
	bytesOut := rw.bytesWritten

	// For billing purposes:
	// - Only count backend bytes for successful responses (no error cost)
	// - Cache hits don't incur backend costs (but are counted separately)
	bytesBackend := bytesOut
	bytesFromCache := int64(0)

	// Check if response came from cache (indicated by X-Cache header or context)
	if val := r.Context().Value(reqctx.ContextKeyCacheHit); val != nil {
		if hit, ok := val.(bool); ok && hit {
			bytesFromCache = bytesOut
			bytesBackend = 0 // Cache hits don't cost backend bandwidth
		}
	}

	// Record metric with meter
	metric := &UsageMetric{
		WorkspaceID:    workspaceID,
		OriginID:       originID,
		OriginHostname: originHostname,
		ProviderName:   providerName,
		Status:         status,
		RequestCount:   1,
		BytesIn:        bytesIn,
		BytesOut:       bytesOut,
		BytesBackend:   bytesBackend,
		BytesFromCache: bytesFromCache,
		TokensUsed:     0, // Will be set separately for AI requests
		ErrorCount:     0,
		Latency:        duration.Seconds(),
		Period:         time.Now(),
	}

	// Count errors
	if rw.statusCode >= 400 {
		metric.ErrorCount = 1
	}

	// Record in the meter (thread-safe aggregation)
	meter.Record(metric)
}

// formatStatus returns the status group for billing purposes
func formatStatus(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "unknown"
	}
}

// RecordAITokens records AI token usage for a request
// This is called separately by AI handling middleware
func RecordAITokens(meter *Meter, workspaceID, originID, providerName string, tokens int64) {
	if meter == nil || workspaceID == "" || originID == "" || tokens == 0 {
		return
	}

	metric := &UsageMetric{
		WorkspaceID:  workspaceID,
		OriginID:     originID,
		ProviderName: providerName,
		TokensUsed:   tokens,
		Period:       time.Now(),
	}

	meter.Record(metric)
}
