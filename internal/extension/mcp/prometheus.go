// prometheus.go registers Prometheus metrics for MCP tool calls and operations.
package mcp

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// =============================================================================
// MCP Prometheus Metrics
// =============================================================================

var (
	// Tool Execution Metrics
	mcpToolCallsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_tool_calls_total",
		Help: "Total MCP tool calls",
	}, []string{"tool", "status"})

	mcpToolCallDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_mcp_tool_call_duration_seconds",
		Help:    "Duration of MCP tool calls",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"tool"})

	mcpToolCallErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_tool_call_errors_total",
		Help: "Total MCP tool call errors by type",
	}, []string{"tool", "error_type"})

	mcpToolCacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_tool_cache_hits_total",
		Help: "Total MCP tool result cache hits",
	}, []string{"tool"})

	mcpToolCacheMissesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_tool_cache_misses_total",
		Help: "Total MCP tool result cache misses",
	}, []string{"tool"})

	// Gateway Metrics
	mcpGatewayUpstreamRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_gateway_upstream_requests_total",
		Help: "Total requests forwarded to upstream MCP servers",
	}, []string{"upstream", "status"})

	mcpGatewayUpstreamLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_mcp_gateway_upstream_latency_seconds",
		Help:    "Upstream MCP server response time",
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"upstream"})

	mcpGatewayDiscoveryErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_gateway_discovery_errors_total",
		Help: "Federation tool discovery failures",
	}, []string{"upstream"})

	// Protocol Metrics
	mcpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_requests_total",
		Help: "Total MCP JSON-RPC requests by method",
	}, []string{"method"})

	mcpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_mcp_request_duration_seconds",
		Help:    "Full MCP request-response latency",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5},
	}, []string{"method"})

	mcpProtocolErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_protocol_errors_total",
		Help: "Total MCP protocol errors by JSON-RPC code",
	}, []string{"code"})

	// Access Control Metrics
	mcpAccessDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_access_denied_total",
		Help: "Total MCP access control rejections",
	}, []string{"tool"})

	// Pagination Metrics
	mcpPaginationPagesFetched = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_mcp_pagination_pages_fetched",
		Help:    "Number of pages fetched per paginated tool call",
		Buckets: []float64{1, 2, 3, 5, 10, 20},
	}, []string{"tool"})

	// Prompt Metrics
	mcpPromptRendersTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_prompt_renders_total",
		Help: "Total prompt template renders",
	}, []string{"prompt"})

	// Completion Metrics
	mcpCompletionRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_mcp_completion_requests_total",
		Help: "Total completion/complete requests",
	}, []string{"ref_type"})
)

// =============================================================================
// Recording Functions
// =============================================================================

// RecordToolCall records a tool call metric.
func RecordToolCall(toolName, status string, durationSeconds float64) {
	mcpToolCallsTotal.WithLabelValues(toolName, status).Inc()
	mcpToolCallDuration.WithLabelValues(toolName).Observe(durationSeconds)
}

// RecordToolError records a tool call error by type.
func RecordToolError(toolName, errorType string) {
	mcpToolCallErrorsTotal.WithLabelValues(toolName, errorType).Inc()
}

// RecordToolCacheHit records a tool result cache hit.
func RecordToolCacheHit(toolName string) {
	mcpToolCacheHitsTotal.WithLabelValues(toolName).Inc()
}

// RecordToolCacheMiss records a tool result cache miss.
func RecordToolCacheMiss(toolName string) {
	mcpToolCacheMissesTotal.WithLabelValues(toolName).Inc()
}

// RecordGatewayUpstream records a gateway upstream request.
func RecordGatewayUpstream(upstream, status string, durationSeconds float64) {
	mcpGatewayUpstreamRequestsTotal.WithLabelValues(upstream, status).Inc()
	mcpGatewayUpstreamLatency.WithLabelValues(upstream).Observe(durationSeconds)
}

// RecordGatewayDiscoveryError records a federation discovery error.
func RecordGatewayDiscoveryError(upstream string) {
	mcpGatewayDiscoveryErrorsTotal.WithLabelValues(upstream).Inc()
}

// RecordRequest records an MCP JSON-RPC request.
func RecordRequest(method string, durationSeconds float64) {
	mcpRequestsTotal.WithLabelValues(method).Inc()
	mcpRequestDuration.WithLabelValues(method).Observe(durationSeconds)
}

// RecordProtocolError records a JSON-RPC protocol error.
func RecordProtocolError(code string) {
	mcpProtocolErrorsTotal.WithLabelValues(code).Inc()
}

// RecordAccessDenied records an access control rejection.
func RecordAccessDenied(toolName string) {
	mcpAccessDeniedTotal.WithLabelValues(toolName).Inc()
}

// RecordPaginationPages records pages fetched in a paginated call.
func RecordPaginationPages(toolName string, pages float64) {
	mcpPaginationPagesFetched.WithLabelValues(toolName).Observe(pages)
}

// RecordPromptRender records a prompt template render.
func RecordPromptRender(promptName string) {
	mcpPromptRendersTotal.WithLabelValues(promptName).Inc()
}

// RecordCompletionRequest records a completion request.
func RecordCompletionRequest(refType string) {
	mcpCompletionRequestsTotal.WithLabelValues(refType).Inc()
}
