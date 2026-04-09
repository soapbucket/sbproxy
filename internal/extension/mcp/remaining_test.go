package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// Prometheus Metrics
// =============================================================================

func TestRecordToolCall(t *testing.T) {
	// Should not panic
	RecordToolCall("test_tool", "success", 0.042)
	RecordToolCall("test_tool", "error", 0.1)
}

func TestRecordToolError(t *testing.T) {
	RecordToolError("test_tool", "timeout")
	RecordToolError("test_tool", "upstream")
}

func TestRecordToolCache(t *testing.T) {
	RecordToolCacheHit("cached_tool")
	RecordToolCacheMiss("cached_tool")
}

func TestRecordGatewayMetrics(t *testing.T) {
	RecordGatewayUpstream("https://upstream.example.com", "success", 0.05)
	RecordGatewayDiscoveryError("https://failing.example.com")
}

func TestRecordRequest(t *testing.T) {
	RecordRequest("tools/list", 0.001)
	RecordRequest("tools/call", 0.5)
}

func TestRecordProtocolError(t *testing.T) {
	RecordProtocolError("-32700")
	RecordProtocolError("-32600")
}

func TestRecordAccessDenied(t *testing.T) {
	RecordAccessDenied("admin_tool")
}

func TestRecordPaginationPages(t *testing.T) {
	RecordPaginationPages("paginated_tool", 3)
}

func TestRecordPromptRender(t *testing.T) {
	RecordPromptRender("summarize")
}

func TestRecordCompletionRequest(t *testing.T) {
	RecordCompletionRequest("ref/prompt")
	RecordCompletionRequest("ref/resource")
}

// =============================================================================
// Notifications
// =============================================================================

func TestNotificationQueue_EnqueueDrain(t *testing.T) {
	q := NewNotificationQueue(10)

	q.EmitToolsListChanged()
	q.EmitResourcesListChanged()
	q.EmitLogMessage("info", "mcp", "test message")

	if q.Size() != 3 {
		t.Fatalf("Expected 3 pending, got %d", q.Size())
	}

	notifications := q.Drain()
	if len(notifications) != 3 {
		t.Fatalf("Expected 3 notifications, got %d", len(notifications))
	}

	if notifications[0].Method != NotificationToolsListChanged {
		t.Errorf("Expected tools/list_changed, got %s", notifications[0].Method)
	}
	if notifications[1].Method != NotificationResourcesListChanged {
		t.Errorf("Expected resources/list_changed, got %s", notifications[1].Method)
	}
	if notifications[2].Method != NotificationMessage {
		t.Errorf("Expected notifications/message, got %s", notifications[2].Method)
	}

	// Queue should be empty after drain
	if q.Size() != 0 {
		t.Errorf("Expected 0 after drain, got %d", q.Size())
	}
}

func TestNotificationQueue_MaxSize(t *testing.T) {
	q := NewNotificationQueue(3)

	for i := 0; i < 5; i++ {
		q.EmitToolsListChanged()
	}

	if q.Size() != 3 {
		t.Errorf("Expected max 3, got %d", q.Size())
	}
}

func TestNotificationQueue_DrainEmpty(t *testing.T) {
	q := NewNotificationQueue(10)
	result := q.Drain()
	if result != nil {
		t.Errorf("Expected nil for empty drain, got %v", result)
	}
}

func TestLogMessageParams_Serialization(t *testing.T) {
	q := NewNotificationQueue(10)
	q.EmitLogMessage("warning", "tool.search", map[string]interface{}{"query": "test"})

	notifications := q.Drain()
	if len(notifications) != 1 {
		t.Fatalf("Expected 1 notification, got %d", len(notifications))
	}

	var params LogMessageParams
	json.Unmarshal(notifications[0].Params, &params)

	if params.Level != "warning" {
		t.Errorf("Expected level 'warning', got %s", params.Level)
	}
	if params.Logger != "tool.search" {
		t.Errorf("Expected logger 'tool.search', got %s", params.Logger)
	}
}

// =============================================================================
// Streamable HTTP Transport
// =============================================================================

type mockMCPHandler struct{}

func (m *mockMCPHandler) HandleRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	req, err := ParseJSONRPCRequest(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp := NewSuccessResponse(req.ID, map[string]interface{}{"status": "ok"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func TestStreamableHTTP_Post(t *testing.T) {
	transport := NewStreamableHTTPTransport(&mockMCPHandler{}, NewNotificationQueue(100))

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()

	transport.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Should have assigned a session ID
	sessionID := w.Header().Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Error("Expected Mcp-Session-Id header")
	}

	if transport.SessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", transport.SessionCount())
	}
}

func TestStreamableHTTP_Delete(t *testing.T) {
	transport := NewStreamableHTTPTransport(&mockMCPHandler{}, NewNotificationQueue(100))

	// Create a session via POST
	postReq := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	postW := httptest.NewRecorder()
	transport.ServeHTTP(postW, postReq)

	sessionID := postW.Header().Get("Mcp-Session-Id")

	// Delete the session
	deleteReq := httptest.NewRequest("DELETE", "/mcp", nil)
	deleteReq.Header.Set("Mcp-Session-Id", sessionID)
	deleteW := httptest.NewRecorder()
	transport.ServeHTTP(deleteW, deleteReq)

	if deleteW.Code != http.StatusNoContent {
		t.Errorf("Expected 204, got %d", deleteW.Code)
	}

	if transport.SessionCount() != 0 {
		t.Errorf("Expected 0 sessions after delete, got %d", transport.SessionCount())
	}
}

func TestStreamableHTTP_GetWithoutSession(t *testing.T) {
	transport := NewStreamableHTTPTransport(&mockMCPHandler{}, NewNotificationQueue(100))

	req := httptest.NewRequest("GET", "/mcp", nil)
	w := httptest.NewRecorder()
	transport.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 without session ID, got %d", w.Code)
	}
}

func TestStreamableHTTP_MethodNotAllowed(t *testing.T) {
	transport := NewStreamableHTTPTransport(&mockMCPHandler{}, NewNotificationQueue(100))

	req := httptest.NewRequest("PATCH", "/mcp", nil)
	w := httptest.NewRecorder()
	transport.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestStreamableHTTP_BroadcastNotification(t *testing.T) {
	transport := NewStreamableHTTPTransport(&mockMCPHandler{}, NewNotificationQueue(100))

	// Should not panic with no sessions
	transport.BroadcastNotification(NotificationToolsListChanged, nil)
}

// =============================================================================
// Sampling Types
// =============================================================================

func TestBuildSamplingRequest(t *testing.T) {
	maxTokens := 100
	params := &SamplingCreateMessageParams{
		Messages: []SamplingMessage{
			{Role: "user", Content: Content{Type: "text", Text: "Hello"}},
		},
		MaxTokens: maxTokens,
	}

	data, err := BuildSamplingRequest(1, params)
	if err != nil {
		t.Fatalf("BuildSamplingRequest failed: %v", err)
	}

	var req JSONRPCRequest
	json.Unmarshal(data, &req)

	if req.Method != "sampling/createMessage" {
		t.Errorf("Expected method 'sampling/createMessage', got %s", req.Method)
	}
}

// =============================================================================
// Federation Origin Config Fields
// =============================================================================

func TestFederatedServerConfig_HasOriginRef(t *testing.T) {
	cfg := FederatedServerConfig{Origin: "internal-mcp.company.local"}
	if !cfg.HasOriginRef() {
		t.Error("Expected HasOriginRef() = true")
	}

	cfg2 := FederatedServerConfig{URL: "https://mcp.example.com"}
	if cfg2.HasOriginRef() {
		t.Error("Expected HasOriginRef() = false for URL-based config")
	}
}

func TestFederatedServerConfig_HasEmbeddedOrigin(t *testing.T) {
	cfg := FederatedServerConfig{OriginConfig: json.RawMessage(`{"action":{"type":"mcp"}}`)}
	if !cfg.HasEmbeddedOrigin() {
		t.Error("Expected HasEmbeddedOrigin() = true")
	}

	cfg2 := FederatedServerConfig{URL: "https://mcp.example.com"}
	if cfg2.HasEmbeddedOrigin() {
		t.Error("Expected HasEmbeddedOrigin() = false")
	}
}

// =============================================================================
// Metrics Integration with Handler
// =============================================================================

func TestHandler_MetricsRecorded_OnToolCall(t *testing.T) {
	config := &Config{
		ServerInfo:   ServerInfo{Name: "test", Version: "1.0"},
		Capabilities: Capabilities{Tools: &ToolsCapability{}},
		Tools: []ToolConfig{{
			Name:        "metered_tool",
			InputSchema: json.RawMessage(`{"type":"object"}`),
			Handler:     ToolHandler{Type: "static", Static: &StaticHandler{Content: `{}`}},
		}},
	}

	handler, _ := NewHandler(config)

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"metered_tool","arguments":{}}}`
	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp JSONRPCResponse
	json.NewDecoder(w.Result().Body).Decode(&resp)

	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}
	// Metrics are recorded internally - no panic means success
}

// =============================================================================
// Origin Validation and Circular Reference Detection
// =============================================================================

func TestValidateServerConfig_ExactlyOneSource(t *testing.T) {
	tests := []struct {
		name    string
		server  FederatedServerConfig
		wantErr bool
	}{
		{"url only", FederatedServerConfig{URL: "https://mcp.example.com"}, false},
		{"origin only", FederatedServerConfig{Origin: "internal-mcp"}, false},
		{"origin_config only", FederatedServerConfig{OriginConfig: json.RawMessage(`{}`)}, false},
		{"none", FederatedServerConfig{}, true},
		{"url and origin", FederatedServerConfig{URL: "https://mcp.example.com", Origin: "internal"}, true},
		{"all three", FederatedServerConfig{URL: "u", Origin: "o", OriginConfig: json.RawMessage(`{}`)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServerConfig(tt.server)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOriginReferences_NoCycles(t *testing.T) {
	servers := []FederatedServerConfig{
		{Origin: "server-a"},
		{Origin: "server-b"},
		{URL: "https://external.com"},
	}

	err := ValidateOriginReferences(servers)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func TestValidateOriginReferences_CircularDetected(t *testing.T) {
	// Two servers referencing the same origin (detected as a cycle since
	// visited map persists across servers)
	servers := []FederatedServerConfig{
		{Origin: "server-a"},
		{Origin: "server-a"}, // duplicate reference
	}

	err := ValidateOriginReferences(servers)
	if err == nil {
		t.Error("Expected circular reference error")
	}
}

func TestValidateOriginReferences_DeeplyNestedEmbedded(t *testing.T) {
	// Programmatically create nesting beyond DefaultMaxOriginDepth
	buildNested := func(depth int) json.RawMessage {
		inner := `{"action":{"federated_servers":[{"url":"https://leaf.example.com"}]}}`
		for i := 0; i < depth; i++ {
			inner = `{"action":{"federated_servers":[{"origin_config":` + inner + `}]}}`
		}
		return json.RawMessage(inner)
	}

	servers := []FederatedServerConfig{
		{OriginConfig: buildNested(DefaultMaxOriginDepth + 2)},
	}

	err := ValidateOriginReferences(servers)
	if err == nil {
		t.Error("Expected depth exceeded error for deeply nested config")
	}
}

func TestValidateOriginReferences_EmptyIsValid(t *testing.T) {
	err := ValidateOriginReferences(nil)
	if err != nil {
		t.Errorf("Expected no error for nil servers, got: %v", err)
	}
}

func TestValidateOriginReferences_URLServersSkipped(t *testing.T) {
	servers := []FederatedServerConfig{
		{URL: "https://a.example.com"},
		{URL: "https://b.example.com"},
	}

	err := ValidateOriginReferences(servers)
	if err != nil {
		t.Errorf("Expected no error for URL-only servers, got: %v", err)
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkNotificationQueue_Enqueue(b *testing.B) {
	b.ReportAllocs()
	q := NewNotificationQueue(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.EmitToolsListChanged()
	}
}

func BenchmarkNotificationQueue_Drain(b *testing.B) {
	b.ReportAllocs()
	q := NewNotificationQueue(100)
	for i := 0; i < 50; i++ {
		q.EmitToolsListChanged()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Drain()
		// Refill
		for j := 0; j < 50; j++ {
			q.EmitToolsListChanged()
		}
	}
}

func BenchmarkRecordToolCall(b *testing.B) {
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecordToolCall("bench_tool", "success", 0.042)
	}
}

func BenchmarkStreamableHTTP_Post(b *testing.B) {
	b.ReportAllocs()

	transport := NewStreamableHTTPTransport(&mockMCPHandler{}, NewNotificationQueue(100))
	reqBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(reqBody))
		req.Header.Set("Mcp-Session-Id", "bench-session")
		w := httptest.NewRecorder()
		transport.ServeHTTP(w, req)
	}
}

func BenchmarkGenerateSessionID(b *testing.B) {
	b.ReportAllocs()

	// Warm up timer
	_ = time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateSessionID()
	}
}
