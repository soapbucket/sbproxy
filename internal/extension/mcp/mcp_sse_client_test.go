package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewSSEClientTransport(t *testing.T) {
	cfg := SSEClientConfig{
		URL:     "http://localhost:8080/sse",
		Headers: map[string]string{"Authorization": "Bearer test"},
	}
	transport := NewSSEClientTransport(cfg)
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if transport.config.URL != cfg.URL {
		t.Errorf("expected URL %q, got %q", cfg.URL, transport.config.URL)
	}
}

func TestSSEClientTransport_Connect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("expected Accept: text/event-stream")
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		fmt.Fprintf(w, "event: endpoint\ndata: /rpc\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: server.URL})

	err := transport.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// The discovered POST URL should be resolved against the server URL.
	expectedPostURL := server.URL + "/rpc"
	if transport.PostURL() != expectedPostURL {
		t.Errorf("expected post URL %q, got %q", expectedPostURL, transport.PostURL())
	}
}

func TestSSEClientTransport_Connect_AbsoluteURL(t *testing.T) {
	var postServer *httptest.Server
	postServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer postServer.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		fmt.Fprintf(w, "event: endpoint\ndata: %s/rpc\n\n", postServer.URL)
		flusher.Flush()
	}))
	defer server.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: server.URL})

	err := transport.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	expectedPostURL := postServer.URL + "/rpc"
	if transport.PostURL() != expectedPostURL {
		t.Errorf("expected post URL %q, got %q", expectedPostURL, transport.PostURL())
	}
}

func TestSSEClientTransport_Connect_NoEndpointEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Close immediately without sending endpoint event.
	}))
	defer server.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: server.URL})

	err := transport.Connect(context.Background())
	if err == nil {
		t.Fatal("expected error when no endpoint event received")
	}
}

func TestSSEClientTransport_Connect_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: server.URL})

	err := transport.Connect(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP error")
	}
}

func TestSSEClientTransport_Send(t *testing.T) {
	// Set up a POST endpoint.
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": []interface{}{},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer postServer.Close()

	// Set up SSE server that discovers the POST endpoint.
	sseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", postServer.URL)
		flusher.Flush()
	}))
	defer sseServer.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: sseServer.URL})

	err := transport.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	result, err := transport.Send(context.Background(), "tools/list", nil)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestSSEClientTransport_Send_NotConnected(t *testing.T) {
	transport := NewSSEClientTransport(SSEClientConfig{URL: "http://localhost:9999"})

	_, err := transport.Send(context.Background(), "tools/list", nil)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestSSEClientTransport_Send_ServerError(t *testing.T) {
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Error:   &JSONRPCError{Code: -32601, Message: "Method not found"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer postServer.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: "http://localhost:9999"})
	// Manually set post URL to skip Connect.
	transport.mu.Lock()
	transport.postURL = postServer.URL
	transport.mu.Unlock()

	_, err := transport.Send(context.Background(), "nonexistent/method", nil)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestSSEClientTransport_Listen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		fmt.Fprintf(w, "event: notification\ndata: {\"method\":\"tools/list_changed\"}\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "data: {\"method\":\"ping\"}\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	transport := NewSSEClientTransport(SSEClientConfig{URL: server.URL})

	var events []struct {
		event string
		data  string
	}

	err := transport.Listen(context.Background(), func(event string, data []byte) error {
		events = append(events, struct {
			event string
			data  string
		}{event, string(data)})
		if len(events) >= 2 {
			return fmt.Errorf("stop")
		}
		return nil
	})

	// We expect the "stop" error from the handler.
	if err == nil || err.Error() != "stop" {
		t.Fatalf("expected 'stop' error, got %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].event != "notification" {
		t.Errorf("expected event type 'notification', got %q", events[0].event)
	}
	if events[1].event != "message" {
		t.Errorf("expected default event type 'message', got %q", events[1].event)
	}
}

func TestSSEClientTransport_Close(t *testing.T) {
	transport := NewSSEClientTransport(SSEClientConfig{URL: "http://localhost:9999"})
	transport.mu.Lock()
	transport.postURL = "http://localhost:9999/rpc"
	transport.mu.Unlock()

	err := transport.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if transport.PostURL() != "" {
		t.Error("expected empty post URL after close")
	}
}

func TestResolveRelativeURL(t *testing.T) {
	tests := []struct {
		base     string
		relative string
		expected string
	}{
		{"http://localhost:8080/sse", "/rpc", "http://localhost:8080/rpc"},
		{"https://example.com/mcp/sse", "/mcp/rpc", "https://example.com/mcp/rpc"},
		{"http://host:9090", "/path", "http://host:9090/path"},
		{"invalid-url", "/path", "/path"},
	}

	for _, tt := range tests {
		got := resolveRelativeURL(tt.base, tt.relative)
		if got != tt.expected {
			t.Errorf("resolveRelativeURL(%q, %q) = %q, want %q", tt.base, tt.relative, got, tt.expected)
		}
	}
}
