package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewStreamableHTTPClient(t *testing.T) {
	cfg := StreamableHTTPClientConfig{
		URL:     "http://localhost:8080/mcp",
		Headers: map[string]string{"Authorization": "Bearer test"},
	}
	client := NewStreamableHTTPClient(cfg)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.config.URL != cfg.URL {
		t.Errorf("expected URL %q, got %q", cfg.URL, client.config.URL)
	}
}

func TestStreamableHTTPClient_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type")
		}
		if r.Header.Get("X-Custom") != "test-value" {
			t.Errorf("expected custom header")
		}

		w.Header().Set("Mcp-Session-Id", "session-123")
		w.Header().Set("Content-Type", "application/json")

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result: map[string]interface{}{
				"tools": []interface{}{},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{
		URL:     server.URL,
		Headers: map[string]string{"X-Custom": "test-value"},
	})

	result, err := client.Send(context.Background(), "tools/list", nil)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Check session ID was captured.
	if client.SessionID() != "session-123" {
		t.Errorf("expected session ID 'session-123', got %q", client.SessionID())
	}
}

func TestStreamableHTTPClient_Send_WithParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Method != "tools/call" {
			t.Errorf("expected method 'tools/call', got %q", req.Method)
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "hello"},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{URL: server.URL})

	params := map[string]interface{}{
		"name":      "search",
		"arguments": map[string]interface{}{"query": "test"},
	}

	result, err := client.Send(context.Background(), "tools/call", params)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestStreamableHTTPClient_Send_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Error: &JSONRPCError{
				Code:    -32600,
				Message: "Invalid request",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{URL: server.URL})

	_, err := client.Send(context.Background(), "tools/list", nil)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestStreamableHTTPClient_Send_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{URL: server.URL})

	_, err := client.Send(context.Background(), "tools/list", nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestStreamableHTTPClient_SendWithSSE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher support")
		}

		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: {\"chunk\":%d}\n\n", i)
			flusher.Flush()
		}
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{URL: server.URL})

	var received []json.RawMessage
	err := client.SendWithSSE(context.Background(), "tools/call", nil, func(data []byte) error {
		received = append(received, json.RawMessage(data))
		return nil
	})

	if err != nil {
		t.Fatalf("SendWithSSE failed: %v", err)
	}

	if len(received) != 3 {
		t.Errorf("expected 3 events, got %d", len(received))
	}
}

func TestStreamableHTTPClient_SendWithSSE_CallbackError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "data: {\"chunk\":%d}\n\n", i)
			flusher.Flush()
		}
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{URL: server.URL})

	callbackErr := fmt.Errorf("stop processing")
	count := 0
	err := client.SendWithSSE(context.Background(), "tools/call", nil, func(data []byte) error {
		count++
		if count >= 2 {
			return callbackErr
		}
		return nil
	})

	if err != callbackErr {
		t.Errorf("expected callback error, got %v", err)
	}
}

func TestStreamableHTTPClient_SessionPersistence(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call: assign session.
			w.Header().Set("Mcp-Session-Id", "sess-abc")
		} else {
			// Subsequent calls: expect session header.
			if r.Header.Get("Mcp-Session-Id") != "sess-abc" {
				t.Errorf("expected session header on call %d", callCount)
			}
		}

		resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: "ok"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewStreamableHTTPClient(StreamableHTTPClientConfig{URL: server.URL})

	// First call establishes session.
	client.Send(context.Background(), "initialize", nil)
	// Second call should include session ID.
	client.Send(context.Background(), "tools/list", nil)

	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestMarshalParams(t *testing.T) {
	// nil params
	result := marshalParams(nil)
	if result != nil {
		t.Error("expected nil for nil params")
	}

	// map params
	result = marshalParams(map[string]string{"key": "value"})
	if result == nil {
		t.Error("expected non-nil for map params")
	}
}
