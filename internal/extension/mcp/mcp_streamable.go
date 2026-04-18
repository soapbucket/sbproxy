// mcp_streamable.go implements a client-side MCP Streamable HTTP transport.
// This connects to upstream MCP servers using HTTP POST for JSON-RPC requests,
// with optional SSE streaming for responses.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// StreamableHTTPClientConfig configures the MCP Streamable HTTP client transport.
type StreamableHTTPClientConfig struct {
	URL     string            `json:"url" yaml:"url"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers"`
}

// StreamableHTTPClient implements bidirectional MCP over HTTP POST + SSE.
// It sends JSON-RPC requests via POST and can receive streaming SSE responses.
type StreamableHTTPClient struct {
	config    StreamableHTTPClientConfig
	client    *http.Client
	sessionID string
	reqID     atomic.Int64
	mu        sync.Mutex
}

// NewStreamableHTTPClient creates a new Streamable HTTP client transport.
func NewStreamableHTTPClient(cfg StreamableHTTPClientConfig) *StreamableHTTPClient {
	return &StreamableHTTPClient{
		config: cfg,
		client: &http.Client{},
	}
}

// Send sends a JSON-RPC request and returns the response.
func (t *StreamableHTTPClient) Send(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	reqID := t.reqID.Add(1)

	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  method,
		Params:  marshalParams(params),
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("streamable_http: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("streamable_http: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	t.applyHeaders(httpReq)

	t.mu.Lock()
	if t.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", t.sessionID)
	}
	t.mu.Unlock()

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("streamable_http: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Capture session ID from response.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("streamable_http: unexpected status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("streamable_http: failed to read response: %w", err)
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("streamable_http: failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("streamable_http: server error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	result, err := json.Marshal(rpcResp.Result)
	if err != nil {
		return nil, fmt.Errorf("streamable_http: failed to marshal result: %w", err)
	}

	return result, nil
}

// SendWithSSE sends a request and streams SSE responses via callback.
// The callback is invoked for each SSE data event. If the callback returns
// an error, streaming stops and the error is returned.
func (t *StreamableHTTPClient) SendWithSSE(ctx context.Context, method string, params interface{}, onEvent func(data []byte) error) error {
	reqID := t.reqID.Add(1)

	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  method,
		Params:  marshalParams(params),
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return fmt.Errorf("streamable_http: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("streamable_http: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	t.applyHeaders(httpReq)

	t.mu.Lock()
	if t.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", t.sessionID)
	}
	t.mu.Unlock()

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("streamable_http: request failed: %w", err)
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("streamable_http: unexpected status %d", resp.StatusCode)
	}

	// Parse SSE stream
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if err := onEvent([]byte(data)); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("streamable_http: SSE stream error: %w", err)
	}

	return nil
}

// SessionID returns the current session ID, if any.
func (t *StreamableHTTPClient) SessionID() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessionID
}

func (t *StreamableHTTPClient) applyHeaders(req *http.Request) {
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}
}

// marshalParams converts params to json.RawMessage. Returns nil if params is nil.
func marshalParams(params interface{}) json.RawMessage {
	if params == nil {
		return nil
	}
	data, err := json.Marshal(params)
	if err != nil {
		return nil
	}
	return data
}
