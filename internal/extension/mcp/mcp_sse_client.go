// mcp_sse_client.go implements the legacy MCP SSE client transport.
// This connects to an upstream MCP server using the SSE-based protocol
// where the server provides an SSE endpoint for events and a POST endpoint
// for sending JSON-RPC requests.
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

// SSEClientConfig configures an upstream MCP SSE connection.
type SSEClientConfig struct {
	URL     string            `json:"url" yaml:"url"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers"`
}

// SSEClientTransport connects to an upstream MCP server using legacy SSE transport.
// The server exposes an SSE endpoint that sends an "endpoint" event containing
// the POST URL for JSON-RPC requests, followed by server-initiated notifications.
type SSEClientTransport struct {
	config  SSEClientConfig
	client  *http.Client
	postURL string // discovered from SSE endpoint event
	reqID   atomic.Int64
	cancel  context.CancelFunc
	mu      sync.Mutex
}

// NewSSEClientTransport creates a new SSE client transport.
func NewSSEClientTransport(cfg SSEClientConfig) *SSEClientTransport {
	return &SSEClientTransport{
		config: cfg,
		client: &http.Client{},
	}
}

// Connect establishes the SSE connection and discovers the POST endpoint.
// It reads SSE events until it finds an "endpoint" event containing the
// POST URL for JSON-RPC requests.
func (t *SSEClientTransport) Connect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.config.URL, nil)
	if err != nil {
		return fmt.Errorf("sse_client: failed to create request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("sse_client: connection failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("sse_client: unexpected status %d", resp.StatusCode)
	}

	// Read SSE events until we find the endpoint event.
	scanner := bufio.NewScanner(resp.Body)
	var currentEvent string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")

			if currentEvent == "endpoint" {
				// The endpoint event data contains the POST URL.
				postURL := data
				if !strings.HasPrefix(postURL, "http") {
					// Relative URL - resolve against the SSE URL base.
					postURL = resolveRelativeURL(t.config.URL, postURL)
				}

				t.mu.Lock()
				t.postURL = postURL
				t.mu.Unlock()

				resp.Body.Close()
				return nil
			}
		}
	}

	resp.Body.Close()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("sse_client: stream error during connect: %w", err)
	}

	return fmt.Errorf("sse_client: stream ended without endpoint event")
}

// Send sends a JSON-RPC request via POST to the discovered endpoint.
func (t *SSEClientTransport) Send(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	t.mu.Lock()
	postURL := t.postURL
	t.mu.Unlock()

	if postURL == "" {
		return nil, fmt.Errorf("sse_client: not connected, call Connect first")
	}

	reqID := t.reqID.Add(1)

	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  method,
		Params:  marshalParams(params),
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("sse_client: failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sse_client: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	t.applyHeaders(httpReq)

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sse_client: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sse_client: unexpected status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sse_client: failed to read response: %w", err)
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("sse_client: failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("sse_client: server error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	result, err := json.Marshal(rpcResp.Result)
	if err != nil {
		return nil, fmt.Errorf("sse_client: failed to marshal result: %w", err)
	}

	return result, nil
}

// Listen starts listening for SSE events and calls handler for each message.
// It blocks until the context is cancelled or the stream is closed.
// The handler receives the event type (e.g., "message", "notification") and data.
func (t *SSEClientTransport) Listen(ctx context.Context, handler func(event string, data []byte) error) error {
	ctx, cancel := context.WithCancel(ctx)
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.config.URL, nil)
	if err != nil {
		cancel()
		return fmt.Errorf("sse_client: failed to create listen request: %w", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
		return fmt.Errorf("sse_client: listen connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cancel()
		return fmt.Errorf("sse_client: listen unexpected status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var currentEvent string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()

		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			eventType := currentEvent
			if eventType == "" {
				eventType = "message"
			}

			if err := handler(eventType, []byte(data)); err != nil {
				return err
			}
			currentEvent = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("sse_client: stream error: %w", err)
	}

	return nil
}

// Close disconnects from the SSE stream.
func (t *SSEClientTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.postURL = ""
	return nil
}

// PostURL returns the discovered POST endpoint URL.
func (t *SSEClientTransport) PostURL() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.postURL
}

func (t *SSEClientTransport) applyHeaders(req *http.Request) {
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}
}

// resolveRelativeURL resolves a relative URL against a base URL.
// It extracts the scheme and host from the base URL and prepends them.
func resolveRelativeURL(base, relative string) string {
	// Find the scheme + host portion of the base URL.
	idx := strings.Index(base, "://")
	if idx == -1 {
		return relative
	}

	// Find the end of the host portion (next "/" after "://").
	hostEnd := strings.Index(base[idx+3:], "/")
	if hostEnd == -1 {
		return base + relative
	}

	return base[:idx+3+hostEnd] + relative
}
