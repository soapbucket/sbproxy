package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
)

// StreamableHTTPTransport implements the MCP 2025-06-18 Streamable HTTP transport.
// It serves a single HTTP endpoint that handles:
//   - POST: JSON-RPC requests (returns JSON-RPC responses, may stream via SSE)
//   - GET: Opens an SSE stream for server-initiated notifications
//   - DELETE: Terminates a session
//
// Sessions are identified by the Mcp-Session-Id header.
type StreamableHTTPTransport struct {
	handler       MCPRequestHandler
	notifications *NotificationQueue
	sessions      map[string]*session
	mu            sync.RWMutex
	logger        *slog.Logger
}

// MCPRequestHandler processes a single MCP JSON-RPC request and returns a response.
type MCPRequestHandler interface {
	HandleRequest(w http.ResponseWriter, r *http.Request, body []byte)
}

type session struct {
	id       string
	sseConns []chan []byte // Active SSE connections for this session
	mu       sync.Mutex
}

// NewStreamableHTTPTransport creates a new streamable HTTP transport.
func NewStreamableHTTPTransport(handler MCPRequestHandler, notifications *NotificationQueue) *StreamableHTTPTransport {
	return &StreamableHTTPTransport{
		handler:       handler,
		notifications: notifications,
		sessions:      make(map[string]*session),
		logger:        slog.Default(),
	}
}

// ServeHTTP implements http.Handler for the streamable HTTP transport.
func (t *StreamableHTTPTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		t.handlePost(w, r)
	case http.MethodGet:
		t.handleGet(w, r)
	case http.MethodDelete:
		t.handleDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost processes JSON-RPC requests.
func (t *StreamableHTTPTransport) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Assign session ID if not present
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		sessionID = generateSessionID()
		w.Header().Set("Mcp-Session-Id", sessionID)
	}

	// Ensure session exists
	t.getOrCreateSession(sessionID)

	// Delegate to the handler
	t.handler.HandleRequest(w, r, body)
}

// handleGet opens an SSE stream for server-initiated notifications.
func (t *StreamableHTTPTransport) handleGet(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}

	sess := t.getSession(sessionID)
	if sess == nil {
		http.Error(w, "Unknown session", http.StatusNotFound)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Create a channel for this connection
	ch := make(chan []byte, 16)
	sess.mu.Lock()
	sess.sseConns = append(sess.sseConns, ch)
	sess.mu.Unlock()

	ctx := r.Context()

	// Send any pending notifications immediately
	pending := t.notifications.Drain()
	for _, n := range pending {
		data, _ := json.Marshal(n)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	// Stream notifications until connection closes
	for {
		select {
		case <-ctx.Done():
			// Remove this connection
			sess.mu.Lock()
			for i, c := range sess.sseConns {
				if c == ch {
					sess.sseConns = append(sess.sseConns[:i], sess.sseConns[i+1:]...)
					break
				}
			}
			sess.mu.Unlock()
			return
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// handleDelete terminates a session.
func (t *StreamableHTTPTransport) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}

	t.mu.Lock()
	sess, ok := t.sessions[sessionID]
	if ok {
		delete(t.sessions, sessionID)
	}
	t.mu.Unlock()

	if !ok {
		http.Error(w, "Unknown session", http.StatusNotFound)
		return
	}

	// Close all SSE connections for this session
	sess.mu.Lock()
	for _, ch := range sess.sseConns {
		close(ch)
	}
	sess.sseConns = nil
	sess.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// BroadcastNotification sends a notification to all SSE connections across all sessions.
func (t *StreamableHTTPTransport) BroadcastNotification(method string, params interface{}) {
	var paramsBytes json.RawMessage
	if params != nil {
		if data, err := json.Marshal(params); err == nil {
			paramsBytes = data
		}
	}

	n := Notification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  paramsBytes,
	}
	data, err := json.Marshal(n)
	if err != nil {
		return
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, sess := range t.sessions {
		sess.mu.Lock()
		for _, ch := range sess.sseConns {
			select {
			case ch <- data:
			default:
				// Drop notification if channel is full
			}
		}
		sess.mu.Unlock()
	}
}

func (t *StreamableHTTPTransport) getOrCreateSession(id string) *session {
	t.mu.Lock()
	defer t.mu.Unlock()

	sess, ok := t.sessions[id]
	if !ok {
		sess = &session{id: id}
		t.sessions[id] = sess
	}
	return sess
}

func (t *StreamableHTTPTransport) getSession(id string) *session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[id]
}

// SessionCount returns the number of active sessions.
func (t *StreamableHTTPTransport) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

func generateSessionID() string {
	// Use a simple counter-based ID for now. In production, use crypto/rand.
	return fmt.Sprintf("mcp-session-%d", sessionCounter.Add(1))
}

var sessionCounter atomicCounter

type atomicCounter struct {
	val int64
	mu  sync.Mutex
}

func (c *atomicCounter) Add(delta int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.val += delta
	return c.val
}
