// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package handler

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// sseEventBufPool pools bytes.Buffer instances for SSE event formatting
// to reduce GC pressure on high-frequency SSE streams.
var sseEventBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// SSEEvent represents a Server-Sent Event
type SSEEvent struct {
	ID    string
	Event string
	Data  string
	Retry int
}

// SSEConnection represents an active SSE connection
type SSEConnection struct {
	w           http.ResponseWriter
	flusher     http.Flusher
	ctx         context.Context
	cancel      context.CancelFunc
	filters     []SSEEventFilter
	mu          sync.Mutex
	lastEventID string
	closed      bool
}

// SSEEventFilter is a function that decides whether to forward an event
type SSEEventFilter func(event SSEEvent) bool

// SSEConnectionManager manages multiple SSE connections
type SSEConnectionManager struct {
	connections map[string]*SSEConnection
	mu          sync.RWMutex

	// Heartbeat configuration
	heartbeatInterval time.Duration
	heartbeatEnabled  bool
}

// NewSSEConnectionManager creates a new SSE connection manager
func NewSSEConnectionManager() *SSEConnectionManager {
	return &SSEConnectionManager{
		connections:       make(map[string]*SSEConnection),
		heartbeatInterval: 30 * time.Second,
		heartbeatEnabled:  true,
	}
}

// SetHeartbeat configures heartbeat settings
func (m *SSEConnectionManager) SetHeartbeat(enabled bool, interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeatEnabled = enabled
	m.heartbeatInterval = interval
}

// AddConnection adds a connection to the manager
func (m *SSEConnectionManager) AddConnection(id string, conn *SSEConnection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connections[id] = conn

	// Update active connections metric
	metric.ActiveConnectionsSet("server", "sse", int64(len(m.connections)))

	slog.Info("SSE connection added", "connection_id", id, "total_connections", len(m.connections))
}

// RemoveConnection removes a connection from the manager
func (m *SSEConnectionManager) RemoveConnection(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conn, exists := m.connections[id]; exists {
		conn.Close()
		delete(m.connections, id)

		// Update active connections metric
		metric.ActiveConnectionsSet("server", "sse", int64(len(m.connections)))

		slog.Info("SSE connection removed", "connection_id", id, "remaining_connections", len(m.connections))
	}
}

// GetConnection retrieves a connection by ID
func (m *SSEConnectionManager) GetConnection(id string) (*SSEConnection, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conn, exists := m.connections[id]
	return conn, exists
}

// Broadcast sends an event to all connections
func (m *SSEConnectionManager) Broadcast(event SSEEvent) {
	m.mu.RLock()
	connections := make([]*SSEConnection, 0, len(m.connections))
	for _, conn := range m.connections {
		connections = append(connections, conn)
	}
	m.mu.RUnlock()

	for _, conn := range connections {
		if err := conn.SendEvent(event); err != nil {
			slog.Debug("failed to send event to connection", "error", err)
		}
	}
}

// Count returns the number of active connections
func (m *SSEConnectionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.connections)
}

// Close closes all connections
func (m *SSEConnectionManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, conn := range m.connections {
		conn.Close()
		delete(m.connections, id)
	}
}

// NewSSEConnection creates a new SSE connection
func NewSSEConnection(w http.ResponseWriter, r *http.Request) (*SSEConnection, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}

	ctx, cancel := context.WithCancel(r.Context())

	conn := &SSEConnection{
		w:       w,
		flusher: flusher,
		ctx:     ctx,
		cancel:  cancel,
		filters: make([]SSEEventFilter, 0),
	}

	// Get Last-Event-ID header for reconnection support
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		conn.lastEventID = lastEventID
		slog.Debug("SSE connection with last event ID", "last_event_id", lastEventID)
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	return conn, nil
}

// AddFilter adds an event filter
func (c *SSEConnection) AddFilter(filter SSEEventFilter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filters = append(c.filters, filter)
}

// SendEvent sends an SSE event to the client
func (c *SSEConnection) SendEvent(event SSEEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection closed")
	}

	// Apply filters
	for _, filter := range c.filters {
		if !filter(event) {
			return nil // Event filtered out
		}
	}

	// Build event using pooled buffer to reduce GC pressure
	buf := sseEventBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer sseEventBufPool.Put(buf)

	if event.ID != "" {
		fmt.Fprintf(buf, "id: %s\n", event.ID)
		c.lastEventID = event.ID
	}

	if event.Event != "" {
		fmt.Fprintf(buf, "event: %s\n", event.Event)
	}

	if event.Retry > 0 {
		fmt.Fprintf(buf, "retry: %d\n", event.Retry)
	}

	// Data can be multi-line
	for _, line := range strings.Split(event.Data, "\n") {
		fmt.Fprintf(buf, "data: %s\n", line)
	}

	buf.WriteString("\n")

	// Write to client
	if _, err := c.w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	c.flusher.Flush()
	return nil
}

// SendComment sends a comment (useful for keep-alive)
func (c *SSEConnection) SendComment(comment string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection closed")
	}

	msg := fmt.Sprintf(": %s\n\n", comment)
	if _, err := c.w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to write comment: %w", err)
	}

	c.flusher.Flush()
	return nil
}

// Close closes the connection
func (c *SSEConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true
		c.cancel()
	}
}

// IsClosed returns whether the connection is closed
func (c *SSEConnection) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Context returns the connection context
func (c *SSEConnection) Context() context.Context {
	return c.ctx
}

// SSEProxy proxies SSE events from an upstream server
type SSEProxy struct {
	client *http.Client
}

// NewSSEProxy creates a new SSE proxy
func NewSSEProxy(client *http.Client) *SSEProxy {
	if client == nil {
		client = &http.Client{
			Timeout: 0, // No timeout for SSE
		}
	}

	return &SSEProxy{
		client: client,
	}
}

// Proxy forwards SSE events from upstream to downstream
func (p *SSEProxy) Proxy(ctx context.Context, upstreamURL string, conn *SSEConnection) error {
	req, err := http.NewRequestWithContext(ctx, "GET", upstreamURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Forward Last-Event-ID if present
	if conn.lastEventID != "" {
		req.Header.Set("Last-Event-ID", conn.lastEventID)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream returned status %d", resp.StatusCode)
	}

	// Parse and forward events
	return p.parseAndForward(resp.Body, conn)
}

// parseAndForward reads SSE events from upstream and forwards them
func (p *SSEProxy) parseAndForward(r io.Reader, conn *SSEConnection) error {
	scanner := bufio.NewScanner(r)
	var currentEvent SSEEvent

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line indicates end of event
		if line == "" {
			if currentEvent.Data != "" || currentEvent.Event != "" {
				if err := conn.SendEvent(currentEvent); err != nil {
					return err
				}
				currentEvent = SSEEvent{}
			}
			continue
		}

		// Parse event field
		if strings.HasPrefix(line, ":") {
			// Comment, ignore
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		field := parts[0]
		value := strings.TrimSpace(parts[1])

		switch field {
		case "id":
			currentEvent.ID = value
		case "event":
			currentEvent.Event = value
		case "data":
			if currentEvent.Data != "" {
				currentEvent.Data += "\n"
			}
			currentEvent.Data += value
		case "retry":
			var retry int
			if _, err := fmt.Sscanf(value, "%d", &retry); err == nil {
				currentEvent.Retry = retry
			}
		}

		// Check if connection is closed
		select {
		case <-conn.Context().Done():
			return conn.Context().Err()
		default:
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading stream: %w", err)
	}

	return nil
}

// CreateEventFilter creates common event filters
func CreateEventFilter(eventType string) SSEEventFilter {
	return func(event SSEEvent) bool {
		if eventType == "" {
			return true // No filter
		}
		return event.Event == eventType
	}
}

// CreateIDFilter creates a filter that only forwards events after a given ID
func CreateIDFilter(lastEventID string) SSEEventFilter {
	found := false
	return func(event SSEEvent) bool {
		if lastEventID == "" {
			return true // No filter
		}
		if found {
			return true // Already found, forward all
		}
		if event.ID == lastEventID {
			found = true
			return false // Skip this event, start from next
		}
		return false // Haven't found it yet
	}
}

// StartHeartbeat starts sending periodic heartbeat comments
func StartHeartbeat(ctx context.Context, conn *SSEConnection, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.Context().Done():
			return
		case <-ticker.C:
			if err := conn.SendComment("heartbeat"); err != nil {
				slog.Debug("heartbeat failed", "error", err)
				return
			}
		}
	}
}
