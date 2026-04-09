// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// SubscriptionProtocol constants for the two major GraphQL subscription protocols.
const (
	ProtocolGraphQLWS          = "graphql-ws"           // Legacy protocol (subscriptions-transport-ws)
	ProtocolGraphQLTransportWS = "graphql-transport-ws" // Modern protocol (graphql-ws library)
)

// graphql-transport-ws message types.
const (
	GQLConnectionInit      = "connection_init"
	GQLConnectionAck       = "connection_ack"
	GQLPing                = "ping"
	GQLPong                = "pong"
	GQLSubscribe           = "subscribe"
	GQLNext                = "next"
	GQLError               = "error"
	GQLComplete            = "complete"
	GQLConnectionKeepAlive = "ka"         // Legacy protocol keep-alive
	GQLStart               = "start"      // Legacy protocol subscribe
	GQLStop                = "stop"       // Legacy protocol unsubscribe
	GQLData                = "data"       // Legacy protocol data
	GQLConnectionTerminate = "connection_terminate" // Legacy protocol terminate
)

// SubscriptionConfig configures GraphQL subscriptions.
type SubscriptionConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Protocol string `json:"protocol,omitempty"` // "graphql-ws" or "graphql-transport-ws"
}

// SubscriptionMessage represents a message in the GraphQL subscription protocol.
type SubscriptionMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// SubscriptionHandler handles WebSocket-based GraphQL subscriptions.
type SubscriptionHandler struct {
	config   SubscriptionConfig
	backend  string // Backend URL (ws:// or wss://)
	upgrader *websocket.Upgrader
	dialer   *websocket.Dialer
}

// NewSubscriptionHandler creates a new SubscriptionHandler.
func NewSubscriptionHandler(cfg SubscriptionConfig, backendURL string) *SubscriptionHandler {
	protocol := cfg.Protocol
	if protocol == "" {
		protocol = ProtocolGraphQLTransportWS
	}

	return &SubscriptionHandler{
		config:  SubscriptionConfig{
			Enabled:  cfg.Enabled,
			Protocol: protocol,
		},
		backend: backendURL,
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins; can be tightened in production config
			},
			Subprotocols: []string{protocol},
		},
		dialer: &websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
			Subprotocols:     []string{protocol},
		},
	}
}

// ServeHTTP upgrades the connection to WebSocket and proxies subscription events.
func (h *SubscriptionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.config.Enabled {
		http.Error(w, "GraphQL subscriptions are not enabled", http.StatusNotFound)
		return
	}

	// Upgrade client connection.
	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("graphql subscriptions: failed to upgrade client connection", "error", err)
		return
	}
	defer clientConn.Close()

	// Build backend WebSocket URL.
	backendURL, err := h.buildBackendURL()
	if err != nil {
		slog.Error("graphql subscriptions: invalid backend URL", "error", err)
		writeWSError(clientConn, "", "Invalid backend URL")
		return
	}

	// Connect to backend.
	backendConn, resp, err := h.dialer.Dial(backendURL, nil)
	if err != nil {
		slog.Error("graphql subscriptions: failed to connect to backend", "error", err, "url", backendURL)
		if resp != nil {
			resp.Body.Close()
		}
		writeWSError(clientConn, "", "Failed to connect to backend")
		return
	}
	defer backendConn.Close()
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	slog.Debug("graphql subscriptions: connected to backend", "url", backendURL, "protocol", h.config.Protocol)

	// Relay messages bidirectionally.
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Client -> Backend
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.relayMessages(clientConn, backendConn, "client->backend", done)
	}()

	// Backend -> Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.relayMessages(backendConn, clientConn, "backend->client", done)
	}()

	// Wait for either direction to close.
	<-done
	// Signal the other goroutine to stop.
	close(done)
	wg.Wait()

	slog.Debug("graphql subscriptions: connection closed")
}

// relayMessages reads messages from src and writes them to dst.
func (h *SubscriptionHandler) relayMessages(src, dst *websocket.Conn, direction string, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
		}

		msgType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Debug("graphql subscriptions: read error", "direction", direction, "error", err)
			}
			// Signal done on first read error (connection closed).
			select {
			case done <- struct{}{}:
			default:
			}
			return
		}

		// Optionally validate/transform messages based on protocol.
		if msgType == websocket.TextMessage {
			var msg SubscriptionMessage
			if err := json.Unmarshal(message, &msg); err == nil {
				if !h.isValidMessageType(msg.Type, direction) {
					slog.Warn("graphql subscriptions: invalid message type", "type", msg.Type, "direction", direction)
					continue
				}
				slog.Debug("graphql subscriptions: relay message", "direction", direction, "type", msg.Type, "id", msg.ID)
			}
		}

		if err := dst.WriteMessage(msgType, message); err != nil {
			slog.Debug("graphql subscriptions: write error", "direction", direction, "error", err)
			select {
			case done <- struct{}{}:
			default:
			}
			return
		}
	}
}

// isValidMessageType checks if a message type is valid for the configured protocol and direction.
func (h *SubscriptionHandler) isValidMessageType(msgType string, direction string) bool {
	if h.config.Protocol == ProtocolGraphQLTransportWS {
		return h.isValidTransportWSMessage(msgType, direction)
	}
	return h.isValidLegacyWSMessage(msgType, direction)
}

// isValidTransportWSMessage validates graphql-transport-ws protocol messages.
func (h *SubscriptionHandler) isValidTransportWSMessage(msgType string, direction string) bool {
	clientToServer := direction == "client->backend"

	if clientToServer {
		switch msgType {
		case GQLConnectionInit, GQLSubscribe, GQLComplete, GQLPing, GQLPong:
			return true
		}
		return false
	}

	// Server to client.
	switch msgType {
	case GQLConnectionAck, GQLNext, GQLError, GQLComplete, GQLPing, GQLPong:
		return true
	}
	return false
}

// isValidLegacyWSMessage validates legacy graphql-ws (subscriptions-transport-ws) protocol messages.
func (h *SubscriptionHandler) isValidLegacyWSMessage(msgType string, direction string) bool {
	clientToServer := direction == "client->backend"

	if clientToServer {
		switch msgType {
		case GQLConnectionInit, GQLStart, GQLStop, GQLConnectionTerminate:
			return true
		}
		return false
	}

	// Server to client.
	switch msgType {
	case GQLConnectionAck, GQLData, GQLError, GQLComplete, GQLConnectionKeepAlive:
		return true
	}
	return false
}

// buildBackendURL converts the backend URL to a WebSocket URL if needed.
func (h *SubscriptionHandler) buildBackendURL() (string, error) {
	u, err := url.Parse(h.backend)
	if err != nil {
		return "", fmt.Errorf("invalid backend URL: %w", err)
	}

	// Convert http(s) to ws(s) if needed.
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// Already a WebSocket URL.
	default:
		return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	return u.String(), nil
}

// writeWSError sends a GraphQL error message over WebSocket.
func writeWSError(conn *websocket.Conn, id string, message string) {
	errPayload, _ := json.Marshal([]map[string]string{
		{"message": message},
	})
	msg := SubscriptionMessage{
		ID:      id,
		Type:    GQLError,
		Payload: errPayload,
	}
	data, _ := json.Marshal(msg)
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		slog.Debug("graphql subscriptions: failed to write error", "error", err)
	}
}

// ParseSubscriptionProtocol normalizes a protocol string.
func ParseSubscriptionProtocol(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	switch p {
	case ProtocolGraphQLWS, "subscriptions-transport-ws":
		return ProtocolGraphQLWS
	case ProtocolGraphQLTransportWS, "graphql-ws-transport":
		return ProtocolGraphQLTransportWS
	default:
		return ProtocolGraphQLTransportWS
	}
}
