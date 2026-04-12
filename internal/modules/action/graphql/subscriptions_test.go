package graphql

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestSubscriptionHandlerCreation(t *testing.T) {
	handler := NewSubscriptionHandler(SubscriptionConfig{
		Enabled:  true,
		Protocol: ProtocolGraphQLTransportWS,
	}, "ws://localhost:4000/graphql")

	if handler == nil {
		t.Fatal("NewSubscriptionHandler() returned nil")
	}
	if handler.config.Protocol != ProtocolGraphQLTransportWS {
		t.Errorf("protocol = %q, want %q", handler.config.Protocol, ProtocolGraphQLTransportWS)
	}
}

func TestSubscriptionHandlerDefaultProtocol(t *testing.T) {
	handler := NewSubscriptionHandler(SubscriptionConfig{
		Enabled: true,
	}, "ws://localhost:4000/graphql")

	if handler.config.Protocol != ProtocolGraphQLTransportWS {
		t.Errorf("default protocol = %q, want %q", handler.config.Protocol, ProtocolGraphQLTransportWS)
	}
}

func TestSubscriptionHandlerDisabled(t *testing.T) {
	handler := NewSubscriptionHandler(SubscriptionConfig{
		Enabled: false,
	}, "ws://localhost:4000/graphql")

	// Create a test server with the handler.
	server := httptest.NewServer(handler)
	defer server.Close()

	// Attempt a regular HTTP request (not WebSocket).
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestSubscriptionProtocolMessages(t *testing.T) {
	// Create a mock backend WebSocket server that echoes messages.
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin:  func(r *http.Request) bool { return true },
			Subprotocols: []string{ProtocolGraphQLTransportWS},
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			msgType, message, err := conn.ReadMessage()
			if err != nil {
				return
			}

			// Parse and respond based on message type.
			var msg SubscriptionMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case GQLConnectionInit:
				// Respond with connection_ack.
				ack := SubscriptionMessage{Type: GQLConnectionAck}
				data, _ := json.Marshal(ack)
				conn.WriteMessage(msgType, data)
			case GQLSubscribe:
				// Respond with a next message followed by complete.
				payload, _ := json.Marshal(map[string]interface{}{
					"data": map[string]interface{}{
						"newMessage": map[string]interface{}{
							"id":   "1",
							"text": "Hello",
						},
					},
				})
				next := SubscriptionMessage{ID: msg.ID, Type: GQLNext, Payload: payload}
				data, _ := json.Marshal(next)
				conn.WriteMessage(msgType, data)

				complete := SubscriptionMessage{ID: msg.ID, Type: GQLComplete}
				data, _ = json.Marshal(complete)
				conn.WriteMessage(msgType, data)
			}
		}
	}))
	defer backendServer.Close()

	// Convert HTTP URL to WS URL.
	backendWSURL := "ws" + strings.TrimPrefix(backendServer.URL, "http")

	// Create the subscription handler pointing to the backend.
	handler := NewSubscriptionHandler(SubscriptionConfig{
		Enabled:  true,
		Protocol: ProtocolGraphQLTransportWS,
	}, backendWSURL)

	// Create a test server with the subscription handler.
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	// Connect as a client.
	proxyWSURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http")
	dialer := websocket.Dialer{
		Subprotocols: []string{ProtocolGraphQLTransportWS},
	}
	clientConn, _, err := dialer.Dial(proxyWSURL, nil)
	if err != nil {
		t.Fatalf("client dial error = %v", err)
	}
	defer clientConn.Close()

	// Send connection_init.
	initMsg := SubscriptionMessage{Type: GQLConnectionInit}
	initData, _ := json.Marshal(initMsg)
	if err := clientConn.WriteMessage(websocket.TextMessage, initData); err != nil {
		t.Fatalf("write connection_init error = %v", err)
	}

	// Read connection_ack.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, message, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read connection_ack error = %v", err)
	}

	var ackMsg SubscriptionMessage
	if err := json.Unmarshal(message, &ackMsg); err != nil {
		t.Fatalf("parse connection_ack error = %v", err)
	}
	if ackMsg.Type != GQLConnectionAck {
		t.Errorf("expected connection_ack, got %q", ackMsg.Type)
	}

	// Send a subscribe message.
	subPayload, _ := json.Marshal(map[string]interface{}{
		"query": `subscription { newMessage { id text } }`,
	})
	subMsg := SubscriptionMessage{
		ID:      "sub1",
		Type:    GQLSubscribe,
		Payload: subPayload,
	}
	subData, _ := json.Marshal(subMsg)
	if err := clientConn.WriteMessage(websocket.TextMessage, subData); err != nil {
		t.Fatalf("write subscribe error = %v", err)
	}

	// Read the next message.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, message, err = clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read next error = %v", err)
	}

	var nextMsg SubscriptionMessage
	if err := json.Unmarshal(message, &nextMsg); err != nil {
		t.Fatalf("parse next error = %v", err)
	}
	if nextMsg.Type != GQLNext {
		t.Errorf("expected next, got %q", nextMsg.Type)
	}
	if nextMsg.ID != "sub1" {
		t.Errorf("next message id = %q, want sub1", nextMsg.ID)
	}

	// Read the complete message.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, message, err = clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read complete error = %v", err)
	}

	var completeMsg SubscriptionMessage
	if err := json.Unmarshal(message, &completeMsg); err != nil {
		t.Fatalf("parse complete error = %v", err)
	}
	if completeMsg.Type != GQLComplete {
		t.Errorf("expected complete, got %q", completeMsg.Type)
	}
}

func TestSubscriptionTransportWSValidation(t *testing.T) {
	handler := NewSubscriptionHandler(SubscriptionConfig{
		Enabled:  true,
		Protocol: ProtocolGraphQLTransportWS,
	}, "ws://localhost:4000/graphql")

	// Client to server valid messages.
	clientValid := []string{GQLConnectionInit, GQLSubscribe, GQLComplete, GQLPing, GQLPong}
	for _, mt := range clientValid {
		if !handler.isValidMessageType(mt, "client->backend") {
			t.Errorf("message type %q should be valid for client->backend", mt)
		}
	}

	// Client to server invalid messages.
	clientInvalid := []string{GQLConnectionAck, GQLNext, GQLError}
	for _, mt := range clientInvalid {
		if handler.isValidMessageType(mt, "client->backend") {
			t.Errorf("message type %q should be invalid for client->backend", mt)
		}
	}

	// Server to client valid messages.
	serverValid := []string{GQLConnectionAck, GQLNext, GQLError, GQLComplete, GQLPing, GQLPong}
	for _, mt := range serverValid {
		if !handler.isValidMessageType(mt, "backend->client") {
			t.Errorf("message type %q should be valid for backend->client", mt)
		}
	}

	// Server to client invalid messages.
	serverInvalid := []string{GQLConnectionInit, GQLSubscribe}
	for _, mt := range serverInvalid {
		if handler.isValidMessageType(mt, "backend->client") {
			t.Errorf("message type %q should be invalid for backend->client", mt)
		}
	}
}

func TestSubscriptionLegacyWSValidation(t *testing.T) {
	handler := NewSubscriptionHandler(SubscriptionConfig{
		Enabled:  true,
		Protocol: ProtocolGraphQLWS,
	}, "ws://localhost:4000/graphql")

	// Client to server valid messages.
	clientValid := []string{GQLConnectionInit, GQLStart, GQLStop, GQLConnectionTerminate}
	for _, mt := range clientValid {
		if !handler.isValidMessageType(mt, "client->backend") {
			t.Errorf("legacy: message type %q should be valid for client->backend", mt)
		}
	}

	// Server to client valid messages.
	serverValid := []string{GQLConnectionAck, GQLData, GQLError, GQLComplete, GQLConnectionKeepAlive}
	for _, mt := range serverValid {
		if !handler.isValidMessageType(mt, "backend->client") {
			t.Errorf("legacy: message type %q should be valid for backend->client", mt)
		}
	}
}

func TestParseSubscriptionProtocol(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"graphql-ws", ProtocolGraphQLWS},
		{"graphql-transport-ws", ProtocolGraphQLTransportWS},
		{"subscriptions-transport-ws", ProtocolGraphQLWS},
		{"graphql-ws-transport", ProtocolGraphQLTransportWS},
		{"", ProtocolGraphQLTransportWS},
		{"unknown", ProtocolGraphQLTransportWS},
		{"  graphql-ws  ", ProtocolGraphQLWS},
		{"GRAPHQL-TRANSPORT-WS", ProtocolGraphQLTransportWS},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseSubscriptionProtocol(tt.input)
			if result != tt.expect {
				t.Errorf("ParseSubscriptionProtocol(%q) = %q, want %q", tt.input, result, tt.expect)
			}
		})
	}
}

func TestBuildBackendURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expect  string
		wantErr bool
	}{
		{"ws url", "ws://localhost:4000/graphql", "ws://localhost:4000/graphql", false},
		{"wss url", "wss://localhost:4000/graphql", "wss://localhost:4000/graphql", false},
		{"http to ws", "http://localhost:4000/graphql", "ws://localhost:4000/graphql", false},
		{"https to wss", "https://localhost:4000/graphql", "wss://localhost:4000/graphql", false},
		{"unsupported scheme", "ftp://localhost:4000", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewSubscriptionHandler(SubscriptionConfig{Enabled: true}, tt.input)
			result, err := handler.buildBackendURL()
			if (err != nil) != tt.wantErr {
				t.Errorf("buildBackendURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expect {
				t.Errorf("buildBackendURL() = %q, want %q", result, tt.expect)
			}
		})
	}
}
