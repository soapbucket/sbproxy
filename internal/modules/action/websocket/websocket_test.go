package websocket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestWebSocket_Registration(t *testing.T) {
	factory, ok := plugin.GetAction("websocket")
	if !ok {
		t.Fatal("websocket action not registered")
	}
	if factory == nil {
		t.Fatal("websocket factory is nil")
	}
}

func TestWebSocket_Type(t *testing.T) {
	cfg := `{"type":"websocket","url":"ws://localhost:9001"}`
	h, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if h.Type() != "websocket" {
		t.Errorf("Type() = %q, want %q", h.Type(), "websocket")
	}
}

func TestWebSocket_ConfigParsing(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name: "minimal valid config",
			json: `{"url":"ws://localhost:8080"}`,
		},
		{
			name: "wss scheme",
			json: `{"url":"wss://example.com/ws"}`,
		},
		{
			name: "full config",
			json: `{
				"url": "ws://localhost:8080/ws",
				"strip_base_path": true,
				"preserve_query": true,
				"provider": "openai",
				"ping_interval": "30s",
				"pong_timeout": "10s",
				"idle_timeout": "5m",
				"handshake_timeout": "15s",
				"read_buffer_size": 8192,
				"write_buffer_size": 8192,
				"max_frame_size": 65536,
				"enable_compression": true,
				"subprotocols": ["graphql-ws", "graphql-transport-ws"],
				"allowed_origins": ["https://example.com"],
				"check_origin": true,
				"skip_tls_verify_host": false
			}`,
		},
		{
			name:    "missing url",
			json:    `{}`,
			wantErr: "url is required",
		},
		{
			name:    "http scheme rejected",
			json:    `{"url":"http://localhost:8080"}`,
			wantErr: "ws:// or wss://",
		},
		{
			name:    "https scheme rejected",
			json:    `{"url":"https://localhost:8080"}`,
			wantErr: "ws:// or wss://",
		},
		{
			name:    "invalid json",
			json:    `{bad json`,
			wantErr: "parse config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := New(json.RawMessage(tt.json))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h == nil {
				t.Fatal("handler is nil")
			}
		})
	}
}

func TestWebSocket_Defaults(t *testing.T) {
	cfg := `{"url":"ws://localhost:8080"}`
	ah, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := ah.(*Handler)

	if h.cfg.ReadBufferSize != DefaultReadBufferSize {
		t.Errorf("ReadBufferSize = %d, want %d", h.cfg.ReadBufferSize, DefaultReadBufferSize)
	}
	if h.cfg.WriteBufferSize != DefaultWriteBufferSize {
		t.Errorf("WriteBufferSize = %d, want %d", h.cfg.WriteBufferSize, DefaultWriteBufferSize)
	}
	if h.cfg.HandshakeTimeout.Duration != DefaultHandshakeTimeout {
		t.Errorf("HandshakeTimeout = %v, want %v", h.cfg.HandshakeTimeout.Duration, DefaultHandshakeTimeout)
	}
}

func TestWebSocket_DefaultsWithPingInterval(t *testing.T) {
	cfg := `{"url":"ws://localhost:8080","ping_interval":"30s"}`
	ah, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := ah.(*Handler)

	if h.cfg.PongTimeout.Duration != DefaultPongTimeout {
		t.Errorf("PongTimeout = %v, want %v (should default when ping_interval is set)",
			h.cfg.PongTimeout.Duration, DefaultPongTimeout)
	}
}

func TestWebSocket_Validate(t *testing.T) {
	cfg := `{"url":"ws://localhost:8080"}`
	ah, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := ah.(*Handler)

	if err := h.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestWebSocket_Provision(t *testing.T) {
	cfg := `{"url":"ws://localhost:8080"}`
	ah, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := ah.(*Handler)

	ctx := plugin.PluginContext{
		OriginID:    "test-origin",
		WorkspaceID: "test-workspace",
	}
	if err := h.Provision(ctx); err != nil {
		t.Errorf("Provision() = %v, want nil", err)
	}
}

func TestWebSocket_Cleanup(t *testing.T) {
	cfg := `{"url":"ws://localhost:8080"}`
	ah, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := ah.(*Handler)

	if err := h.Cleanup(); err != nil {
		t.Errorf("Cleanup() = %v, want nil", err)
	}
}

func TestWebSocket_BidirectionalProxy(t *testing.T) {
	// Start a WebSocket echo backend.
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("echo server upgrade error: %v", err)
			return
		}
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	defer echoServer.Close()

	// Convert http URL to ws URL.
	wsURL := "ws" + strings.TrimPrefix(echoServer.URL, "http")

	cfg := json.RawMessage(`{"type":"websocket","url":"` + wsURL + `"}`)

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Start proxy server.
	proxyServer := httptest.NewServer(http.HandlerFunc(handler.ServeHTTP))
	defer proxyServer.Close()

	proxyWSURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http")

	// Connect as a client through the proxy.
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	clientConn, _, err := dialer.Dial(proxyWSURL, nil)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	defer clientConn.Close()

	// Send a message and verify echo.
	testMsg := "hello websocket module"
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(testMsg)); err != nil {
		t.Fatalf("write error: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, msg, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Errorf("message type = %d, want %d", mt, websocket.TextMessage)
	}
	if string(msg) != testMsg {
		t.Errorf("message = %q, want %q", string(msg), testMsg)
	}

	// Send binary message.
	binMsg := []byte{0x01, 0x02, 0x03, 0x04}
	if err := clientConn.WriteMessage(websocket.BinaryMessage, binMsg); err != nil {
		t.Fatalf("binary write error: %v", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, msg, err = clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("binary read error: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Errorf("binary message type = %d, want %d", mt, websocket.BinaryMessage)
	}
	if len(msg) != len(binMsg) {
		t.Errorf("binary message length = %d, want %d", len(msg), len(binMsg))
	}
}

func TestWebSocket_DurationUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "seconds string", input: `"10s"`, want: 10 * time.Second},
		{name: "minutes string", input: `"5m"`, want: 5 * time.Minute},
		{name: "nanoseconds number", input: `1000000000`, want: time.Second},
		{name: "invalid string", input: `"bad"`, wantErr: true},
		{name: "invalid type", input: `true`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tt.input), &d)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Duration != tt.want {
				t.Errorf("duration = %v, want %v", d.Duration, tt.want)
			}
		})
	}
}

func TestWebSocket_CheckOrigin(t *testing.T) {
	// No origin checking - allow all.
	cfg := `{"url":"ws://localhost:8080","check_origin":false}`
	ah, err := New(json.RawMessage(cfg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := ah.(*Handler)
	if h.upgrader.CheckOrigin == nil {
		t.Fatal("CheckOrigin should not be nil when check_origin=false")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	if !h.upgrader.CheckOrigin(req) {
		t.Error("CheckOrigin should allow all when disabled")
	}

	// Origin checking with allowed list.
	cfg2 := `{"url":"ws://localhost:8080","check_origin":true,"allowed_origins":["https://good.com"]}`
	ah2, err := New(json.RawMessage(cfg2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h2 := ah2.(*Handler)
	if h2.upgrader.CheckOrigin == nil {
		t.Fatal("CheckOrigin should not be nil")
	}
	reqGood := httptest.NewRequest(http.MethodGet, "/", nil)
	reqGood.Header.Set("Origin", "https://good.com")
	if !h2.upgrader.CheckOrigin(reqGood) {
		t.Error("CheckOrigin should allow listed origin")
	}
	reqBad := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBad.Header.Set("Origin", "https://evil.com")
	if h2.upgrader.CheckOrigin(reqBad) {
		t.Error("CheckOrigin should reject unlisted origin")
	}
}

func TestWebSocket_ParseSubprotocols(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   int
	}{
		{name: "none", header: "", want: 0},
		{name: "single", header: "graphql-ws", want: 1},
		{name: "comma separated", header: "graphql-ws, graphql-transport-ws", want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set("Sec-WebSocket-Protocol", tt.header)
			}
			got := parseSubprotocols(r)
			if len(got) != tt.want {
				t.Errorf("parseSubprotocols() returned %d protocols, want %d", len(got), tt.want)
			}
		})
	}
}
