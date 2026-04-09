package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
)

func TestWebSocketAction_MakeCheckOrigin(t *testing.T) {
	tests := []struct {
		name           string
		checkOrigin    bool
		allowedOrigins []string
		requestOrigin  string
		wantAllowed    bool
	}{
		{
			name:           "check_origin disabled - allows any origin",
			checkOrigin:    false,
			allowedOrigins: nil,
			requestOrigin:  "https://malicious-site.com",
			wantAllowed:    true,
		},
		{
			name:           "check_origin enabled, no allowed_origins - rejects different origin",
			checkOrigin:    true,
			allowedOrigins: nil,
			requestOrigin:  "https://malicious-site.com",
			wantAllowed:    false, // Default gorilla/websocket behavior checks same host
		},
		{
			name:           "check_origin enabled with allowed_origins - allows listed origin",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com", "https://www.example.com"},
			requestOrigin:  "https://app.example.com",
			wantAllowed:    true,
		},
		{
			name:           "check_origin enabled with allowed_origins - rejects unlisted origin",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com", "https://www.example.com"},
			requestOrigin:  "https://malicious-site.com",
			wantAllowed:    false,
		},
		{
			name:           "check_origin enabled with allowed_origins - allows second listed origin",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com", "https://www.example.com"},
			requestOrigin:  "https://www.example.com",
			wantAllowed:    true,
		},
		{
			name:           "check_origin enabled with allowed_origins - no origin header allowed",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com"},
			requestOrigin:  "",
			wantAllowed:    true, // No origin header is allowed (for non-browser clients)
		},
		{
			name:           "check_origin enabled with allowed_origins - rejects similar but different origin",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com"},
			requestOrigin:  "https://app.example.com.evil.com",
			wantAllowed:    false,
		},
		{
			name:           "check_origin enabled with allowed_origins - rejects subdomain",
			checkOrigin:    true,
			allowedOrigins: []string{"https://example.com"},
			requestOrigin:  "https://app.example.com",
			wantAllowed:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create WebSocketAction with test config
			action := &WebSocketAction{
				WebSocketConfig: WebSocketConfig{
					CheckOrigin:    tt.checkOrigin,
					AllowedOrigins: tt.allowedOrigins,
				},
			}

			checkOriginFn := action.makeCheckOrigin()

			// Create a mock request with the origin header
			req := httptest.NewRequest("GET", "/ws", nil)
			if tt.requestOrigin != "" {
				req.Header.Set("Origin", tt.requestOrigin)
			}

			var got bool
			if checkOriginFn == nil {
				// nil means use default gorilla/websocket check
				// For testing purposes, we'll simulate it - default check compares origin host with request host
				got = tt.requestOrigin == "" || req.Host == extractHost(tt.requestOrigin)
			} else {
				got = checkOriginFn(req)
			}

			if got != tt.wantAllowed {
				t.Errorf("makeCheckOrigin() returned func that gave %v for origin %q, want %v",
					got, tt.requestOrigin, tt.wantAllowed)
			}
		})
	}
}

// extractHost extracts the host from an origin URL
func extractHost(origin string) string {
	// Simple extraction - remove scheme
	if len(origin) > 8 && origin[:8] == "https://" {
		return origin[8:]
	}
	if len(origin) > 7 && origin[:7] == "http://" {
		return origin[7:]
	}
	return origin
}

func TestWebSocketAction_OriginCheckIntegration(t *testing.T) {
	// Create a WebSocket server that uses our origin check
	tests := []struct {
		name           string
		checkOrigin    bool
		allowedOrigins []string
		requestOrigin  string
		wantUpgrade    bool
	}{
		{
			name:           "allowed origin upgrades successfully",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com"},
			requestOrigin:  "https://app.example.com",
			wantUpgrade:    true,
		},
		{
			name:           "disallowed origin fails to upgrade",
			checkOrigin:    true,
			allowedOrigins: []string{"https://app.example.com"},
			requestOrigin:  "https://malicious-site.com",
			wantUpgrade:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create WebSocketAction with test config
			action := &WebSocketAction{
				WebSocketConfig: WebSocketConfig{
					CheckOrigin:    tt.checkOrigin,
					AllowedOrigins: tt.allowedOrigins,
				},
			}

			checkOriginFn := action.makeCheckOrigin()

			// Create upgrader with our check function
			upgrader := websocket.Upgrader{
				CheckOrigin: checkOriginFn,
			}

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					// Upgrade failed - expected for disallowed origins
					return
				}
				defer conn.Close()
			}))
			defer server.Close()

			// Create WebSocket dialer
			dialer := websocket.Dialer{}

			// Connect with origin header
			header := http.Header{}
			if tt.requestOrigin != "" {
				header.Set("Origin", tt.requestOrigin)
			}

			wsURL := "ws" + server.URL[4:]
			conn, resp, err := dialer.Dial(wsURL, header)

			if tt.wantUpgrade {
				if err != nil {
					t.Errorf("expected successful upgrade, got error: %v", err)
					if resp != nil {
						t.Errorf("response status: %d", resp.StatusCode)
					}
					return
				}
				if conn == nil {
					t.Error("expected non-nil connection")
					return
				}
				conn.Close()
			} else {
				if err == nil {
					t.Error("expected upgrade to fail, but it succeeded")
					if conn != nil {
						conn.Close()
					}
					return
				}
				if resp != nil && resp.StatusCode != http.StatusForbidden {
					t.Logf("note: got status %d (gorilla/websocket may return different codes)", resp.StatusCode)
				}
			}
		})
	}
}

func TestWebSocketAction_DemoConfigOriginCheck(t *testing.T) {
	// Test that the demo config properly rejects malicious origins
	configJSON := `{
		"type": "websocket",
		"url": "wss://echo.websocket.org",
		"check_origin": true,
		"allowed_origins": ["https://app.example.com", "https://www.example.com"]
	}`

	var rawAction json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &rawAction); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	action, err := NewWebSocketAction(rawAction)
	if err != nil {
		t.Fatalf("failed to create WebSocket action: %v", err)
	}

	wsAction := action.(*WebSocketAction)

	// Test allowed origin
	allowedReq := httptest.NewRequest("GET", "/ws", nil)
	allowedReq.Header.Set("Origin", "https://app.example.com")
	if !wsAction.upgrader.CheckOrigin(allowedReq) {
		t.Error("expected https://app.example.com to be allowed")
	}

	// Test disallowed origin
	disallowedReq := httptest.NewRequest("GET", "/ws", nil)
	disallowedReq.Header.Set("Origin", "https://malicious-site.com")
	if wsAction.upgrader.CheckOrigin(disallowedReq) {
		t.Error("expected https://malicious-site.com to be rejected")
	}

	// Test no origin (should be allowed for non-browser clients)
	noOriginReq := httptest.NewRequest("GET", "/ws", nil)
	if !wsAction.upgrader.CheckOrigin(noOriginReq) {
		t.Error("expected request with no Origin header to be allowed")
	}
}
