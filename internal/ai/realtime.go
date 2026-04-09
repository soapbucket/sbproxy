// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/gorilla/websocket"
)

// RealtimeMessage is the envelope for all WebSocket realtime messages.
type RealtimeMessage struct {
	Type  string          `json:"type"`
	Event string          `json:"event,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// RealtimeHandler handles WebSocket connections for the realtime API (/v1/realtime).
// It upgrades the client connection, opens a backend WebSocket to the provider,
// and relays messages bidirectionally with format translation.
type RealtimeHandler struct {
	providers map[string]*ProviderConfig
	sessions  *RealtimeSessionManager
	upgrader  websocket.Upgrader
}

// NewRealtimeHandler creates a RealtimeHandler with the given session manager.
func NewRealtimeHandler(sessions *RealtimeSessionManager) *RealtimeHandler {
	return &RealtimeHandler{
		providers: make(map[string]*ProviderConfig),
		sessions:  sessions,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

// RegisterProvider adds a provider configuration for realtime routing.
func (h *RealtimeHandler) RegisterProvider(cfg *ProviderConfig) {
	h.providers[cfg.Name] = cfg
}

// defaultProvider returns the first available provider, preferring "openai".
func (h *RealtimeHandler) defaultProvider() (*ProviderConfig, bool) {
	if p, ok := h.providers["openai"]; ok {
		return p, true
	}
	for _, p := range h.providers {
		return p, true
	}
	return nil, false
}

// providerRealtimeURL builds the WebSocket URL for the provider's realtime endpoint.
func providerRealtimeURL(cfg *ProviderConfig, model string) (string, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.openai.com"
	}

	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	// Switch scheme to wss.
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		// Already ws/wss - keep as is.
	}

	u.Path = strings.TrimRight(u.Path, "/") + "/v1/realtime"
	q := u.Query()
	if model != "" {
		q.Set("model", model)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ServeHTTP upgrades the client connection to WebSocket and proxies to the provider.
func (h *RealtimeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Determine provider.
	providerName := r.URL.Query().Get("provider")
	model := r.URL.Query().Get("model")

	var pcfg *ProviderConfig
	if providerName != "" {
		var ok bool
		pcfg, ok = h.providers[providerName]
		if !ok {
			http.Error(w, `{"error":"unknown provider"}`, http.StatusBadRequest)
			return
		}
	} else {
		var ok bool
		pcfg, ok = h.defaultProvider()
		if !ok {
			http.Error(w, `{"error":"no providers configured"}`, http.StatusServiceUnavailable)
			return
		}
	}

	if model == "" {
		model = pcfg.DefaultModel
	}

	// Determine principal from header or query.
	principalID := r.Header.Get("X-Principal-ID")
	if principalID == "" {
		principalID = "anonymous"
	}

	// Create session.
	sess, err := h.sessions.Create(principalID, pcfg.Name, model)
	if err != nil {
		slog.Warn("realtime: session create failed", "error", err)
		http.Error(w, `{"error":"session limit reached"}`, http.StatusTooManyRequests)
		return
	}
	defer h.sessions.Close(sess.ID)

	// Build provider URL.
	providerURL, err := providerRealtimeURL(pcfg, model)
	if err != nil {
		slog.Error("realtime: bad provider URL", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Connect to provider.
	providerHeader := http.Header{}
	if pcfg.APIKey != "" {
		authHeader := pcfg.AuthHeader
		if authHeader == "" {
			authHeader = "Authorization"
		}
		prefix := pcfg.AuthPrefix
		if prefix == "" {
			prefix = "Bearer"
		}
		providerHeader.Set(authHeader, prefix+" "+pcfg.APIKey)
	}
	if pcfg.Organization != "" {
		providerHeader.Set("OpenAI-Organization", pcfg.Organization)
	}
	for k, v := range pcfg.Headers {
		providerHeader.Set(k, v)
	}

	providerConn, _, err := websocket.DefaultDialer.Dial(providerURL, providerHeader)
	if err != nil {
		slog.Error("realtime: provider dial failed", "error", err, "url", providerURL)
		http.Error(w, `{"error":"provider connection failed"}`, http.StatusBadGateway)
		return
	}
	defer providerConn.Close()

	// Upgrade client connection.
	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("realtime: client upgrade failed", "error", err)
		return
	}
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Provider relay.
	go func() {
		defer wg.Done()
		defer cancel()
		h.relayMessages(ctx, clientConn, providerConn, sess, directionToProvider, pcfg.Name)
	}()

	// Provider -> Client relay.
	go func() {
		defer wg.Done()
		defer cancel()
		h.relayMessages(ctx, providerConn, clientConn, sess, directionFromProvider, pcfg.Name)
	}()

	wg.Wait()
}

type relayDirection int

const (
	directionToProvider   relayDirection = iota
	directionFromProvider
)

// relayMessages reads from src and writes to dst, translating messages based on direction.
func (h *RealtimeHandler) relayMessages(ctx context.Context, src, dst *websocket.Conn, sess *RealtimeSession, dir relayDirection, provider string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		src.SetReadDeadline(time.Now().Add(60 * time.Second))
		msgType, data, err := src.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || err == io.EOF {
				return
			}
			if ctx.Err() != nil {
				return
			}
			slog.Debug("realtime: read error", "direction", dir, "error", err)
			return
		}

		// Only translate text messages (JSON). Binary messages (audio) are relayed as-is.
		if msgType == websocket.TextMessage {
			var msg RealtimeMessage
			if err := json.Unmarshal(data, &msg); err == nil {
				switch dir {
				case directionToProvider:
					msg = TranslateToProvider(msg, provider)
				case directionFromProvider:
					msg = TranslateFromProvider(msg, provider)
					h.trackUsageFromEvent(sess, msg)
				}

				translated, err := json.Marshal(msg)
				if err == nil {
					data = translated
				}
			}
		}

		if err := dst.WriteMessage(msgType, data); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("realtime: write error", "direction", dir, "error", err)
			return
		}
	}
}

// trackUsageFromEvent extracts token usage from provider response events.
func (h *RealtimeHandler) trackUsageFromEvent(sess *RealtimeSession, msg RealtimeMessage) {
	// OpenAI realtime sends usage in response.done events.
	if msg.Type != "response.done" {
		return
	}
	if msg.Data == nil {
		return
	}

	var envelope struct {
		Response struct {
			Usage struct {
				InputTokens  int64 `json:"input_tokens"`
				OutputTokens int64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"response"`
	}
	if err := json.Unmarshal(msg.Data, &envelope); err == nil {
		if envelope.Response.Usage.InputTokens > 0 || envelope.Response.Usage.OutputTokens > 0 {
			h.sessions.TrackTokens(sess.ID, envelope.Response.Usage.InputTokens, envelope.Response.Usage.OutputTokens)
		}
	}
}

// TranslateToProvider converts a client-format message to the provider's expected format.
// Currently supports OpenAI realtime events. Other providers can be added here.
func TranslateToProvider(msg RealtimeMessage, provider string) RealtimeMessage {
	switch provider {
	case "openai":
		// OpenAI realtime uses the Type field as the event type directly.
		// The client may send either Type or Event; normalize to Type.
		if msg.Type == "" && msg.Event != "" {
			msg.Type = msg.Event
		}
	default:
		// Unknown provider: pass through unchanged.
	}
	return msg
}

// TranslateFromProvider converts a provider-format message to the client-facing format.
func TranslateFromProvider(msg RealtimeMessage, provider string) RealtimeMessage {
	switch provider {
	case "openai":
		// Ensure both Type and Event are populated for client convenience.
		if msg.Event == "" && msg.Type != "" {
			msg.Event = msg.Type
		}
	default:
		// Unknown provider: pass through unchanged.
	}
	return msg
}
