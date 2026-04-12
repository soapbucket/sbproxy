// Package websocket implements the websocket action as a self-contained module
// registered into the pkg/plugin registry.
//
// It upgrades HTTP connections to WebSocket and proxies frames bidirectionally
// between the client and an upstream WebSocket server using gorilla/websocket.
//
// This package has zero imports from internal/config.
package websocket

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("websocket", New)
}

// Defaults for WebSocket configuration.
const (
	DefaultReadBufferSize   = 4096
	DefaultWriteBufferSize  = 4096
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultPongTimeout      = 10 * time.Second
)

// Direction constants for frame relay logging and metrics.
const (
	DirectionClientToBackend = "client_to_backend"
	DirectionBackendToClient = "backend_to_client"
)

// Handler is the websocket action handler.
type Handler struct {
	cfg      Config
	upgrader *websocket.Upgrader
	dialer   *websocket.Dialer
	connSeq  atomic.Int64

	// ServiceProvider for metrics and events (set during Provision).
	services plugin.ServiceProvider
}

// New is the ActionFactory for the websocket module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("websocket: parse config: %w", err)
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("websocket: url is required")
	}

	backendURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("websocket: invalid url: %w", err)
	}
	if backendURL.Scheme != "ws" && backendURL.Scheme != "wss" {
		return nil, fmt.Errorf("websocket: url must use ws:// or wss:// scheme")
	}

	// Apply defaults.
	if cfg.ReadBufferSize == 0 {
		cfg.ReadBufferSize = DefaultReadBufferSize
	}
	if cfg.WriteBufferSize == 0 {
		cfg.WriteBufferSize = DefaultWriteBufferSize
	}
	if cfg.HandshakeTimeout.Duration == 0 {
		cfg.HandshakeTimeout.Duration = DefaultHandshakeTimeout
	}
	if cfg.PongTimeout.Duration == 0 && cfg.PingInterval.Duration > 0 {
		cfg.PongTimeout.Duration = DefaultPongTimeout
	}

	h := &Handler{cfg: cfg}

	// Build upgrader for client connections.
	h.upgrader = &websocket.Upgrader{
		ReadBufferSize:    cfg.ReadBufferSize,
		WriteBufferSize:   cfg.WriteBufferSize,
		EnableCompression: cfg.EnableCompression,
		Subprotocols:      cfg.Subprotocols,
		CheckOrigin:       h.makeCheckOrigin(),
	}

	// Build dialer for backend connections.
	h.dialer = &websocket.Dialer{
		HandshakeTimeout:  cfg.HandshakeTimeout.Duration,
		ReadBufferSize:    cfg.ReadBufferSize,
		WriteBufferSize:   cfg.WriteBufferSize,
		EnableCompression: cfg.EnableCompression,
		Subprotocols:      cfg.Subprotocols,
	}

	// TLS configuration.
	if cfg.SkipTLSVerifyHost {
		h.dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
		slog.Warn("websocket: TLS certificate verification disabled",
			"url", cfg.URL,
			"risk", "man-in-the-middle attacks possible")
	}

	return h, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "websocket" }

// Provision receives origin-level context. Satisfies plugin.Provisioner.
func (h *Handler) Provision(ctx plugin.PluginContext) error {
	h.services = ctx.Services
	return nil
}

// Validate checks configuration validity. Satisfies plugin.Validator.
func (h *Handler) Validate() error {
	if h.cfg.URL == "" {
		return fmt.Errorf("websocket: url is required")
	}
	return nil
}

// Cleanup stops background resources. Satisfies plugin.Cleanup.
func (h *Handler) Cleanup() error {
	return nil
}

// ServeHTTP upgrades the HTTP connection to WebSocket and proxies frames
// bidirectionally between the client and the upstream backend.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Debug("websocket: handling connection", "path", r.URL.Path)

	startTime := time.Now()
	origin := h.cfg.URL

	connectionID := fmt.Sprintf("ws-%d", h.connSeq.Add(1))

	// Upgrade client connection.
	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("websocket: failed to upgrade client connection", "error", err)
		return
	}
	defer func() {
		clientConn.Close()
		duration := time.Since(startTime).Seconds()
		h.recordDuration(origin, duration)
		slog.Debug("websocket: connection closed",
			"path", r.URL.Path,
			"connection_id", connectionID,
			"duration_s", duration)
	}()

	// Build backend URL.
	backendURL := h.buildBackendURL(r)
	dialHeaders := h.buildBackendDialHeaders(r)

	// Resolve subprotocols for the backend dial.
	backendSubprotocols := h.resolveBackendSubprotocols(r, clientConn.Subprotocol())
	dialer := *h.dialer
	dialer.Subprotocols = backendSubprotocols

	// Connect to backend.
	backendConn, resp, err := dialer.DialContext(r.Context(), backendURL, dialHeaders)
	if err != nil {
		slog.Error("websocket: failed to connect to backend", "url", backendURL, "error", err)
		if resp != nil {
			slog.Debug("websocket: backend response", "status", resp.Status)
		}
		_ = clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "Failed to connect to backend"))
		return
	}
	defer backendConn.Close()

	slog.Debug("websocket: connected to backend", "url", backendURL, "connection_id", connectionID)

	// Apply frame size limits.
	if h.cfg.MaxFrameSize > 0 {
		clientConn.SetReadLimit(int64(h.cfg.MaxFrameSize))
		backendConn.SetReadLimit(int64(h.cfg.MaxFrameSize))
	}

	// Set up ping/pong if configured.
	if h.cfg.PingInterval.Duration > 0 {
		h.setupPingPong(clientConn, backendConn)
	}

	// Proxy messages bidirectionally.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend
	go func() {
		defer wg.Done()
		h.proxyMessages(ctx, cancel, origin, connectionID, clientConn, backendConn, DirectionClientToBackend)
	}()

	// Backend -> Client
	go func() {
		defer wg.Done()
		h.proxyMessages(ctx, cancel, origin, connectionID, backendConn, clientConn, DirectionBackendToClient)
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (h *Handler) buildBackendURL(r *http.Request) string {
	backendURL, _ := url.Parse(h.cfg.URL)

	if h.cfg.StripBasePath {
		backendURL.Path = r.URL.Path
	}
	if h.cfg.PreserveQuery {
		backendURL.RawQuery = r.URL.RawQuery
	}

	return backendURL.String()
}

func (h *Handler) buildBackendDialHeaders(r *http.Request) http.Header {
	headers := make(http.Header)
	for name, values := range r.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Connection", "Upgrade", "Sec-Websocket-Key",
			"Sec-Websocket-Version", "Sec-Websocket-Extensions",
			"Sec-Websocket-Protocol":
			continue
		}
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return headers
}

func (h *Handler) resolveBackendSubprotocols(r *http.Request, negotiatedSubprotocol string) []string {
	if strings.EqualFold(h.cfg.Provider, "openai") {
		protocols := parseSubprotocols(r)
		if len(protocols) > 0 {
			return protocols
		}
	}
	if negotiatedSubprotocol != "" {
		return []string{negotiatedSubprotocol}
	}
	return nil
}

// parseSubprotocols extracts WebSocket subprotocols from request headers.
func parseSubprotocols(r *http.Request) []string {
	if r == nil {
		return nil
	}
	raw := r.Header.Values("Sec-WebSocket-Protocol")
	if len(raw) == 0 {
		if header := r.Header.Get("Sec-WebSocket-Protocol"); header != "" {
			raw = []string{header}
		}
	}
	var protocols []string
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				protocols = append(protocols, part)
			}
		}
	}
	return protocols
}

func (h *Handler) makeCheckOrigin() func(*http.Request) bool {
	if !h.cfg.CheckOrigin {
		return func(r *http.Request) bool { return true }
	}
	if len(h.cfg.AllowedOrigins) == 0 {
		return nil // default same-host check
	}
	allowedMap := make(map[string]bool, len(h.cfg.AllowedOrigins))
	for _, origin := range h.cfg.AllowedOrigins {
		allowedMap[origin] = true
	}
	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return allowedMap[origin]
	}
}

func (h *Handler) setupPingPong(clientConn, backendConn *websocket.Conn) {
	readTimeout := h.nextReadTimeout()

	// Set pong handlers.
	if readTimeout > 0 {
		_ = clientConn.SetReadDeadline(time.Now().Add(readTimeout))
		_ = backendConn.SetReadDeadline(time.Now().Add(readTimeout))
	}
	clientConn.SetPongHandler(func(string) error {
		if d := h.nextReadTimeout(); d > 0 {
			_ = clientConn.SetReadDeadline(time.Now().Add(d))
		}
		return nil
	})
	backendConn.SetPongHandler(func(string) error {
		if d := h.nextReadTimeout(); d > 0 {
			_ = backendConn.SetReadDeadline(time.Now().Add(d))
		}
		return nil
	})

	// Start ping tickers.
	go func() {
		ticker := time.NewTicker(h.cfg.PingInterval.Duration)
		defer ticker.Stop()
		for range ticker.C {
			if err := clientConn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(h.cfg.PingInterval.Duration)
		defer ticker.Stop()
		for range ticker.C {
			if err := backendConn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		}
	}()
}

func (h *Handler) nextReadTimeout() time.Duration {
	idle := h.cfg.IdleTimeout.Duration
	pong := h.cfg.PongTimeout.Duration
	switch {
	case idle > 0 && pong > 0:
		if idle < pong {
			return idle
		}
		return pong
	case idle > 0:
		return idle
	case pong > 0:
		return pong
	default:
		return 0
	}
}

func (h *Handler) proxyMessages(
	ctx context.Context,
	cancel context.CancelFunc,
	origin string,
	connectionID string,
	src, dst *websocket.Conn,
	direction string,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if deadline := h.nextReadTimeout(); deadline > 0 {
			_ = src.SetReadDeadline(time.Now().Add(deadline))
		}

		messageType, message, err := src.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Debug("websocket: unexpected close", "direction", direction, "error", err)
			}
			cancel()
			return
		}

		if err := dst.WriteMessage(messageType, message); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("websocket: write error", "direction", direction, "error", err)
			}
			cancel()
			return
		}

		h.recordFrame(origin, direction, len(message))
		slog.Debug("websocket: message proxied",
			"direction", direction,
			"type", messageType,
			"size", len(message),
			"connection_id", connectionID)
	}
}

// ---------------------------------------------------------------------------
// Metrics helpers (use plugin.Observer when available, otherwise noop)
// ---------------------------------------------------------------------------

func (h *Handler) recordDuration(origin string, seconds float64) {
	if h.services == nil {
		return
	}
	m := h.services.Metrics()
	if m == nil {
		return
	}
	m.Histogram("websocket_connection_duration_seconds", "origin").Observe(seconds, origin)
}

func (h *Handler) recordFrame(origin, direction string, size int) {
	if h.services == nil {
		return
	}
	m := h.services.Metrics()
	if m == nil {
		return
	}
	m.Counter("websocket_frames_relayed_total", "origin", "direction").Inc(origin, direction)
	m.Counter("websocket_bytes_transferred_total", "origin", "direction").Inc(origin, direction)
}
