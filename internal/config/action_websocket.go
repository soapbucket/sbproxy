// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const (
	// DefaultWSReadBufferSize is the default value for ws read buffer size.
	DefaultWSReadBufferSize   = 4096
	// DefaultWSWriteBufferSize is the default value for ws write buffer size.
	DefaultWSWriteBufferSize  = 4096
	// DefaultWSHandshakeTimeout is the default value for ws handshake timeout.
	DefaultWSHandshakeTimeout = 10 * time.Second
	// DefaultWSPongTimeout is the default value for ws pong timeout.
	DefaultWSPongTimeout      = 10 * time.Second
)

func init() {
	loaderFns[TypeWebSocket] = NewWebSocketAction
}

// WebSocketAction represents a web socket action.
type WebSocketAction struct {
	WebSocketConfig

	upgrader       *websocket.Upgrader
	dialer         *websocket.Dialer
	pool           *transport.WebSocketConnectionPool
	poolMu         sync.Mutex
	budgetEnforcer *ai.BudgetEnforcer
	connSeq        atomic.Int64
}

type websocketSessionState struct {
	action       *WebSocketAction
	request      *http.Request
	origin       string
	provider     string
	connectionID string
	budget       *ai.BudgetEnforcer
	budgetScope  string
}

// NewWebSocketAction creates and initializes a new WebSocketAction.
func NewWebSocketAction(data []byte) (ActionConfig, error) {
	config := &WebSocketAction{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Validate URL
	if config.URL == "" {
		return nil, fmt.Errorf("websocket: url is required")
	}

	backendURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("websocket: invalid url: %w", err)
	}

	if backendURL.Scheme != "ws" && backendURL.Scheme != "wss" {
		return nil, fmt.Errorf("websocket: url must use ws:// or wss:// scheme")
	}

	// Set defaults
	if config.ReadBufferSize == 0 {
		config.ReadBufferSize = DefaultWSReadBufferSize
	}
	if config.WriteBufferSize == 0 {
		config.WriteBufferSize = DefaultWSWriteBufferSize
	}
	if config.HandshakeTimeout.Duration == 0 {
		config.HandshakeTimeout.Duration = DefaultWSHandshakeTimeout
	}
	if config.PongTimeout.Duration == 0 && config.PingInterval.Duration > 0 {
		config.PongTimeout.Duration = DefaultWSPongTimeout
	}
	if config.EnableRFC8441 || config.EnableRFC9220 {
		enableHTTP2ExtendedConnectRuntime()
	}

	// Create upgrader for client connections
	config.upgrader = &websocket.Upgrader{
		ReadBufferSize:    config.ReadBufferSize,
		WriteBufferSize:   config.WriteBufferSize,
		EnableCompression: config.EnableCompression,
		Subprotocols:      config.Subprotocols,
		CheckOrigin:       config.makeCheckOrigin(),
	}

	// Create dialer for backend connections
	config.dialer = &websocket.Dialer{
		HandshakeTimeout:  config.HandshakeTimeout.Duration,
		ReadBufferSize:    config.ReadBufferSize,
		WriteBufferSize:   config.WriteBufferSize,
		EnableCompression: config.EnableCompression,
		Subprotocols:      config.Subprotocols,
	}

	// Apply connection-level settings to dialer
	tlsConfig := &tls.Config{}

	if config.SkipTLSVerifyHost {
		tlsConfig.InsecureSkipVerify = true

		// CRITICAL SECURITY WARNING: Log and record metric when TLS verification is disabled
		originName := config.URL
		if originName == "" {
			originName = "unknown"
		}
		slog.Warn("CRITICAL SECURITY WARNING: TLS certificate verification is disabled",
			"origin", originName,
			"connection_type", "websocket",
			"risk", "man-in-the-middle attacks possible",
			"recommendation", "enable TLS verification in production environments")
		metric.TLSInsecureSkipVerifyEnabled(originName, "websocket")
	}

	// Set up mutual TLS (mTLS) if configured
	// Support both file paths and base64-encoded data (prefer base64 if both provided)
	hasClientCert := (config.MTLSClientCertFile != "" || config.MTLSClientCertData != "") &&
		(config.MTLSClientKeyFile != "" || config.MTLSClientKeyData != "")

	if hasClientCert {
		originName := config.URL
		if originName == "" {
			originName = "unknown"
		}

		// Load client certificate and key (prefer base64 data over file paths)
		var cert tls.Certificate
		var err error
		var certSource string

		if config.MTLSClientCertData != "" && config.MTLSClientKeyData != "" {
			// Load from base64-encoded data
			certPEM, err := base64.StdEncoding.DecodeString(config.MTLSClientCertData)
			if err != nil {
				slog.Error("failed to decode base64 mTLS client certificate for WebSocket",
					"origin", originName,
					"error", err)
			} else {
				keyPEM, err := base64.StdEncoding.DecodeString(config.MTLSClientKeyData)
				if err != nil {
					slog.Error("failed to decode base64 mTLS client key for WebSocket",
						"origin", originName,
						"error", err)
				} else {
					cert, err = tls.X509KeyPair(certPEM, keyPEM)
					if err != nil {
						slog.Error("failed to parse mTLS client certificate from base64 data for WebSocket",
							"origin", originName,
							"error", err)
					} else {
						certSource = "base64_data"
					}
				}
			}
		} else if config.MTLSClientCertFile != "" && config.MTLSClientKeyFile != "" {
			// Load from file paths
			cert, err = tls.LoadX509KeyPair(config.MTLSClientCertFile, config.MTLSClientKeyFile)
			if err != nil {
				slog.Error("failed to load mTLS client certificate from file for WebSocket",
					"origin", originName,
					"cert_file", config.MTLSClientCertFile,
					"key_file", config.MTLSClientKeyFile,
					"error", err)
			} else {
				certSource = fmt.Sprintf("file:%s", config.MTLSClientCertFile)
			}
		} else {
			slog.Error("mTLS configuration incomplete for WebSocket: both certificate and key must be provided (either as files or base64 data)",
				"origin", originName)
		}

		if err == nil && certSource != "" {
			tlsConfig.Certificates = []tls.Certificate{cert}
			slog.Info("mTLS client certificate loaded for WebSocket",
				"origin", originName,
				"source", certSource)

			// Load CA certificate if provided for server verification (prefer base64 over file)
			var caCertData []byte
			var caCertSource string

			if config.MTLSCACertData != "" {
				// Load from base64-encoded data
				decoded, err := base64.StdEncoding.DecodeString(config.MTLSCACertData)
				if err != nil {
					slog.Error("failed to decode base64 mTLS CA certificate for WebSocket",
						"origin", originName,
						"error", err)
				} else {
					caCertData = decoded
					caCertSource = "base64_data"
				}
			} else if config.MTLSCACertFile != "" {
				// Load from file path
				var err error
				caCertData, err = os.ReadFile(config.MTLSCACertFile)
				if err != nil {
					slog.Error("failed to load mTLS CA certificate from file for WebSocket",
						"origin", originName,
						"ca_cert_file", config.MTLSCACertFile,
						"error", err)
				} else {
					caCertSource = fmt.Sprintf("file:%s", config.MTLSCACertFile)
				}
			}

			if len(caCertData) > 0 {
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCertData) {
					slog.Error("failed to parse mTLS CA certificate for WebSocket",
						"origin", originName,
						"source", caCertSource)
				} else {
					tlsConfig.RootCAs = caCertPool
					slog.Info("mTLS CA certificate loaded for WebSocket",
						"origin", originName,
						"source", caCertSource)
				}
			}
		}
	}

	// Set TLS config on dialer if any TLS settings were configured
	if tlsConfig.InsecureSkipVerify || len(tlsConfig.Certificates) > 0 || tlsConfig.RootCAs != nil {
		config.dialer.TLSClientConfig = tlsConfig
	}

	// Initialize connection pool unless explicitly disabled.
	// Default: enabled when path/query are not preserved (pooling doesn't work well with dynamic URLs)
	canUsePool := !config.StripBasePath && !config.PreserveQuery
	if canUsePool && !config.DisablePool {
		poolConfig := config.getPoolConfig()
		// Pass the dialer and origin ID to the pool so it can use the same TLS configuration and track metrics
		// Note: We don't have access to the origin ID here, so we'll use the URL as a fallback
		originID := config.URL // Use URL as origin identifier for metrics
		pool, err := transport.NewWebSocketConnectionPoolWithDialerAndOrigin(config.URL, poolConfig, config.dialer, originID)
		if err != nil {
			slog.Warn("websocket: failed to create connection pool, falling back to direct connections",
				"url", config.URL,
				"error", err)
		} else {
			config.pool = pool
			slog.Info("websocket: connection pool enabled",
				"url", config.URL,
				"max_connections", poolConfig.MaxConnections,
				"max_idle", poolConfig.MaxIdleConnections)
		}
	} else {
		slog.Debug("websocket: connection pool disabled due to strip_base_path or preserve_query",
			"url", config.URL,
			"strip_base_path", config.StripBasePath,
			"preserve_query", config.PreserveQuery)
	}

	return config, nil
}

// Init performs the init operation on the WebSocketAction.
func (c *WebSocketAction) Init(cfg *Config) error {
	if err := c.BaseAction.Init(cfg); err != nil {
		return err
	}

	if c.Budget != nil {
		var store ai.BudgetStore
		if cfg.l3Cache != nil {
			store = ai.NewCacherBudgetStore(cfg.l3Cache)
		} else {
			store = ai.NewInMemoryBudgetStore()
		}
		c.budgetEnforcer = ai.NewBudgetEnforcer(c.Budget, store)
	}

	return nil
}

// getPoolConfig creates a pool configuration from WebSocketConfig
func (c *WebSocketAction) getPoolConfig() *transport.WebSocketPoolConfig {
	config := transport.DefaultWebSocketPoolConfig()

	// Override defaults if specified
	if c.PoolMaxConnections > 0 {
		config.MaxConnections = c.PoolMaxConnections
	}
	if c.PoolMaxIdleConnections > 0 {
		config.MaxIdleConnections = c.PoolMaxIdleConnections
	}
	if c.PoolMaxLifetime.Duration > 0 {
		config.MaxLifetime = c.PoolMaxLifetime.Duration
	}
	if c.PoolMaxIdleTime.Duration > 0 {
		config.MaxIdleTime = c.PoolMaxIdleTime.Duration
	}
	config.AutoReconnect = !c.DisablePoolAutoReconnect
	if c.PoolReconnectDelay.Duration > 0 {
		config.ReconnectDelay = c.PoolReconnectDelay.Duration
	}
	if c.PoolMaxReconnectAttempts > 0 {
		config.MaxReconnectAttempts = c.PoolMaxReconnectAttempts
	}
	config.EnableCompression = c.EnableCompression
	config.ReadBufferSize = c.ReadBufferSize
	config.WriteBufferSize = c.WriteBufferSize
	if c.PingInterval.Duration > 0 {
		config.PingInterval = c.PingInterval.Duration
	}
	if c.PongTimeout.Duration > 0 {
		config.PongTimeout = c.PongTimeout.Duration
	}

	return config
}

// IsProxy reports whether the WebSocketAction is proxy.
func (c *WebSocketAction) IsProxy() bool {
	return false
}

// PoolStats returns pool statistics if the pool is enabled
func (c *WebSocketAction) PoolStats() map[string]interface{} {
	c.poolMu.Lock()
	pool := c.pool
	c.poolMu.Unlock()

	if pool == nil {
		return map[string]interface{}{
			"enabled": false,
			"reason":  "pool not enabled (strip_base_path or preserve_query is true)",
		}
	}

	return pool.Stats()
}

func (c *WebSocketAction) makeCheckOrigin() func(*http.Request) bool {
	if !c.CheckOrigin {
		// Allow all origins
		return func(r *http.Request) bool { return true }
	}

	if len(c.AllowedOrigins) == 0 {
		// Use default origin check (same host)
		return nil
	}

	// Check against allowed origins
	allowedMap := make(map[string]bool)
	for _, origin := range c.AllowedOrigins {
		allowedMap[origin] = true
	}

	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // No origin header
		}
		return allowedMap[origin]
	}
}

// Handler performs the handler operation on the WebSocketAction.
func (c *WebSocketAction) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("websocket: handling connection", "path", r.URL.Path)

		if isExtendedConnectWebSocketRequest(r) {
			c.handleExtendedConnectWebSocket(w, r)
			return
		}

		// Record connection start time for duration tracking
		startTime := time.Now()

		// Get origin for metrics
		origin := c.URL
		if origin == "" {
			origin = "unknown"
		}

		var session *websocketSessionState

		// Upgrade client connection
		clientConn, err := c.upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("websocket: failed to upgrade client connection", "error", err)
			return
		}
		defer func() {
			clientConn.Close()
			// Record WebSocket connection duration
			duration := time.Since(startTime).Seconds()
			metric.WebSocketConnectionDuration(origin, duration)
			if session != nil {
				emitWebSocketConnectionLifecycle(r.Context(), c.cfg, r, session.connectionID, session.provider, "closed", duration)
			}
		}()

		// Build backend URL
		backendURL := c.buildBackendURL(r)
		backendSubprotocols := c.resolveBackendSubprotocols(r, clientConn.Subprotocol())
		dialHeaders := c.buildBackendDialHeaders(r)
		canUsePool := c.canUsePooledConnection(backendURL, dialHeaders, backendSubprotocols)
		session = c.newSessionState(r, origin, backendURL)

		// Connect to backend - use pool if available, otherwise direct connection
		var backendConn *websocket.Conn
		var pooledConn *transport.PooledWebSocketConn
		var resp *http.Response

		c.poolMu.Lock()
		pool := c.pool
		c.poolMu.Unlock()

		if pool != nil && backendURL == c.URL && canUsePool {
			// Use connection pool
			slog.Debug("websocket: acquiring connection from pool", "url", backendURL)
			var err error
			pooledConn, err = pool.Acquire(r.Context())
			if err != nil {
				slog.Warn("websocket: failed to acquire connection from pool, falling back to direct connection",
					"url", backendURL,
					"error", err)
				// Fall through to direct connection
			} else {
				backendConn = pooledConn.Conn()
				slog.Debug("websocket: acquired connection from pool", "url", backendURL)
			}
		}

		// Fall back to direct connection if pool not available or failed
		if backendConn == nil {
			slog.Debug("websocket: connecting to backend directly", "url", backendURL)
			var err error
			dialer := *c.dialer
			dialer.Subprotocols = backendSubprotocols
			backendConn, resp, err = dialer.DialContext(r.Context(), backendURL, dialHeaders)
			if err != nil {
				// Check if this is a TLS handshake error
				errStr := err.Error()
				if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") || strings.Contains(errStr, "handshake") {
					// Determine TLS version and error type
					tlsVersion := "unknown"
					if c.dialer.TLSClientConfig != nil && c.dialer.TLSClientConfig.MinVersion != 0 {
						switch c.dialer.TLSClientConfig.MinVersion {
						case tls.VersionTLS10:
							tlsVersion = "1.0"
						case tls.VersionTLS11:
							tlsVersion = "1.1"
						case tls.VersionTLS12:
							tlsVersion = "1.2"
						case tls.VersionTLS13:
							tlsVersion = "1.3"
						}
					}

					errorType := "handshake_failed"
					if strings.Contains(errStr, "certificate") {
						errorType = "certificate_error"
					} else if strings.Contains(errStr, "timeout") {
						errorType = "timeout"
					} else if strings.Contains(errStr, "protocol") {
						errorType = "protocol_error"
					}

					originName := c.URL
					if originName == "" {
						originName = "unknown"
					}

					// Record TLS handshake failure metric
					metric.TLSHandshakeFailure(originName, errorType, tlsVersion)
				}

				slog.Error("websocket: failed to connect to backend", "url", backendURL, "error", err)
				if resp != nil {
					slog.Debug("websocket: backend response", "status", resp.Status)
				}
				_ = clientConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "Failed to connect to backend"))
				return
			}
			defer backendConn.Close()
		} else {
			// Release pooled connection when done
			defer func() {
				if pooledConn != nil {
					pool.Release(pooledConn)
					slog.Debug("websocket: released connection to pool", "url", backendURL)
				}
			}()
		}

		slog.Debug("websocket: connected to backend", "url", backendURL, "pooled", pooledConn != nil)
		emitWebSocketConnectionLifecycle(r.Context(), c.cfg, r, session.connectionID, session.provider, "opened", 0)

		if c.MaxFrameSize > 0 {
			clientConn.SetReadLimit(int64(c.MaxFrameSize))
			backendConn.SetReadLimit(int64(c.MaxFrameSize))
		}

		// Set up ping/pong if configured
		if c.PingInterval.Duration > 0 {
			c.setupPingPong(clientConn, backendConn)
		}

		// Proxy messages bidirectionally
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		var (
			wg        sync.WaitGroup
			closeOnce sync.Once
		)
		wg.Add(2)

		// Client -> Backend
		go func() {
			defer wg.Done()
			c.proxyMessages(ctx, cancel, &closeOnce, session, clientConn, backendConn, MessageDirectionClientToBackend)
		}()

		// Backend -> Client
		go func() {
			defer wg.Done()
			c.proxyMessages(ctx, cancel, &closeOnce, session, backendConn, clientConn, MessageDirectionBackendToClient)
		}()

		wg.Wait()
		slog.Debug("websocket: connection closed", "path", r.URL.Path)
	})
}

func (c *WebSocketAction) buildBackendURL(r *http.Request) string {
	backendURL, _ := url.Parse(c.URL)

	// Preserve path if configured
	if c.StripBasePath {
		backendURL.Path = r.URL.Path
	}

	// Preserve query if configured
	if c.PreserveQuery {
		backendURL.RawQuery = r.URL.RawQuery
	}

	return backendURL.String()
}

func (c *WebSocketAction) setupPingPong(clientConn, backendConn *websocket.Conn) {
	// Set pong handler for client
	if deadline := c.nextReadTimeout(); deadline > 0 {
		_ = clientConn.SetReadDeadline(time.Now().Add(deadline))
	}
	clientConn.SetPongHandler(func(string) error {
		if deadline := c.nextReadTimeout(); deadline > 0 {
			_ = clientConn.SetReadDeadline(time.Now().Add(deadline))
		}
		return nil
	})

	// Set pong handler for backend
	if deadline := c.nextReadTimeout(); deadline > 0 {
		_ = backendConn.SetReadDeadline(time.Now().Add(deadline))
	}
	backendConn.SetPongHandler(func(string) error {
		if deadline := c.nextReadTimeout(); deadline > 0 {
			_ = backendConn.SetReadDeadline(time.Now().Add(deadline))
		}
		return nil
	})

	// Start ping ticker for client
	go func() {
		ticker := time.NewTicker(c.PingInterval.Duration)
		defer ticker.Stop()
		for range ticker.C {
			if err := clientConn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		}
	}()

	// Start ping ticker for backend
	go func() {
		ticker := time.NewTicker(c.PingInterval.Duration)
		defer ticker.Stop()
		for range ticker.C {
			if err := backendConn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		}
	}()
}

func (c *WebSocketAction) nextReadTimeout() time.Duration {
	switch {
	case c.IdleTimeout.Duration > 0 && c.PongTimeout.Duration > 0:
		if c.IdleTimeout.Duration < c.PongTimeout.Duration {
			return c.IdleTimeout.Duration
		}
		return c.PongTimeout.Duration
	case c.IdleTimeout.Duration > 0:
		return c.IdleTimeout.Duration
	case c.PongTimeout.Duration > 0:
		return c.PongTimeout.Duration
	default:
		return 0
	}
}

func (c *WebSocketAction) proxyMessages(
	ctx context.Context,
	cancel context.CancelFunc,
	closeOnce *sync.Once,
	session *websocketSessionState,
	src, dst *websocket.Conn,
	direction string,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if deadline := c.nextReadTimeout(); deadline > 0 {
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

		msg := &MessageContext{
			Protocol:     MessageProtocolWebSocket,
			Phase:        MessagePhaseMessage,
			Direction:    direction,
			MessageType:  messageType,
			Path:         session.request.URL.Path,
			Headers:      session.request.Header.Clone(),
			Payload:      message,
			ConnectionID: session.connectionID,
			Provider:     session.provider,
			Request:      session.request,
			Metadata: map[string]any{
				"origin": session.origin,
			},
		}

		if err := c.processMessage(ctx, session, msg); err != nil {
			closeOnce.Do(func() {
				c.closeConnectionPair(src, dst, err)
				cancel()
			})
			return
		}

		if err := dst.WriteMessage(msg.MessageType, msg.Payload); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("websocket: write error", "direction", direction, "error", err)
			}
			cancel()
			return
		}

		metric.WebSocketFrameRelayed(session.origin, direction, session.provider)
		metric.WebSocketBytesTransferred(session.origin, direction, session.provider, len(msg.Payload))
		slog.Debug("websocket: message proxied", "direction", direction, "type", msg.MessageType, "size", len(msg.Payload), "event_type", msg.EventType, "provider", msg.Provider)
	}
}

func (c *WebSocketAction) processMessage(ctx context.Context, session *websocketSessionState, msg *MessageContext) error {
	if c.MaxFrameSize > 0 && len(msg.Payload) > c.MaxFrameSize {
		metric.WebSocketPolicyViolation(session.origin, "max_frame_size")
		return newWebSocketCloseError(websocket.CloseMessageTooBig, "websocket frame too large", nil)
	}

	if msg.Provider == "" {
		msg.Provider = session.provider
	}

	if msg.Provider == WebSocketProviderOpenAI && isWebSocketJSONTextMessage(msg) {
		msg.EventType = extractWebSocketEventType(msg.Payload)
	}

	if msg.Direction == MessageDirectionClientToBackend && session.budget != nil && isOpenAIClientGenerationEvent(msg.EventType) {
		if err := session.budget.Check(ctx, session.budgetScope, 0); err != nil {
			c.emitWebSocketBudgetExceeded(ctx, session, err)
			metric.WebSocketPolicyViolation(session.origin, "budget")
			return newWebSocketCloseError(websocket.ClosePolicyViolation, "token budget exceeded", err)
		}
	}

	handler := c.buildMessageHandler()
	if handler != nil {
		if err := handler(ctx, msg); err != nil {
			if closeErr, ok := websocketCloseError(err); ok {
				reason := closeErr.Reason
				if reason == "" {
					reason = "policy"
				}
				metric.WebSocketPolicyViolation(session.origin, reason)
			}
			return err
		}
	}

	c.observeMessage(ctx, session, msg)
	return nil
}

func (c *WebSocketAction) buildMessageHandler() MessageHandler {
	if c.cfg == nil || len(c.cfg.policies) == 0 {
		return nil
	}

	handler := MessageHandler(func(_ context.Context, _ *MessageContext) error {
		return nil
	})
	for i := len(c.cfg.policies) - 1; i >= 0; i-- {
		policy, ok := c.cfg.policies[i].(MessagePolicyConfig)
		if !ok {
			continue
		}
		handler = policy.ApplyMessage(handler)
	}

	return handler
}

func (c *WebSocketAction) buildBackendDialHeaders(r *http.Request) http.Header {
	headers := make(http.Header)
	for name, values := range r.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Connection", "Upgrade", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions":
			continue
		case "Sec-Websocket-Protocol":
			continue
		}
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return headers
}

func (c *WebSocketAction) canUsePooledConnection(backendURL string, headers http.Header, backendSubprotocols []string) bool {
	if len(backendSubprotocols) > 0 {
		return false
	}
	if backendURL != c.URL {
		return false
	}
	for name := range headers {
		switch http.CanonicalHeaderKey(name) {
		case "Authorization", "Cookie", "Origin", "X-Api-Key":
			return false
		}
	}
	return true
}

func (c *WebSocketAction) resolveBackendSubprotocols(r *http.Request, negotiatedSubprotocol string) []string {
	if strings.EqualFold(c.Provider, WebSocketProviderOpenAI) {
		protocols := websocketSubprotocols(r)
		if len(protocols) > 0 {
			return protocols
		}
	}
	if negotiatedSubprotocol != "" {
		return []string{negotiatedSubprotocol}
	}
	return nil
}

func (c *WebSocketAction) newSessionState(r *http.Request, origin string, backendURL string) *websocketSessionState {
	provider := c.Provider
	if provider == "" {
		provider = inferWebSocketProvider(backendURL)
	}

	connectionID := fmt.Sprintf("ws-%d", c.connSeq.Add(1))
	return &websocketSessionState{
		action:       c,
		request:      r,
		origin:       origin,
		provider:     provider,
		connectionID: connectionID,
		budget:       c.budgetEnforcer,
		budgetScope:  c.budgetScopeKey(r.Context()),
	}
}

func inferWebSocketProvider(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	path := strings.ToLower(u.Path)
	if strings.Contains(host, "openai.com") && (strings.HasPrefix(path, "/v1/realtime") || strings.HasPrefix(path, "/v1/responses")) {
		return WebSocketProviderOpenAI
	}
	return ""
}

func (c *WebSocketAction) budgetScopeKey(ctx context.Context) string {
	if rd := reqctx.GetRequestData(ctx); rd != nil && rd.Config != nil {
		if wid := reqctx.ConfigParams(rd.Config).GetWorkspaceID(); wid != "" {
			return wid
		}
	}
	if c.cfg != nil && c.cfg.WorkspaceID != "" {
		return c.cfg.WorkspaceID
	}
	return "default"
}

func (c *WebSocketAction) observeMessage(ctx context.Context, session *websocketSessionState, msg *MessageContext) {
	if msg.Provider == WebSocketProviderOpenAI && isOpenAIUsageEvent(msg.EventType) && session.budget != nil {
		if totalTokens, ok := extractOpenAIUsageTokens(msg.EventType, msg.Payload); ok && totalTokens > 0 {
			if err := session.budget.Record(ctx, session.budgetScope, totalTokens, 0); err != nil {
				slog.Warn("websocket: failed to record budget usage", "connection_id", session.connectionID, "error", err)
			}
		}
	}

	if strings.Contains(msg.EventType, "function_call") {
		slog.Info("websocket: observed tool call event", "connection_id", session.connectionID, "event_type", msg.EventType, "direction", msg.Direction)
		metric.WebSocketToolCallEvent(session.origin, msg.Direction, session.provider)
		emitWebSocketToolCall(ctx, c.cfg, session.request, session.connectionID, session.provider, msg.Direction, msg.EventType)
	}
}

func (c *WebSocketAction) emitWebSocketBudgetExceeded(ctx context.Context, session *websocketSessionState, err error) {
	if c.cfg == nil || !c.cfg.EventEnabled("ai.budget.exceeded") {
		return
	}

	event := &events.AIBudgetExceeded{
		EventBase:   events.NewBase("ai.budget.exceeded", events.SeverityWarning, c.cfg.WorkspaceID, reqctx.GetRequestID(ctx)),
		Scope:       "workspace",
		ScopeValue:  session.budgetScope,
		Period:      err.Error(),
		ActionTaken: "close",
	}
	event.Origin = ConfigOriginContext(c.cfg)
	events.Emit(ctx, c.cfg.WorkspaceID, event)
}

func (c *WebSocketAction) closeConnectionPair(src, dst *websocket.Conn, err error) {
	if closeErr, ok := websocketCloseError(err); ok {
		deadline := time.Now().Add(5 * time.Second)
		closePayload := websocket.FormatCloseMessage(closeErr.Code, closeErr.Reason)
		_ = src.WriteControl(websocket.CloseMessage, closePayload, deadline)
		_ = dst.WriteControl(websocket.CloseMessage, closePayload, deadline)
		return
	}

	if err != nil {
		slog.Error("websocket: closing connection pair after error", "error", err)
	}
}
