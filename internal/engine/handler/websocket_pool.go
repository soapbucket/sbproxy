// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

var (
	// ErrPoolClosed is a sentinel error for pool closed conditions.
	ErrPoolClosed    = errors.New("connection pool is closed")
	// ErrPoolExhausted is a sentinel error for pool exhausted conditions.
	ErrPoolExhausted = errors.New("connection pool exhausted")
	// ErrConnClosed is a sentinel error for conn closed conditions.
	ErrConnClosed    = errors.New("connection closed")
	// ErrInvalidConfig is a sentinel error for invalid config conditions.
	ErrInvalidConfig = errors.New("invalid pool configuration")
)

// WebSocketPoolConfig configures a WebSocket connection pool
type WebSocketPoolConfig struct {
	// Maximum number of connections in the pool
	MaxConnections int

	// Maximum number of idle connections
	MaxIdleConnections int

	// Maximum lifetime of a connection
	MaxLifetime time.Duration

	// Maximum idle time before closing
	MaxIdleTime time.Duration

	// Enable automatic reconnection
	AutoReconnect bool

	// Reconnect delay
	ReconnectDelay time.Duration

	// Maximum reconnect attempts (0 = unlimited)
	MaxReconnectAttempts int

	// Enable compression
	EnableCompression bool

	// Read buffer size
	ReadBufferSize int

	// Write buffer size
	WriteBufferSize int

	// Ping interval for keep-alive
	PingInterval time.Duration

	// Pong timeout
	PongTimeout time.Duration
}

// DefaultWebSocketPoolConfig returns default configuration
func DefaultWebSocketPoolConfig() *WebSocketPoolConfig {
	return &WebSocketPoolConfig{
		MaxConnections:       100,
		MaxIdleConnections:   10,
		MaxLifetime:          1 * time.Hour,
		MaxIdleTime:          5 * time.Minute,
		AutoReconnect:        true,
		ReconnectDelay:       5 * time.Second,
		MaxReconnectAttempts: 3,
		EnableCompression:    true,
		ReadBufferSize:       4096,
		WriteBufferSize:      4096,
		PingInterval:         30 * time.Second,
		PongTimeout:          10 * time.Second,
	}
}

// PooledWebSocketConn wraps a WebSocket connection with pool metadata
type PooledWebSocketConn struct {
	conn           *websocket.Conn
	pool           *WebSocketConnectionPool
	target         string
	createdAt      time.Time
	lastUsedAt     time.Time
	reconnectCount int
	closed         bool
	mu             sync.RWMutex

	// Ping/pong for keep-alive
	stopPing chan struct{}
}

// WebSocketConnectionPool manages a pool of WebSocket connections
type WebSocketConnectionPool struct {
	config *WebSocketPoolConfig
	target string
	dialer *websocket.Dialer

	mu          sync.RWMutex
	connections map[*PooledWebSocketConn]bool
	idle        chan *PooledWebSocketConn
	closed      bool

	// Statistics
	stats struct {
		mu              sync.RWMutex
		totalCreated    int64
		totalClosed     int64
		totalReconnects int64
		totalAcquired   int64
		totalReleased   int64
	}
}

// NewWebSocketConnectionPool creates a new WebSocket connection pool
func NewWebSocketConnectionPool(target string, config *WebSocketPoolConfig) (*WebSocketConnectionPool, error) {
	return NewWebSocketConnectionPoolWithDialer(target, config, nil)
}

// NewWebSocketConnectionPoolWithDialer creates a new WebSocket connection pool with a custom dialer
func NewWebSocketConnectionPoolWithDialer(target string, config *WebSocketPoolConfig, customDialer *websocket.Dialer) (*WebSocketConnectionPool, error) {
	if config == nil {
		config = DefaultWebSocketPoolConfig()
	}

	// Validate configuration
	if config.MaxConnections <= 0 {
		return nil, fmt.Errorf("%w: MaxConnections must be positive", ErrInvalidConfig)
	}
	if config.MaxIdleConnections > config.MaxConnections {
		config.MaxIdleConnections = config.MaxConnections
	}

	// Parse target URL
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if targetURL.Scheme != "ws" && targetURL.Scheme != "wss" {
		return nil, fmt.Errorf("invalid scheme: %s (must be ws or wss)", targetURL.Scheme)
	}

	var dialer *websocket.Dialer
	if customDialer != nil {
		// Use custom dialer, but override buffer sizes and compression from config
		dialer = &websocket.Dialer{
			ReadBufferSize:    config.ReadBufferSize,
			WriteBufferSize:   config.WriteBufferSize,
			EnableCompression: config.EnableCompression,
			HandshakeTimeout:  customDialer.HandshakeTimeout,
			TLSClientConfig:   customDialer.TLSClientConfig,
			Subprotocols:      customDialer.Subprotocols,
		}
		if dialer.HandshakeTimeout == 0 {
			dialer.HandshakeTimeout = 10 * time.Second
		}
	} else {
		// Create default dialer
		dialer = &websocket.Dialer{
			ReadBufferSize:    config.ReadBufferSize,
			WriteBufferSize:   config.WriteBufferSize,
			EnableCompression: config.EnableCompression,
			HandshakeTimeout:  10 * time.Second,
		}
	}

	pool := &WebSocketConnectionPool{
		config:      config,
		target:      target,
		dialer:      dialer,
		connections: make(map[*PooledWebSocketConn]bool),
		idle:        make(chan *PooledWebSocketConn, config.MaxIdleConnections),
	}

	slog.Info("WebSocket connection pool created",
		"target", target,
		"max_connections", config.MaxConnections,
		"max_idle", config.MaxIdleConnections)

	return pool, nil
}

// Acquire gets a connection from the pool
func (p *WebSocketConnectionPool) Acquire(ctx context.Context) (*PooledWebSocketConn, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	p.mu.RUnlock()

	p.stats.mu.Lock()
	p.stats.totalAcquired++
	p.stats.mu.Unlock()

	// Try to get an idle connection first
	select {
	case conn := <-p.idle:
		if p.isConnectionValid(conn) {
			conn.mu.Lock()
			conn.lastUsedAt = time.Now()
			conn.mu.Unlock()
			slog.Debug("acquired idle WebSocket connection", "target", p.target)
			return conn, nil
		}
		// Connection is invalid, close it and create new one
		conn.Close()
	default:
		// No idle connections available
	}

	// Check if we can create a new connection
	p.mu.RLock()
	canCreate := len(p.connections) < p.config.MaxConnections
	p.mu.RUnlock()

	if !canCreate {
		// Record connection pool exhaustion metric
		origin := "unknown" // WebSocket pool doesn't have direct origin access
		metric.ConnectionPoolExhaustion(origin, "websocket")
		return nil, ErrPoolExhausted
	}

	// Create new connection
	return p.createConnection(ctx)
}

// Release returns a connection to the pool
func (p *WebSocketConnectionPool) Release(conn *PooledWebSocketConn) {
	if conn == nil {
		return
	}

	p.stats.mu.Lock()
	p.stats.totalReleased++
	p.stats.mu.Unlock()

	conn.mu.Lock()
	conn.lastUsedAt = time.Now()
	isClosed := conn.closed
	conn.mu.Unlock()

	if isClosed || !p.isConnectionValid(conn) {
		conn.Close()
		return
	}

	// Try to return to idle pool
	select {
	case p.idle <- conn:
		slog.Debug("WebSocket connection returned to pool", "target", p.target)
	default:
		// Idle pool is full, close the connection
		conn.Close()
		slog.Debug("idle pool full, closing WebSocket connection", "target", p.target)
	}
}

// createConnection creates a new WebSocket connection
func (p *WebSocketConnectionPool) createConnection(ctx context.Context) (*PooledWebSocketConn, error) {
	slog.Debug("creating new WebSocket connection", "target", p.target)

	conn, _, err := p.dialer.DialContext(ctx, p.target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	pooledConn := &PooledWebSocketConn{
		conn:       conn,
		pool:       p,
		target:     p.target,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		stopPing:   make(chan struct{}),
	}

	// Configure ping/pong
	if p.config.PingInterval > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(p.config.PongTimeout))
		conn.SetPongHandler(func(string) error {
			_ = conn.SetReadDeadline(time.Now().Add(p.config.PongTimeout))
			return nil
		})
		go pooledConn.startPingLoop()
	}

	// Add to pool
	p.mu.Lock()
	p.connections[pooledConn] = true
	poolSize := len(p.connections)
	p.mu.Unlock()

	// Update active connections metric (client-side WebSocket pool connections)
	metric.ActiveConnectionsSet("websocket_pool", "websocket", int64(poolSize))

	p.stats.mu.Lock()
	p.stats.totalCreated++
	p.stats.mu.Unlock()

	slog.Info("WebSocket connection created",
		"target", p.target,
		"pool_size", p.Size())

	return pooledConn, nil
}

// isConnectionValid checks if a connection is still valid
func (p *WebSocketConnectionPool) isConnectionValid(conn *PooledWebSocketConn) bool {
	conn.mu.RLock()
	defer conn.mu.RUnlock()

	if conn.closed {
		return false
	}

	now := time.Now()

	// Check max lifetime
	if p.config.MaxLifetime > 0 && now.Sub(conn.createdAt) > p.config.MaxLifetime {
		slog.Debug("WebSocket connection exceeded max lifetime", "target", p.target)
		return false
	}

	// Check max idle time
	if p.config.MaxIdleTime > 0 && now.Sub(conn.lastUsedAt) > p.config.MaxIdleTime {
		slog.Debug("WebSocket connection exceeded max idle time", "target", p.target)
		return false
	}

	return true
}

// Close closes all connections in the pool
func (p *WebSocketConnectionPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	// Close all connections
	p.mu.RLock()
	connections := make([]*PooledWebSocketConn, 0, len(p.connections))
	for conn := range p.connections {
		connections = append(connections, conn)
	}
	p.mu.RUnlock()

	for _, conn := range connections {
		conn.Close()
	}

	close(p.idle)

	slog.Info("WebSocket connection pool closed", "target", p.target)
	return nil
}

// Size returns the total number of connections in the pool
func (p *WebSocketConnectionPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.connections)
}

// IdleCount returns the number of idle connections
func (p *WebSocketConnectionPool) IdleCount() int {
	return len(p.idle)
}

// Stats returns pool statistics
func (p *WebSocketConnectionPool) Stats() map[string]interface{} {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()

	return map[string]interface{}{
		"target":           p.target,
		"total_created":    p.stats.totalCreated,
		"total_closed":     p.stats.totalClosed,
		"total_reconnects": p.stats.totalReconnects,
		"total_acquired":   p.stats.totalAcquired,
		"total_released":   p.stats.totalReleased,
		"current_size":     p.Size(),
		"idle_count":       p.IdleCount(),
	}
}

// PooledWebSocketConn methods

// WriteMessage writes a message to the WebSocket
func (c *PooledWebSocketConn) WriteMessage(messageType int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrConnClosed
	}

	return c.conn.WriteMessage(messageType, data)
}

// ReadMessage reads a message from the WebSocket
func (c *PooledWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()

	if closed {
		return 0, nil, ErrConnClosed
	}

	return c.conn.ReadMessage()
}

// Close closes the connection and removes it from the pool
func (c *PooledWebSocketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// Stop ping loop
	close(c.stopPing)

	// Close underlying connection
	err := c.conn.Close()

	// Remove from pool
	c.pool.mu.Lock()
	delete(c.pool.connections, c)
	poolSize := len(c.pool.connections)
	c.pool.mu.Unlock()

	// Update active connections metric (client-side WebSocket pool connections)
	metric.ActiveConnectionsSet("websocket_pool", "websocket", int64(poolSize))

	c.pool.stats.mu.Lock()
	c.pool.stats.totalClosed++
	c.pool.stats.mu.Unlock()

	slog.Debug("WebSocket connection closed",
		"target", c.target,
		"pool_size", c.pool.Size())

	return err
}

// Reconnect attempts to reconnect the WebSocket
func (c *PooledWebSocketConn) Reconnect(ctx context.Context) error {
	if !c.pool.config.AutoReconnect {
		return errors.New("auto-reconnect disabled")
	}

	c.mu.Lock()
	if c.reconnectCount >= c.pool.config.MaxReconnectAttempts && c.pool.config.MaxReconnectAttempts > 0 {
		c.mu.Unlock()
		return fmt.Errorf("max reconnect attempts reached: %d", c.reconnectCount)
	}
	c.reconnectCount++
	reconnectCount := c.reconnectCount
	c.mu.Unlock()

	slog.Info("attempting to reconnect WebSocket",
		"target", c.target,
		"attempt", reconnectCount)

	// Wait before reconnecting
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(c.pool.config.ReconnectDelay):
	}

	// Close old connection
	if c.conn != nil {
		c.conn.Close()
	}

	// Create new connection
	conn, _, err := c.pool.dialer.DialContext(ctx, c.target, nil)
	if err != nil {
		return fmt.Errorf("reconnect failed: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.closed = false
	c.lastUsedAt = time.Now()
	c.mu.Unlock()

	c.pool.stats.mu.Lock()
	c.pool.stats.totalReconnects++
	c.pool.stats.mu.Unlock()

	slog.Info("WebSocket reconnected",
		"target", c.target,
		"attempt", reconnectCount)

	return nil
}

// startPingLoop sends periodic ping messages
func (c *PooledWebSocketConn) startPingLoop() {
	ticker := time.NewTicker(c.pool.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				return
			}

			err := c.conn.WriteControl(
				websocket.PingMessage,
				[]byte{},
				time.Now().Add(10*time.Second),
			)
			c.mu.Unlock()

			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					slog.Debug("ping failed, closing connection",
						"target", c.target,
						"error", err)
				}
				c.Close()
				return
			}

		case <-c.stopPing:
			return
		}
	}
}

// SetReadDeadline sets the read deadline on the connection
func (c *PooledWebSocketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrConnClosed
	}

	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the connection
func (c *PooledWebSocketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrConnClosed
	}

	return c.conn.SetWriteDeadline(t)
}

// LocalAddr returns the local network address
func (c *PooledWebSocketConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil
	}

	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (c *PooledWebSocketConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil
	}

	return c.conn.RemoteAddr()
}

// IsClosed returns whether the connection is closed
func (c *PooledWebSocketConn) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// Conn returns the underlying WebSocket connection
// This should be used carefully as it bypasses pool management
func (c *PooledWebSocketConn) Conn() *websocket.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}
