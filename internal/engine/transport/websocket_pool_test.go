package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestNewWebSocketConnectionPool(t *testing.T) {
	config := DefaultWebSocketPoolConfig()
	pool, err := NewWebSocketConnectionPool("ws://localhost:8080", config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	if pool.Size() != 0 {
		t.Errorf("expected initial size 0, got %d", pool.Size())
	}
}

func TestNewWebSocketConnectionPool_InvalidURL(t *testing.T) {
	config := DefaultWebSocketPoolConfig()
	_, err := NewWebSocketConnectionPool("invalid://url", config)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestNewWebSocketConnectionPool_InvalidScheme(t *testing.T) {
	config := DefaultWebSocketPoolConfig()
	_, err := NewWebSocketConnectionPool("http://localhost:8080", config)
	if err == nil {
		t.Error("expected error for non-WebSocket scheme")
	}
}

func TestNewWebSocketConnectionPool_InvalidConfig(t *testing.T) {
	config := &WebSocketPoolConfig{
		MaxConnections: 0,
	}
	_, err := NewWebSocketConnectionPool("ws://localhost:8080", config)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestWebSocketPool_AcquireRelease(t *testing.T) {
	// Create test WebSocket server
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo server
		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(messageType, p); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	// Create pool
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()
	config.MaxConnections = 5
	config.MaxIdleConnections = 2

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	// Acquire connection
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	if pool.Size() != 1 {
		t.Errorf("expected pool size 1, got %d", pool.Size())
	}

	// Test write/read
	testMsg := []byte("hello")
	if err := conn.WriteMessage(websocket.TextMessage, testMsg); err != nil {
		t.Fatalf("failed to write message: %v", err)
	}

	messageType, p, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}

	if messageType != websocket.TextMessage {
		t.Errorf("expected text message, got %d", messageType)
	}

	if string(p) != string(testMsg) {
		t.Errorf("expected %s, got %s", testMsg, p)
	}

	// Release connection
	pool.Release(conn)

	// Connection should be in idle pool
	if pool.IdleCount() != 1 {
		t.Errorf("expected 1 idle connection, got %d", pool.IdleCount())
	}

	// Acquire again - should reuse connection
	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	if conn2 != conn {
		t.Error("expected to reuse same connection")
	}

	if pool.IdleCount() != 0 {
		t.Errorf("expected 0 idle connections after reuse, got %d", pool.IdleCount())
	}

	conn2.Close()
}

func TestWebSocketPool_MaxConnections(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second) // Keep connection alive
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()
	config.MaxConnections = 2

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Acquire max connections
	conn1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection 1: %v", err)
	}

	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection 2: %v", err)
	}

	// Try to acquire one more - should fail
	_, err = pool.Acquire(ctx)
	if err != ErrPoolExhausted {
		t.Errorf("expected ErrPoolExhausted, got %v", err)
	}

	// Release one connection
	pool.Release(conn1)

	// Now we should be able to acquire again
	conn3, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection after release: %v", err)
	}

	conn2.Close()
	conn3.Close()
}

func TestWebSocketPool_MaxIdleConnections(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()
	config.MaxConnections = 5
	config.MaxIdleConnections = 2

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Create 3 connections
	conns := make([]*PooledWebSocketConn, 3)
	for i := 0; i < 3; i++ {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire connection %d: %v", i, err)
		}
		conns[i] = conn
	}

	// Release all 3
	for _, conn := range conns {
		pool.Release(conn)
	}

	// Only 2 should be in idle pool (max idle is 2)
	// The third one should be closed
	if pool.IdleCount() > 2 {
		t.Errorf("expected max 2 idle connections, got %d", pool.IdleCount())
	}
}

func TestWebSocketPool_Stats(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()

	// Acquire and release
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}
	pool.Release(conn)

	stats := pool.Stats()

	if stats["total_created"].(int64) != 1 {
		t.Errorf("expected total_created 1, got %v", stats["total_created"])
	}

	if stats["total_acquired"].(int64) != 1 {
		t.Errorf("expected total_acquired 1, got %v", stats["total_acquired"])
	}

	if stats["total_released"].(int64) != 1 {
		t.Errorf("expected total_released 1, got %v", stats["total_released"])
	}
}

func TestWebSocketPool_Close(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}
	pool.Release(conn)

	// Close pool
	if err := pool.Close(); err != nil {
		t.Fatalf("failed to close pool: %v", err)
	}

	if pool.Size() != 0 {
		t.Errorf("expected size 0 after close, got %d", pool.Size())
	}

	// Try to acquire from closed pool
	_, err = pool.Acquire(ctx)
	if err != ErrPoolClosed {
		t.Errorf("expected ErrPoolClosed, got %v", err)
	}
}

func TestPooledWebSocketConn_Close(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	initialSize := pool.Size()

	// Close connection
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close connection: %v", err)
	}

	if !conn.IsClosed() {
		t.Error("connection should be marked as closed")
	}

	// Pool size should decrease
	if pool.Size() >= initialSize {
		t.Errorf("expected pool size to decrease after closing connection")
	}

	// Try to write to closed connection
	err = conn.WriteMessage(websocket.TextMessage, []byte("test"))
	if err != ErrConnClosed {
		t.Errorf("expected ErrConnClosed, got %v", err)
	}
}

func TestPooledWebSocketConn_MaxLifetime(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()
	config.MaxLifetime = 100 * time.Millisecond

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	// Release immediately
	pool.Release(conn)

	// Wait for max lifetime to expire
	time.Sleep(150 * time.Millisecond)

	// Try to acquire - should create new connection because old one expired
	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	if conn2 == conn {
		t.Error("expected new connection due to max lifetime expiration")
	}

	conn2.Close()
}

func TestPooledWebSocketConn_MaxIdleTime(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	config := DefaultWebSocketPoolConfig()
	config.MaxIdleTime = 100 * time.Millisecond

	pool, err := NewWebSocketConnectionPool(wsURL, config)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	pool.Release(conn)

	// Wait for idle time to expire
	time.Sleep(150 * time.Millisecond)

	// Try to acquire - should create new connection
	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}

	if conn2 == conn {
		t.Error("expected new connection due to max idle time expiration")
	}

	conn2.Close()
}

func TestDefaultWebSocketPoolConfig(t *testing.T) {
	config := DefaultWebSocketPoolConfig()

	if config.MaxConnections <= 0 {
		t.Error("max connections should be positive")
	}

	if config.MaxIdleConnections > config.MaxConnections {
		t.Error("max idle should not exceed max connections")
	}

	if config.ReadBufferSize <= 0 {
		t.Error("read buffer size should be positive")
	}

	if config.WriteBufferSize <= 0 {
		t.Error("write buffer size should be positive")
	}
}
