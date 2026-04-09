package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

func TestWebSocketAction_ConnectionPool(t *testing.T) {
	// Create a simple WebSocket echo server
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Failed to upgrade: %v", err)
			return
		}
		defer conn.Close()

		// Echo messages
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if err := conn.WriteMessage(messageType, message); err != nil {
				break
			}
		}
	}))
	defer server.Close()

	// Convert http:// to ws://
	wsURL := "ws" + server.URL[4:]

	// Create WebSocket action with pooling enabled (default behavior)
	configJSON := `{
		"type": "websocket",
		"url": "` + wsURL + `",
		"disable_pool": false,
		"pool_max_connections": 5,
		"pool_max_idle_connections": 2,
		"pool_max_lifetime": "1h",
		"pool_max_idle_time": "1m",
		"disable_pool_auto_reconnect": false
	}`

	action, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create WebSocket action: %v", err)
	}

	wsAction := action.(*WebSocketAction)

	// Verify pool was created
	if wsAction.pool == nil {
		t.Fatal("Expected connection pool to be created, but it was nil")
	}

	// Test acquiring connections from pool
	ctx := context.Background()
	conn1, err := wsAction.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire connection 1: %v", err)
	}
	defer wsAction.pool.Release(conn1)

	conn2, err := wsAction.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire connection 2: %v", err)
	}
	defer wsAction.pool.Release(conn2)

	// Verify we got different connections
	if conn1 == conn2 {
		t.Error("Expected different connections, but got the same")
	}

	// Verify pool statistics
	stats := wsAction.pool.Stats()
	if stats["total_acquired"].(int64) < 2 {
		t.Errorf("Expected at least 2 acquisitions, got %d", stats["total_acquired"])
	}

	// Release connections and verify they can be reused
	wsAction.pool.Release(conn1)
	wsAction.pool.Release(conn2)

	// Acquire again - should reuse from pool
	conn3, err := wsAction.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire connection 3: %v", err)
	}
	defer wsAction.pool.Release(conn3)

	// Verify pool size
	poolSize := wsAction.pool.Size()
	if poolSize < 1 {
		t.Errorf("Expected pool size >= 1, got %d", poolSize)
	}

	// Close pool
	if err := wsAction.pool.Close(); err != nil {
		t.Errorf("Failed to close pool: %v", err)
	}
}

func TestWebSocketAction_PoolDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
	}))
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Create WebSocket action with pool explicitly disabled.
	configJSON := `{
		"type": "websocket",
		"url": "` + wsURL + `",
		"disable_pool": true
	}`

	action, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create WebSocket action: %v", err)
	}

	wsAction := action.(*WebSocketAction)

	// Verify pool was NOT created when explicitly disabled
	if wsAction.pool != nil {
		t.Error("Expected connection pool to be nil when disable_pool is enabled, but it was created")
	}
}

func TestWebSocketAction_PoolWithStripBasePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
	}))
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Create WebSocket action with strip_base_path (should disable pool)
	configJSON := `{
		"type": "websocket",
		"url": "` + wsURL + `",
		"strip_base_path": true,
		"disable_pool": false
	}`

	action, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create WebSocket action: %v", err)
	}

	wsAction := action.(*WebSocketAction)

	// Verify pool was NOT created when strip_base_path is enabled
	if wsAction.pool != nil {
		t.Error("Expected connection pool to be nil when strip_base_path is enabled, but it was created")
	}
}

func TestWebSocketAction_PoolConfigDefaults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
	}))
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Create WebSocket action with minimal config (should use defaults)
	// Pool is enabled by default when strip_base_path and preserve_query are false
	configJSON := `{
		"type": "websocket",
		"url": "` + wsURL + `"
	}`

	action, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create WebSocket action: %v", err)
	}

	wsAction := action.(*WebSocketAction)

	// Verify pool was created with defaults
	if wsAction.pool == nil {
		t.Fatal("Expected connection pool to be created with defaults, but it was nil")
	}

	// Verify default pool configuration
	poolConfig := wsAction.getPoolConfig()
	defaultConfig := transport.DefaultWebSocketPoolConfig()

	if poolConfig.MaxConnections != defaultConfig.MaxConnections {
		t.Errorf("Expected MaxConnections %d, got %d", defaultConfig.MaxConnections, poolConfig.MaxConnections)
	}
	if poolConfig.MaxIdleConnections != defaultConfig.MaxIdleConnections {
		t.Errorf("Expected MaxIdleConnections %d, got %d", defaultConfig.MaxIdleConnections, poolConfig.MaxIdleConnections)
	}
	if !poolConfig.AutoReconnect {
		t.Error("Expected AutoReconnect to be enabled by default")
	}
}

func TestWebSocketAction_PoolConnectionReuse(t *testing.T) {
	// Create a simple WebSocket echo server
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Keep connection alive for a short time
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Create WebSocket action with small pool
	configJSON := `{
		"type": "websocket",
		"url": "` + wsURL + `",
		"disable_pool": false,
		"pool_max_connections": 3,
		"pool_max_idle_connections": 2
	}`

	action, err := NewWebSocketAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create WebSocket action: %v", err)
	}

	wsAction := action.(*WebSocketAction)

	ctx := context.Background()

	// Acquire and release multiple connections
	for i := 0; i < 5; i++ {
		conn, err := wsAction.pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Failed to acquire connection %d: %v", i, err)
		}

		// Verify connection is valid
		if conn.IsClosed() {
			t.Errorf("Connection %d is closed immediately after acquisition", i)
		}

		// Release connection
		wsAction.pool.Release(conn)

		// Small delay to allow pool processing
		time.Sleep(10 * time.Millisecond)
	}

	// Verify pool statistics
	stats := wsAction.pool.Stats()
	t.Logf("Pool stats: %+v", stats)

	if stats["total_acquired"].(int64) != 5 {
		t.Errorf("Expected 5 acquisitions, got %d", stats["total_acquired"])
	}
	if stats["total_released"].(int64) != 5 {
		t.Errorf("Expected 5 releases, got %d", stats["total_released"])
	}

	// Verify pool size is within limits
	poolSize := wsAction.pool.Size()
	if poolSize > 3 {
		t.Errorf("Expected pool size <= 3, got %d", poolSize)
	}

	// Close pool
	if err := wsAction.pool.Close(); err != nil {
		t.Errorf("Failed to close pool: %v", err)
	}
}
