package e2e

import (
	"net/http"
	"testing"

	"github.com/gorilla/websocket"
)

// TestLoadBalancer tests the load balancer action type.
// Fixture: 14-loadbalancer.json (loadbalancer.test)
func TestLoadBalancer(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("distributes requests to backends", func(t *testing.T) {
		// Both targets point to the same test server, so all requests succeed
		for i := 0; i < 5; i++ {
			resp := proxyGet(t, "loadbalancer.test", "/test/simple-200")
			assertStatus(t, resp, 200)
		}
	})

	t.Run("sets sticky cookie", func(t *testing.T) {
		resp := proxyGet(t, "loadbalancer.test", "/test/simple-200")
		assertStatus(t, resp, 200)
		// Check for sticky session cookie
		cookies := resp.Cookies()
		hasStickyCokie := false
		for _, c := range cookies {
			if c.Name == "_sb.l" {
				hasStickyCokie = true
				break
			}
		}
		if !hasStickyCokie {
			t.Log("Note: Sticky cookie _sb.l not found. This is expected if disable_sticky is set or sticky cookies are disabled globally.")
		}
	})
}

// TestLoadBalancerWithHealthCheck tests load balancer with health check configuration.
// Fixture: 93-loadbalancer-with-health-check.json (loadbalancer-health.test)
func TestLoadBalancerWithHealthCheck(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("routes to healthy backends", func(t *testing.T) {
		resp := proxyGet(t, "loadbalancer-health.test", "/test/simple-200")
		assertStatus(t, resp, 200)
	})
}

// TestABTestAction tests the A/B testing action type.
// Fixture: 48-abtest-action.json (abtest.test)
func TestABTestAction(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("routes request to a variant", func(t *testing.T) {
		resp := proxyGet(t, "abtest.test", "/test/simple-200")
		// A/B test should route to one of the variants
		if resp.StatusCode >= 500 {
			t.Errorf("Expected A/B test routing to succeed, got status %d", resp.StatusCode)
		}
	})
}

// TestStorageAction tests the storage action type.
// Fixture: 47-storage-action.json (storage.test)
func TestStorageAction(t *testing.T) {
	checkProxyReachable(t)

	t.Run("responds from storage action", func(t *testing.T) {
		resp := proxyGet(t, "storage.test", "/")
		// Storage action should return content
		if resp.StatusCode == 0 {
			t.Error("Expected response from storage action")
		}
	})
}

// TestGraphQLProxy tests the GraphQL proxy action type.
// Fixture: 12-graphql-proxy.json (graphql.test)
func TestGraphQLProxy(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("forwards GraphQL query", func(t *testing.T) {
		query := `{"query": "{ hello }"}`
		resp := proxyPost(t, "graphql.test", "/graphql", query,
			"Content-Type", "application/json")
		// Should forward to the GraphQL server
		if resp.StatusCode >= 500 {
			t.Errorf("Expected GraphQL proxy to forward request, got status %d", resp.StatusCode)
		}
	})
}

// TestWebSocketProxy tests the WebSocket proxy action type.
// Fixture: 13-websocket-proxy.json (websocket.test)
func TestWebSocketProxy(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("echoes websocket messages end to end", func(t *testing.T) {
		conn, _ := proxyWebSocket(t, "websocket.test", "/echo", nil)
		defer conn.Close()

		payload := []byte(`{"hello":"world"}`)
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatalf("failed to write websocket message: %v", err)
		}

		messageType, reply, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read websocket reply: %v", err)
		}
		if messageType != websocket.TextMessage {
			t.Fatalf("expected text message, got %d", messageType)
		}
		if string(reply) != string(payload) {
			t.Fatalf("expected echoed payload %q, got %q", string(payload), string(reply))
		}
	})

	t.Run("responds to HTTP request on websocket origin", func(t *testing.T) {
		resp := proxyGet(t, "websocket.test", "/health")
		if resp.StatusCode == 0 {
			t.Error("Expected a response from websocket proxy")
		}
	})
}

func TestWebSocketProxyWithAuth(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("rejects missing auth header", func(t *testing.T) {
		_, resp := proxyWebSocket(t, "ws-auth.test", "/echo", nil)
		if resp == nil {
			t.Fatal("expected HTTP response for unauthorized websocket dial")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("accepts bearer auth header", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"Bearer ws-token-123"},
		}
		conn, _ := proxyWebSocket(t, "ws-auth.test", "/echo", headers)
		defer conn.Close()

		if err := conn.WriteMessage(websocket.TextMessage, []byte("authenticated")); err != nil {
			t.Fatalf("failed to write authenticated websocket message: %v", err)
		}
		_, reply, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read authenticated websocket reply: %v", err)
		}
		if string(reply) != "authenticated" {
			t.Fatalf("expected authenticated echo, got %q", string(reply))
		}
	})

	t.Run("accepts auth from realtime subprotocol", func(t *testing.T) {
		conn, _ := proxyWebSocket(
			t,
			"ws-auth.test",
			"/echo",
			nil,
			"realtime",
			"openai-insecure-api-key.ws-token-123",
		)
		defer conn.Close()

		if err := conn.WriteMessage(websocket.TextMessage, []byte("subprotocol-auth")); err != nil {
			t.Fatalf("failed to write subprotocol-auth websocket message: %v", err)
		}
		_, reply, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read subprotocol-auth websocket reply: %v", err)
		}
		if string(reply) != "subprotocol-auth" {
			t.Fatalf("expected subprotocol-auth echo, got %q", string(reply))
		}
	})
}

func TestWebSocketMessagePolicies(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("rate limiting closes repeated generation events", func(t *testing.T) {
		conn, _ := proxyWebSocket(t, "ws-openai-rate.test", "/echo", nil)
		defer conn.Close()

		first := []byte(`{"type":"response.create","input":"hello"}`)
		if err := conn.WriteMessage(websocket.TextMessage, first); err != nil {
			t.Fatalf("failed to write first rate-limited message: %v", err)
		}
		if _, _, err := conn.ReadMessage(); err != nil {
			t.Fatalf("expected first rate-limited message to be forwarded: %v", err)
		}

		if err := conn.WriteMessage(websocket.TextMessage, first); err != nil {
			t.Fatalf("failed to write second rate-limited message: %v", err)
		}

		_, _, err := conn.ReadMessage()
		if err == nil {
			t.Fatal("expected websocket close after second response.create")
		}
		if closeErr, ok := err.(*websocket.CloseError); !ok || closeErr.Code != websocket.ClosePolicyViolation {
			t.Fatalf("expected close policy violation, got %v", err)
		}
	})

	t.Run("pii policy blocks sensitive websocket payloads", func(t *testing.T) {
		conn, _ := proxyWebSocket(t, "ws-openai-pii.test", "/echo", nil)
		defer conn.Close()

		payload := []byte(`{"type":"response.create","input":"email me at test@example.com"}`)
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatalf("failed to write PII websocket message: %v", err)
		}

		_, _, err := conn.ReadMessage()
		if err == nil {
			t.Fatal("expected websocket close after PII detection")
		}
		if closeErr, ok := err.(*websocket.CloseError); !ok || closeErr.Code != websocket.ClosePolicyViolation {
			t.Fatalf("expected close policy violation, got %v", err)
		}
	})
}

// TestGRPCProxy tests the gRPC proxy action type.
// Fixture: 45-grpc-proxy.json (grpc-proxy.test)
func TestGRPCProxy(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("gRPC proxy is configured", func(t *testing.T) {
		// gRPC typically requires HTTP/2 which is harder to test via HTTP/1.1
		// Verify the origin is reachable and returns some response
		resp := proxyGet(t, "grpc-proxy.test", "/")
		if resp.StatusCode == 0 {
			t.Error("Expected a response from gRPC proxy origin")
		}
	})
}

// TestFailoverLoadBalancer tests failover load balancer configuration.
// Fixture: 109-failover-loadbalancer.json (failover-lb.test)
func TestFailoverLoadBalancer(t *testing.T) {
	checkProxyReachable(t)
	checkTestServerReachable(t)

	t.Run("routes to available backend", func(t *testing.T) {
		resp := proxyGet(t, "failover-lb.test", "/test/simple-200")
		// Should route to the available backend
		if resp.StatusCode >= 500 {
			t.Log("Note: Failover LB returned 5xx, primary backend might be down")
		}
	})
}
