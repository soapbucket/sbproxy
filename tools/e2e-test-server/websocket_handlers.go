// Package main provides main functionality for the proxy.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// BroadcastPool represents a broadcast pool.
type BroadcastPool struct {
	connections map[*websocket.Conn]bool
	mu          sync.Mutex
}

var broadcastPool = &BroadcastPool{
	connections: make(map[*websocket.Conn]bool),
}

func (s *Server) registerWebSocketHandlers(mux *http.ServeMux) {
	// Echo endpoint - reflects messages back
	mux.HandleFunc("/echo", s.handleWSEcho)
	
	// Timestamp endpoint - streams server timestamps
	mux.HandleFunc("/timestamp", s.handleWSTimestamp)
	
	// Broadcast endpoint - multicasts to all connected clients
	mux.HandleFunc("/broadcast", s.handleWSBroadcast)
	
	// Test scenario endpoint
	mux.HandleFunc("/test/", s.handleWSTest)
	
	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "websocket"})
	})
	
	// Info endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		
		info := map[string]interface{}{
			"service": "WebSocket Test Server",
			"endpoints": map[string]string{
				"GET /":             "This info",
				"GET /health":       "Health check",
				"WS  /echo":         "Echo messages back",
				"WS  /timestamp":    "Stream timestamps",
				"WS  /broadcast":    "Broadcast to all clients",
				"WS  /test/{id}":    "Test scenario endpoint",
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
}

func (s *Server) handleWSEcho(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket echo connection from %s", r.RemoteAddr)

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Unexpected close error: %v", err)
			}
			break
		}

		log.Printf("Echo: received %d bytes (type=%d)", len(message), messageType)

		// Echo the message back
		if err := conn.WriteMessage(messageType, message); err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}

	log.Printf("WebSocket echo connection closed from %s", r.RemoteAddr)
}

func (s *Server) handleWSTimestamp(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket timestamp connection from %s", r.RemoteAddr)

	// Send timestamps every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Channel to signal client disconnection
	done := make(chan struct{})

	// Read pump to detect disconnection
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				close(done)
				return
			}
		}
	}()

	for {
		select {
		case t := <-ticker.C:
			msg := map[string]interface{}{
				"type":      "timestamp",
				"timestamp": t.Unix(),
				"time":      t.Format(time.RFC3339),
			}
			
			data, _ := json.Marshal(msg)
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Printf("Write error: %v", err)
				return
			}
		case <-done:
			log.Printf("WebSocket timestamp connection closed from %s", r.RemoteAddr)
			return
		}
	}
}

func (s *Server) handleWSBroadcast(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket broadcast connection from %s", r.RemoteAddr)

	// Add to broadcast pool
	broadcastPool.add(conn)
	defer broadcastPool.remove(conn)

	// Keep connection alive by reading messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		log.Printf("Broadcasting message (type=%d, len=%d)", messageType, len(message))
		
		// Broadcast to all connections
		broadcastPool.broadcast(messageType, message)
	}

	log.Printf("WebSocket broadcast connection closed from %s", r.RemoteAddr)
}

func (s *Server) handleWSTest(w http.ResponseWriter, r *http.Request) {
	// Extract scenario ID from path
	scenarioID := r.URL.Path[len("/test/"):]
	if scenarioID == "" {
		http.Error(w, "Scenario ID required", http.StatusBadRequest)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket test connection (scenario=%s) from %s", scenarioID, r.RemoteAddr)

	// Find scenario
	s.mu.RLock()
	scenario, exists := s.scenarios[scenarioID]
	s.mu.RUnlock()

	if !exists {
		msg := map[string]interface{}{
			"error": fmt.Sprintf("Scenario not found: %s", scenarioID),
		}
		data, _ := json.Marshal(msg)
		conn.WriteMessage(websocket.TextMessage, data)
		return
	}

	// Send scenario response
	response := map[string]interface{}{
		"scenario":  scenarioID,
		"name":      scenario.Name,
		"timestamp": time.Now().Unix(),
	}

	// Merge scenario response body
	for key, value := range scenario.Response.Body {
		response[key] = value
	}

	data, _ := json.Marshal(response)
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("Write error: %v", err)
		return
	}

	// Keep connection open and echo messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Echo back with scenario metadata
		var incoming map[string]interface{}
		if err := json.Unmarshal(message, &incoming); err == nil {
			incoming["scenario"] = scenarioID
			incoming["echo"] = true
			data, _ := json.Marshal(incoming)
			conn.WriteMessage(messageType, data)
		} else {
			conn.WriteMessage(messageType, message)
		}
	}

	log.Printf("WebSocket test connection closed from %s", r.RemoteAddr)
}

func (p *BroadcastPool) add(conn *websocket.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections[conn] = true
	log.Printf("Client added to broadcast pool. Total clients: %d", len(p.connections))
}

func (p *BroadcastPool) remove(conn *websocket.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.connections, conn)
	log.Printf("Client removed from broadcast pool. Total clients: %d", len(p.connections))
}

func (p *BroadcastPool) broadcast(messageType int, message []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for conn := range p.connections {
		if err := conn.WriteMessage(messageType, message); err != nil {
			log.Printf("Broadcast error: %v", err)
			conn.Close()
			delete(p.connections, conn)
		}
	}
}

