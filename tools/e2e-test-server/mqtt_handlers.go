// Package main provides main functionality for the proxy.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var mqttUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for testing
	},
	Subprotocols: []string{"mqtt"},
}

// MQTT connection state
type mqttConnection struct {
	conn      *websocket.Conn
	clientID  string
	topics    map[string]byte // topic -> QoS
	mu        sync.RWMutex
	connected bool
}

var (
	mqttConnections = make(map[string]*mqttConnection)
	mqttConnMu      sync.RWMutex
	mqttSubscribers = make(map[string]map[*websocket.Conn]bool) // topic -> connections
	mqttSubMu       sync.RWMutex
)

func (s *Server) registerMQTTHandlers(mux *http.ServeMux) {
	// MQTT over WebSocket endpoint
	mux.HandleFunc("/mqtt", s.handleMQTTWebSocket)
	
	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "mqtt"})
	})
	
	// Info endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		
		info := map[string]interface{}{
			"service": "MQTT Test Server (WebSocket)",
			"endpoints": map[string]string{
				"GET  /":         "This info",
				"GET  /health":   "Health check",
				"GET  /mqtt":     "MQTT over WebSocket endpoint",
			},
			"protocol": "MQTT over WebSockets",
			"supported_versions": []string{"3.1.1", "5.0"},
			"test_topics": []string{
				"sensors/temperature",
				"sensors/humidity",
				"devices/+/status",
				"test/#",
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
}

func (s *Server) handleMQTTWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade to WebSocket
	conn, err := mqttUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("MQTT: failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("MQTT: client connected from %s", r.RemoteAddr)

	// Create connection state
	mqttConn := &mqttConnection{
		conn:      conn,
		clientID:  fmt.Sprintf("client-%d", time.Now().UnixNano()),
		topics:    make(map[string]byte),
		connected: true,
	}

	connID := mqttConn.clientID

	// Store connection
	mqttConnMu.Lock()
	mqttConnections[connID] = mqttConn
	mqttConnMu.Unlock()

	// Cleanup on exit
	defer func() {
		mqttConnMu.Lock()
		delete(mqttConnections, connID)
		mqttConnMu.Unlock()

		// Unsubscribe from all topics
		mqttSubMu.Lock()
		for topic := range mqttConn.topics {
			if subs, ok := mqttSubscribers[topic]; ok {
				delete(subs, conn)
				if len(subs) == 0 {
					delete(mqttSubscribers, topic)
				}
			}
		}
		mqttSubMu.Unlock()

		log.Printf("MQTT: client disconnected: %s", connID)
	}()

	// Handle MQTT messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("MQTT: unexpected close: %v", err)
			}
			break
		}

		// Process MQTT message (simplified - just echo for testing)
		// In a real implementation, this would parse MQTT packets
		log.Printf("MQTT: received message (type=%d, size=%d)", messageType, len(message))

		// Echo message back (simplified MQTT broker behavior)
		if err := conn.WriteMessage(messageType, message); err != nil {
			log.Printf("MQTT: write error: %v", err)
			break
		}

		// For testing: if message contains "PUBLISH", simulate publishing to subscribers
		msgStr := string(message)
		if strings.Contains(msgStr, "PUBLISH") || strings.Contains(msgStr, "publish") {
			// Extract topic from message (simplified)
			// In real MQTT, this would parse the PUBLISH packet
			topic := s.extractTopicFromMessage(msgStr)
			if topic != "" {
				s.publishToSubscribers(topic, message)
			}
		}
	}
}

func (s *Server) extractTopicFromMessage(msg string) string {
	// Simplified topic extraction for testing
	// Look for common patterns like "topic: sensors/temperature"
	if idx := strings.Index(msg, "topic:"); idx != -1 {
		parts := strings.Fields(msg[idx:])
		if len(parts) > 1 {
			return parts[1]
		}
	}
	// Default test topic
	return "test/topic"
}

func (s *Server) publishToSubscribers(topic string, message []byte) {
	mqttSubMu.RLock()
	defer mqttSubMu.RUnlock()

	// Find all subscribers for this topic (including wildcards)
	for subTopic, subscribers := range mqttSubscribers {
		if s.matchMQTTTopic(topic, subTopic) {
			for conn := range subscribers {
				if err := conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
					log.Printf("MQTT: failed to publish to subscriber: %v", err)
				}
			}
		}
	}
}

func (s *Server) matchMQTTTopic(topic, pattern string) bool {
	// Simple MQTT topic matching with wildcards
	if pattern == "#" {
		return true
	}

	patternParts := strings.Split(pattern, "/")
	topicParts := strings.Split(topic, "/")

	if len(patternParts) > 0 && patternParts[len(patternParts)-1] == "#" {
		// Multi-level wildcard
		if len(patternParts) > 1 {
			prefix := strings.Join(patternParts[:len(patternParts)-1], "/")
			return strings.HasPrefix(topic, prefix+"/") || topic == prefix
		}
		return true
	}

	if len(patternParts) != len(topicParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if patternPart == "+" {
			continue
		}
		if i >= len(topicParts) || patternPart != topicParts[i] {
			return false
		}
	}

	return true
}

