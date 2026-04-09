// Package main provides main functionality for the proxy.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func (s *Server) registerGRPCHandlers(mux *http.ServeMux) {
	// gRPC echo endpoint - mimics gRPC behavior
	mux.HandleFunc("/helloworld.Greeter/SayHello", s.handleGRPCEcho)
	mux.HandleFunc("/test.EchoService/Echo", s.handleGRPCEcho)
	mux.HandleFunc("/test.HealthService/Check", s.handleGRPCHealth)
	
	// Generic gRPC endpoint handler
	mux.HandleFunc("/", s.handleGRPCGeneric)
	
	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "grpc"})
	})
}

// handleGRPCEcho handles gRPC echo requests
func (s *Server) handleGRPCEcho(w http.ResponseWriter, r *http.Request) {
	// Set gRPC response headers
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-status", "0")
	w.Header().Set("grpc-message", "")
	
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("grpc-status", "13") // INTERNAL
		w.Header().Set("grpc-message", "Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	
	// Echo back the request with some metadata
	response := map[string]interface{}{
		"message":   "Hello from gRPC test server",
		"timestamp": time.Now().Unix(),
		"request_body_length": len(body),
		"method":     r.Method,
		"path":       r.URL.Path,
	}
	
	// Forward any gRPC metadata headers
	for key, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "grpc-") {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	
	// Write response as JSON (simplified - real gRPC would use protobuf)
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)
	
	log.Printf("gRPC echo: %s %s (body: %d bytes)", r.Method, r.URL.Path, len(body))
}

// handleGRPCHealth handles gRPC health check requests
func (s *Server) handleGRPCHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-status", "0")
	w.Header().Set("grpc-message", "")
	
	response := map[string]interface{}{
		"status":    "SERVING",
		"timestamp": time.Now().Unix(),
	}
	
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)
	
	log.Printf("gRPC health check: %s %s", r.Method, r.URL.Path)
}

// handleGRPCGeneric handles generic gRPC requests
func (s *Server) handleGRPCGeneric(w http.ResponseWriter, r *http.Request) {
	// Only handle POST requests (gRPC uses POST)
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	
	// Check if it's a gRPC request
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/grpc") {
		http.NotFound(w, r)
		return
	}
	
	// Set gRPC response headers
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-status", "0")
	w.Header().Set("grpc-message", "")
	
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("grpc-status", "13") // INTERNAL
		w.Header().Set("grpc-message", "Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	
	// Forward any gRPC metadata headers
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "grpc-") || strings.HasPrefix(lowerKey, "grpc-metadata-") {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	
	// Create response
	response := map[string]interface{}{
		"service":   "gRPC Test Server",
		"path":       r.URL.Path,
		"method":     r.Method,
		"timestamp":  time.Now().Unix(),
		"body_length": len(body),
		"headers":    r.Header,
	}
	
	responseJSON, _ := json.Marshal(response)
	w.Write(responseJSON)
	
	log.Printf("gRPC generic: %s %s (body: %d bytes)", r.Method, r.URL.Path, len(body))
}

