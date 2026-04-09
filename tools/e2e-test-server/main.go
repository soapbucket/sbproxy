// Package main provides main functionality for the proxy.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

var (
	configFile  = flag.String("config", "test-config.json", "Test configuration file")
	bindAddress = flag.String("bind", "", "Bind address (empty for all interfaces, supports IPv4/IPv6)")
	httpPort    = flag.Int("http-port", 8090, "HTTP server port")
	httpsPort   = flag.Int("https-port", 9443, "HTTPS server port")
	mtlsPort    = flag.Int("mtls-port", 9444, "mTLS HTTPS server port (requires client certificates)")
	wsPort      = flag.Int("ws-port", 8091, "WebSocket server port")
	graphqlPort = flag.Int("graphql-port", 8092, "GraphQL server port")
	grpcPort    = flag.Int("grpc-port", 8093, "gRPC server port (HTTP/2)")
	mqttPort    = flag.Int("mqtt-port", 8094, "MQTT server port (WebSocket)")
)

// TestConfig defines the configuration for predictable test responses
type TestConfig struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Scenarios   []TestScenario         `json:"scenarios"`
	Defaults    map[string]interface{} `json:"defaults"`
}

// TestScenario defines a test case with expected request and response
type TestScenario struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Path        string                 `json:"path"`
	Method      string                 `json:"method"`
	Request     RequestMatch           `json:"request"`
	Response    ResponseConfig         `json:"response"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RequestMatch defines what to match in a request
type RequestMatch struct {
	Headers     map[string]string      `json:"headers"`
	QueryParams map[string]string      `json:"query_params"`
	Body        map[string]interface{} `json:"body"`
	BodyJSON    string                 `json:"body_json"`
}

// ResponseConfig defines the response to return
type ResponseConfig struct {
	Status  int                    `json:"status"`
	Headers map[string]string      `json:"headers"`
	Body    map[string]interface{} `json:"body"`
	BodyRaw string                 `json:"body_raw"`
	Delay   int                    `json:"delay"` // milliseconds
}

// Server represents a server.
type Server struct {
	config       *TestConfig
	httpServer   *http.Server
	httpsServer  *http.Server
	mtlsServer   *http.Server
	wsServer     *http.Server
	graphqlServer *http.Server
	grpcServer   *http.Server
	mqttServer   *http.Server
	upgrader     websocket.Upgrader
	mu           sync.RWMutex
	scenarios    map[string]TestScenario // keyed by ID
	scenariosByPath map[string]TestScenario // keyed by path
	
	// Cache testing state
	cacheState   map[string]*CacheState
	cacheStateMu sync.RWMutex
	
	// Circuit breaker simulation state
	circuitBreakers map[string]*CircuitBreakerState
	circuitMu       sync.RWMutex
	
	// Retry testing state
	retryState      map[string]*RetryState
	retryMu         sync.RWMutex
	
	// Max requests testing state
	maxRequestsState map[string]*MaxRequestsState
	maxRequestsMu    sync.RWMutex
}

// CacheState tracks cache-related state for testing
type CacheState struct {
	ETag         string
	LastModified time.Time
	RequestCount int
	CacheHits    int
	CacheMisses  int
	Data         map[string]interface{}
	mu           sync.RWMutex
}

// CircuitBreakerState simulates circuit breaker behavior
type CircuitBreakerState struct {
	Failures      int
	Successes     int
	State         string // "closed", "open", "half-open"
	LastFailure   time.Time
	FailureCount  int
	mu            sync.RWMutex
}

// RetryState tracks retry testing state
type RetryState struct {
	AttemptCount  int
	SuccessAfter  int // Succeed after this many attempts (0 = always fail)
	RetryableCode int // Status code to return on retryable attempts
	FinalCode     int // Final status code after all retries
	mu            sync.RWMutex
}

// MaxRequestsState tracks max requests/concurrent connection testing
type MaxRequestsState struct {
	ActiveConnections int
	TotalRequests     int
	MaxConnections    int
	mu                sync.RWMutex
}

func main() {
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Printf("Warning: Could not load config file %s: %v", *configFile, err)
		log.Printf("Using default configuration")
		config = getDefaultConfig()
	}

	// Create server
	server := &Server{
		config:           config,
		scenarios:        make(map[string]TestScenario),
		scenariosByPath:  make(map[string]TestScenario),
		cacheState:       make(map[string]*CacheState),
		circuitBreakers:  make(map[string]*CircuitBreakerState),
		retryState:       make(map[string]*RetryState),
		maxRequestsState: make(map[string]*MaxRequestsState),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for testing
			},
		},
	}

	// Index scenarios by ID and path
	for _, scenario := range config.Scenarios {
		server.scenarios[scenario.ID] = scenario
		if scenario.Path != "" {
			server.scenariosByPath[scenario.Path] = scenario
		}
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start servers
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startHTTPServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startHTTPSServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS server error: %v", err)
		}
	}()

	// Start mTLS HTTPS server (requires client certificates)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startMTLSHTTPSServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("mTLS HTTPS server error: %v", err)
		}
	}()

	// Start WebSocket server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startWebSocketServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("WebSocket server error: %v", err)
		}
	}()

	// Start GraphQL server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startGraphQLServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("GraphQL server error: %v", err)
		}
	}()

	// Start gRPC server (HTTP/2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startGRPCServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Start MQTT server (WebSocket)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.startMQTTServer(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("MQTT server error: %v", err)
		}
	}()

	// Determine display host for logging
	displayHost := "localhost"
	if *bindAddress != "" {
		displayHost = *bindAddress
		// For IPv6 addresses, wrap in brackets for URL display
		if net.ParseIP(*bindAddress) != nil && net.ParseIP(*bindAddress).To4() == nil {
			displayHost = "[" + *bindAddress + "]"
		}
	}

	log.Println("🚀 E2E Test Server Suite Started")
	log.Printf("📝 Test Config: %s", config.Name)
	if *bindAddress != "" {
		log.Printf("🌐 Bind Address: %s (IPv6: %v)", *bindAddress, net.ParseIP(*bindAddress).To4() == nil)
	}
	log.Printf("   HTTP:      http://%s:%d", displayHost, *httpPort)
	log.Printf("   HTTPS:     https://%s:%d (self-signed)", displayHost, *httpsPort)
	log.Printf("   mTLS HTTPS: https://%s:%d (requires client cert)", displayHost, *mtlsPort)
	log.Printf("   WebSocket: ws://%s:%d", displayHost, *wsPort)
	log.Printf("   GraphQL:   http://%s:%d/graphql", displayHost, *graphqlPort)
	log.Printf("   gRPC:      https://%s:%d (HTTP/2)", displayHost, *grpcPort)
	log.Printf("   MQTT:      ws://%s:%d/mqtt (WebSocket)", displayHost, *mqttPort)
	log.Println("")
	log.Printf("📋 Loaded %d test scenarios", len(config.Scenarios))
	log.Println("")
	log.Println("Press Ctrl+C to shutdown")

	// Wait for shutdown signal
	<-sigChan
	log.Println("\n⏸️  Shutting down servers...")

	// Shutdown servers gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if server.httpServer != nil {
		server.httpServer.Shutdown(shutdownCtx)
	}
	if server.httpsServer != nil {
		server.httpsServer.Shutdown(shutdownCtx)
	}
	if server.mtlsServer != nil {
		server.mtlsServer.Shutdown(shutdownCtx)
	}
	if server.wsServer != nil {
		server.wsServer.Shutdown(shutdownCtx)
	}
	if server.graphqlServer != nil {
		server.graphqlServer.Shutdown(shutdownCtx)
	}
	if server.grpcServer != nil {
		server.grpcServer.Shutdown(shutdownCtx)
	}
	if server.mqttServer != nil {
		server.mqttServer.Shutdown(shutdownCtx)
	}

	wg.Wait()
	log.Println("✅ All servers stopped")
}

func (s *Server) startHTTPServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerHTTPHandlers(mux)

	addr := getListenAddr(*bindAddress, *httpPort)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("HTTP server listening on %s", addr)
	return s.httpServer.Serve(ln)
}

func (s *Server) startHTTPSServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerHTTPHandlers(mux)

	// Generate self-signed certificate
	cert, key, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("failed to load key pair: %w", err)
	}

	addr := getListenAddr(*bindAddress, *httpsPort)
	s.httpsServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("HTTPS server listening on %s", addr)
	return s.httpsServer.ServeTLS(ln, "", "")
}

func (s *Server) startMTLSHTTPSServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerHTTPHandlers(mux)

	// Load CA certificate for client verification
	// Path is relative to the proxy root directory
	caCertPEM, err := os.ReadFile("../../test/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("../../test/certs/server-cert.pem", "../../test/certs/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	addr := getListenAddr(*bindAddress, *mtlsPort)
	s.mtlsServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caCertPool,
			MinVersion:   tls.VersionTLS12,
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("mTLS HTTPS server listening on %s (requires client certificate)", addr)
	return s.mtlsServer.ServeTLS(ln, "", "")
}

func (s *Server) startWebSocketServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerWebSocketHandlers(mux)

	addr := getListenAddr(*bindAddress, *wsPort)
	s.wsServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("WebSocket server listening on %s", addr)
	return s.wsServer.Serve(ln)
}

func (s *Server) startGraphQLServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerGraphQLHandlers(mux)

	addr := getListenAddr(*bindAddress, *graphqlPort)
	s.graphqlServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("GraphQL server listening on %s", addr)
	return s.graphqlServer.Serve(ln)
}

func (s *Server) startGRPCServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerGRPCHandlers(mux)

	// Generate self-signed certificate for HTTPS (required for HTTP/2)
	cert, key, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("failed to load key pair: %w", err)
	}

	addr := getListenAddr(*bindAddress, *grpcPort)
	s.grpcServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"}, // Enable HTTP/2
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// Configure HTTP/2
	if err := http2.ConfigureServer(s.grpcServer, nil); err != nil {
		return fmt.Errorf("failed to configure HTTP/2: %w", err)
	}

	log.Printf("gRPC server (HTTP/2) listening on %s", addr)
	return s.grpcServer.ServeTLS(ln, "", "")
}

func (s *Server) startMQTTServer(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerMQTTHandlers(mux)

	addr := getListenAddr(*bindAddress, *mqttPort)
	s.mqttServer = &http.Server{
		Addr:    addr,
		Handler: loggingMiddleware(mux),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("MQTT server (WebSocket) listening on %s", addr)
	return s.mqttServer.Serve(ln)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("→ %s %s %s from %s", r.Proto, r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("← %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func loadConfig(filename string) (*TestConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Use json.RawMessage to handle body as either string or map
	var rawConfig struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Scenarios   json.RawMessage `json:"scenarios"`
		Defaults    map[string]interface{} `json:"defaults"`
	}

	if err := json.Unmarshal(data, &rawConfig); err != nil {
		return nil, err
	}

	// Parse scenarios with flexible body handling
	var scenarios []struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Path     string          `json:"path"`
		Method   string          `json:"method"`
		Request  json.RawMessage `json:"request"`
		Response struct {
			Status  int                    `json:"status"`
			Headers map[string]string      `json:"headers"`
			Body    json.RawMessage        `json:"body"` // Can be string or map
			BodyRaw string                 `json:"body_raw"`
			Delay   int                    `json:"delay"`
		} `json:"response"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.Unmarshal(rawConfig.Scenarios, &scenarios); err != nil {
		return nil, err
	}

	// Convert to TestConfig format
	config := &TestConfig{
		Name:        rawConfig.Name,
		Description: rawConfig.Description,
		Defaults:    rawConfig.Defaults,
		Scenarios:   make([]TestScenario, len(scenarios)),
	}

	for i, s := range scenarios {
		config.Scenarios[i] = TestScenario{
			ID:       s.ID,
			Name:     s.Name,
			Path:     s.Path,
			Method:   s.Method,
			Metadata: s.Metadata,
		}

		// Handle response - convert body from string to BodyRaw if needed
		config.Scenarios[i].Response = ResponseConfig{
			Status:  s.Response.Status,
			Headers: s.Response.Headers,
			BodyRaw: s.Response.BodyRaw,
			Delay:   s.Response.Delay,
		}

		// If body_raw is not set, try to parse body
		if s.Response.BodyRaw == "" && len(s.Response.Body) > 0 {
			// Try as map first
			var bodyMap map[string]interface{}
			if err := json.Unmarshal(s.Response.Body, &bodyMap); err == nil {
				config.Scenarios[i].Response.Body = bodyMap
			} else {
				// If not a map, treat as raw string
				var bodyStr string
				if err := json.Unmarshal(s.Response.Body, &bodyStr); err == nil {
					config.Scenarios[i].Response.BodyRaw = bodyStr
				}
			}
		}
	}

	return config, nil
}

func getDefaultConfig() *TestConfig {
	return &TestConfig{
		Name:        "Default E2E Test Configuration",
		Description: "Basic test scenarios for proxy validation",
		Scenarios:   []TestScenario{},
		Defaults: map[string]interface{}{
			"status": 200,
		},
	}
}

// getListenAddr constructs the listen address from bind address and port
// Supports IPv4, IPv6, and listening on all interfaces
func getListenAddr(bindAddr string, port int) string {
	if bindAddr == "" {
		// Listen on all interfaces (both IPv4 and IPv6)
		return fmt.Sprintf(":%d", port)
	}
	
	// Check if it's an IPv6 address
	ip := net.ParseIP(bindAddr)
	if ip != nil && ip.To4() == nil {
		// IPv6 address - wrap in brackets
		return fmt.Sprintf("[%s]:%d", bindAddr, port)
	}
	
	// IPv4 address or hostname
	return fmt.Sprintf("%s:%d", bindAddr, port)
}

