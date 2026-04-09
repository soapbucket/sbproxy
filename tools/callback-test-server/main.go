// callback-test-server provides a configurable HTTP server for end-to-end
// testing of the proxy callback framework. It supports controllable response
// delays, ETags, Cache-Control headers, conditional requests (304 Not Modified),
// error injection, request logging, and parallel callback simulation.
//
// Usage:
//
//	go run . [-port 9100] [-verbose]
//
// Endpoints:
//
//	POST /callback          - Standard callback (returns JSON body as params)
//	POST /callback/slow     - Configurable delay (via ?delay=500ms query param)
//	POST /callback/etag     - Returns ETag + Cache-Control, honors If-None-Match
//	POST /callback/error    - Returns configurable errors (via ?status=500&rate=0.5)
//	POST /callback/large    - Returns a large response (via ?size=1048576 bytes)
//	POST /callback/parallel - Returns unique data for parallel execution testing
//	POST /callback/echo     - Echoes request body and headers back
//	GET  /callback/health   - Health check
//	GET  /callback/stats    - Request count and latency stats
//	POST /callback/reset    - Reset stats counters
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	port    = flag.Int("port", 9100, "HTTP server port")
	verbose = flag.Bool("verbose", false, "Enable verbose request logging")
)

// stats tracks request counts and latencies per endpoint.
type stats struct {
	mu             sync.Mutex
	requestCounts  map[string]*atomic.Int64
	totalLatencyNs map[string]*atomic.Int64
}

var serverStats = &stats{
	requestCounts:  make(map[string]*atomic.Int64),
	totalLatencyNs: make(map[string]*atomic.Int64),
}

func (s *stats) record(endpoint string, latency time.Duration) {
	s.mu.Lock()
	if _, ok := s.requestCounts[endpoint]; !ok {
		s.requestCounts[endpoint] = &atomic.Int64{}
		s.totalLatencyNs[endpoint] = &atomic.Int64{}
	}
	s.mu.Unlock()

	s.requestCounts[endpoint].Add(1)
	s.totalLatencyNs[endpoint].Add(int64(latency))
}

func (s *stats) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]any)
	for endpoint, count := range s.requestCounts {
		c := count.Load()
		latNs := s.totalLatencyNs[endpoint].Load()
		avgMs := float64(0)
		if c > 0 {
			avgMs = float64(latNs) / float64(c) / 1e6
		}
		result[endpoint] = map[string]any{
			"count":      c,
			"avg_ms":     avgMs,
			"total_ms":   float64(latNs) / 1e6,
		}
	}
	return result
}

func (s *stats) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requestCounts = make(map[string]*atomic.Int64)
	s.totalLatencyNs = make(map[string]*atomic.Int64)
}

// callbackSeq is a monotonically increasing counter for parallel testing.
var callbackSeq atomic.Int64

func main() {
	flag.Parse()

	mux := http.NewServeMux()

	// Standard callback - returns posted data as params
	mux.HandleFunc("POST /callback", handleCallback)
	mux.HandleFunc("POST /callback/", handleCallback)

	// Slow callback - configurable delay
	mux.HandleFunc("POST /callback/slow", handleSlow)

	// ETag callback - returns ETag, honors If-None-Match
	mux.HandleFunc("POST /callback/etag", handleETag)

	// Error callback - configurable error injection
	mux.HandleFunc("POST /callback/error", handleError)

	// Large callback - returns large responses
	mux.HandleFunc("POST /callback/large", handleLarge)

	// Parallel callback - returns unique data per call
	mux.HandleFunc("POST /callback/parallel", handleParallel)

	// Echo callback - echoes request back
	mux.HandleFunc("POST /callback/echo", handleEcho)

	// Health check
	mux.HandleFunc("GET /callback/health", handleHealth)

	// Stats
	mux.HandleFunc("GET /callback/stats", handleStats)

	// Reset stats
	mux.HandleFunc("POST /callback/reset", handleReset)

	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		server.Close()
	}()

	log.Printf("callback-test-server listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// handleCallback returns posted JSON data merged with metadata.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback", time.Since(start)) }()

	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(&body)
	}
	if body == nil {
		body = make(map[string]any)
	}

	resp := map[string]any{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"server":    "callback-test-server",
	}

	// Merge posted body into response
	for k, v := range body {
		resp[k] = v
	}

	if *verbose {
		log.Printf("POST /callback from %s body_keys=%v", r.RemoteAddr, mapKeys(body))
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleSlow adds a configurable delay before responding.
// Query params: delay (duration string, default "1s")
func handleSlow(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback/slow", time.Since(start)) }()

	delayStr := r.URL.Query().Get("delay")
	if delayStr == "" {
		delayStr = "1s"
	}

	delay, err := time.ParseDuration(delayStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("invalid delay: %s", delayStr),
		})
		return
	}

	if *verbose {
		log.Printf("POST /callback/slow delay=%s from %s", delay, r.RemoteAddr)
	}

	time.Sleep(delay)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"delay_ms":  delay.Milliseconds(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleETag returns responses with ETag and Cache-Control headers.
// Honors If-None-Match for conditional requests (returns 304).
// Query params: max_age (seconds, default 300), etag (custom etag value)
func handleETag(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback/etag", time.Since(start)) }()

	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(&body)
	}

	// Generate ETag based on body content or use custom
	etagValue := r.URL.Query().Get("etag")
	if etagValue == "" {
		bodyBytes, _ := json.Marshal(body)
		etagValue = fmt.Sprintf("%x", len(bodyBytes))
	}
	etag := `"` + etagValue + `"`

	// Check If-None-Match
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" && (ifNoneMatch == etag || ifNoneMatch == etagValue) {
		if *verbose {
			log.Printf("POST /callback/etag 304 Not Modified etag=%s", etag)
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Max-age
	maxAge := 300
	if ma := r.URL.Query().Get("max_age"); ma != "" {
		if v, err := strconv.Atoi(ma); err == nil {
			maxAge = v
		}
	}

	// Stale-while-revalidate
	swr := 60
	if s := r.URL.Query().Get("swr"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			swr = v
		}
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, stale-while-revalidate=%d", maxAge, swr))
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))

	if *verbose {
		log.Printf("POST /callback/etag 200 etag=%s max_age=%d swr=%d", etag, maxAge, swr)
	}

	resp := map[string]any{
		"status":    "ok",
		"etag":      etagValue,
		"max_age":   maxAge,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleError returns configurable error responses.
// Query params:
//   - status: HTTP status code (default 500)
//   - rate: error probability 0.0-1.0 (default 1.0 = always error)
//   - message: custom error message
func handleError(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback/error", time.Since(start)) }()

	status := 500
	if s := r.URL.Query().Get("status"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 100 && v < 600 {
			status = v
		}
	}

	rate := 1.0
	if rateStr := r.URL.Query().Get("rate"); rateStr != "" {
		if v, err := strconv.ParseFloat(rateStr, 64); err == nil {
			rate = v
		}
	}

	message := r.URL.Query().Get("message")
	if message == "" {
		message = "simulated error"
	}

	// Probabilistic error
	if rate < 1.0 {
		n, _ := rand.Int(rand.Reader, big.NewInt(1000))
		if float64(n.Int64())/1000.0 >= rate {
			// Return success instead
			writeJSON(w, http.StatusOK, map[string]any{
				"status":    "ok",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
	}

	if *verbose {
		log.Printf("POST /callback/error status=%d rate=%.2f", status, rate)
	}

	writeJSON(w, status, map[string]any{
		"error":   message,
		"status":  status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleLarge returns a response of configurable size.
// Query params: size (bytes, default 1024)
func handleLarge(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback/large", time.Since(start)) }()

	size := 1024
	if s := r.URL.Query().Get("size"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 100*1024*1024 {
			size = v
		}
	}

	if *verbose {
		log.Printf("POST /callback/large size=%d", size)
	}

	// Generate a response with a "data" field padded to the requested size
	padding := strings.Repeat("x", size)
	resp := map[string]any{
		"status":    "ok",
		"size":      size,
		"data":      padding,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleParallel returns unique data per call for parallel execution testing.
// Each response includes a monotonically increasing sequence number and the
// worker timestamp, making it easy to verify parallel callbacks executed
// concurrently and returned distinct results.
func handleParallel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback/parallel", time.Since(start)) }()

	seq := callbackSeq.Add(1)

	// Optional delay to simulate work
	if delayStr := r.URL.Query().Get("delay"); delayStr != "" {
		if d, err := time.ParseDuration(delayStr); err == nil {
			time.Sleep(d)
		}
	}

	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(&body)
	}

	if *verbose {
		log.Printf("POST /callback/parallel seq=%d", seq)
	}

	resp := map[string]any{
		"status":    "ok",
		"seq":       seq,
		"worker_ts": time.Now().UnixNano(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Pass through any request body fields
	if body != nil {
		for k, v := range body {
			resp[k] = v
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleEcho returns the full request details (method, headers, body, query params).
func handleEcho(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { serverStats.record("/callback/echo", time.Since(start)) }()

	var body any
	if r.Body != nil {
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(&body)
	}

	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	query := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			query[k] = v[0]
		}
	}

	if *verbose {
		log.Printf("POST /callback/echo headers=%d query=%d", len(headers), len(query))
	}

	resp := map[string]any{
		"method":    r.Method,
		"path":      r.URL.Path,
		"headers":   headers,
		"query":     query,
		"body":      body,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth returns a simple health check response.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "healthy",
		"uptime": time.Since(startTime).String(),
	})
}

var startTime = time.Now()

// handleStats returns request statistics.
func handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, serverStats.snapshot())
}

// handleReset clears all statistics.
func handleReset(w http.ResponseWriter, r *http.Request) {
	serverStats.reset()
	callbackSeq.Store(0)
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset"})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
