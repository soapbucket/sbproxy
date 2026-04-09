// Package main provides main functionality for the proxy.
package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) registerHTTPHandlers(mux *http.ServeMux) {
	// Health check (exact match)
	mux.HandleFunc("/health", s.handleHealth)

	// Response validation endpoint (exact match)
	mux.HandleFunc("/validate", s.handleValidate)

	// Static HTML page for comprehensive testing
	mux.HandleFunc("/test-page.html", s.handleTestPage)
	mux.HandleFunc("/test-page.css", s.handleTestPageCSS)
	mux.HandleFunc("/test-page.js", s.handleTestPageJS)
	mux.HandleFunc("/test-page.json", s.handleTestPageJSON)

	// Test endpoint with scenario support
	mux.HandleFunc("/test/", s.handleTestEndpoint)

	// Callback endpoints
	mux.HandleFunc("/callback/session", s.handleSessionCallback)
	mux.HandleFunc("/callback/auth", s.handleAuthCallback)
	mux.HandleFunc("/callback/config", s.handleConfigCallback)
	mux.HandleFunc("/callback/webhook", s.handleWebhookCallback)
	mux.HandleFunc("/callback/", s.handleCallbackEndpoint)

	// Cache testing endpoints
	mux.HandleFunc("/cache/", s.handleCacheEndpoint)
	mux.HandleFunc("/cache-test/", s.handleCacheTest)

	// Circuit breaker simulation endpoints
	mux.HandleFunc("/circuit/", s.handleCircuitBreaker)

	// Retry testing endpoints
	mux.HandleFunc("/retry/", s.handleRetryEndpoint)

	// Max requests/concurrent connection testing endpoints
	mux.HandleFunc("/max-requests/", s.handleMaxRequestsEndpoint)

	// Error callback endpoints for error page testing
	mux.HandleFunc("/error/", s.handleErrorCallback)

	// REST API endpoints (exact matches first)
	mux.HandleFunc("/api/echo", s.handleEcho)
	mux.HandleFunc("/api/headers", s.handleHeaders)
	mux.HandleFunc("/api/delay", s.handleDelay)
	mux.HandleFunc("/api/status/", s.handleStatus)

	// Root handler - info about available endpoints (must be after /api/status/ to avoid conflicts)
	mux.HandleFunc("/", s.handleRoot)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// Delegate to scenario handler for non-root paths
		s.handleScenarioByPath(w, r)
		return
	}

	info := map[string]interface{}{
		"service": "E2E Test Server",
		"config":  s.config.Name,
		"endpoints": map[string]string{
			"GET  /":                  "This info",
			"GET  /health":            "Health check",
			"ANY  /test/{scenario}":   "Test scenario endpoint",
			"POST /callback/session":  "Session callback",
			"POST /callback/auth":     "Auth callback",
			"POST /callback/{id}":     "Configurable callback endpoint",
			"GET  /cache/{id}":        "Cache testing endpoint",
			"GET  /cache-test/{id}":   "Cache test with ETag/Last-Modified",
			"GET  /circuit/{id}":      "Circuit breaker simulation",
			"POST /api/echo":          "Echo request body",
			"GET  /api/headers":       "Return request headers",
			"GET  /api/delay?ms=N":    "Delayed response",
			"GET  /api/status/{code}": "Return specific status code",
			"POST /validate":          "Validate test response",
		},
		"scenarios":      len(s.config.Scenarios),
		"graphql_port":   *graphqlPort,
		"websocket_port": *wsPort,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) handleScenarioByPath(w http.ResponseWriter, r *http.Request) {
	// Skip if this is a known exact endpoint
	if r.URL.Path == "/" || r.URL.Path == "/health" || r.URL.Path == "/validate" {
		// Let other handlers deal with these
		http.NotFound(w, r)
		return
	}

	// Check if this is a scenario path FIRST
	s.mu.RLock()
	scenario, isScenarioPath := s.scenariosByPath[r.URL.Path]
	scenarioCount := len(s.scenariosByPath)
	s.mu.RUnlock()

	// If it's a scenario path, handle it (skip the prefix checks)
	if isScenarioPath {
		// Continue to handle scenario below
	} else {
		// Skip if this matches known endpoint prefixes
		if strings.HasPrefix(r.URL.Path, "/test/") ||
			strings.HasPrefix(r.URL.Path, "/callback/") ||
			strings.HasPrefix(r.URL.Path, "/cache/") ||
			strings.HasPrefix(r.URL.Path, "/cache-test/") ||
			strings.HasPrefix(r.URL.Path, "/circuit/") ||
			r.URL.Path == "/api/echo" ||
			r.URL.Path == "/api/headers" ||
			r.URL.Path == "/api/delay" ||
			strings.HasPrefix(r.URL.Path, "/api/status/") {
			// Let other handlers deal with these
			http.NotFound(w, r)
			return
		}
		// Not a scenario path and not a known endpoint
		log.Printf("Scenario path not found: %s (total scenarios by path: %d)", r.URL.Path, scenarioCount)
		http.NotFound(w, r)
		return
	}

	// Check if request matches scenario
	if scenario.Method != "" && scenario.Method != r.Method {
		http.Error(w, fmt.Sprintf("Method mismatch: expected %s, got %s", scenario.Method, r.Method), http.StatusMethodNotAllowed)
		return
	}

	// Apply delay if configured
	if scenario.Response.Delay > 0 {
		time.Sleep(time.Duration(scenario.Response.Delay) * time.Millisecond)
	}

	// Set response headers
	for key, value := range scenario.Response.Headers {
		w.Header().Set(key, value)
	}

	// Set status code
	status := scenario.Response.Status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)

	// Write response body
	if scenario.Response.BodyRaw != "" {
		w.Write([]byte(scenario.Response.BodyRaw))
	} else if len(scenario.Response.Body) > 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scenario.Response.Body)
	} else {
		// Default response
		response := map[string]interface{}{
			"scenario":  scenario.ID,
			"name":      scenario.Name,
			"timestamp": time.Now().Unix(),
			"success":   true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"uptime":    time.Since(time.Now()).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (s *Server) handleTestEndpoint(w http.ResponseWriter, r *http.Request) {
	// Extract scenario ID from path: /test/{scenarioID}
	scenarioID := strings.TrimPrefix(r.URL.Path, "/test/")
	if scenarioID == "" {
		s.listScenarios(w, r)
		return
	}

	// Find matching scenario - prefer path-based lookup to handle duplicate IDs
	s.mu.RLock()
	scenario, exists := s.scenariosByPath[r.URL.Path]
	if !exists {
		// Fallback to ID-based lookup if path-based lookup fails
		scenario, exists = s.scenarios[scenarioID]
	}
	s.mu.RUnlock()

	if !exists {
		http.Error(w, fmt.Sprintf("Scenario not found: %s", scenarioID), http.StatusNotFound)
		return
	}

	// Verify the scenario path matches the request path (for /test/ endpoints)
	if scenario.Path != "" && scenario.Path != r.URL.Path && strings.HasPrefix(r.URL.Path, "/test/") {
		// If path doesn't match and this is a /test/ endpoint, try ID-based lookup
		s.mu.RLock()
		scenarioByID, existsByID := s.scenarios[scenarioID]
		s.mu.RUnlock()
		if existsByID && scenarioByID.Path == r.URL.Path {
			scenario = scenarioByID
		} else {
			http.Error(w, fmt.Sprintf("Scenario path mismatch: expected %s, got %s", scenario.Path, r.URL.Path), http.StatusNotFound)
			return
		}
	}

	// Check if request matches scenario
	if scenario.Method != "" && scenario.Method != r.Method {
		http.Error(w, fmt.Sprintf("Method mismatch: expected %s, got %s", scenario.Method, r.Method), http.StatusMethodNotAllowed)
		return
	}

	// Apply delay if configured
	if scenario.Response.Delay > 0 {
		time.Sleep(time.Duration(scenario.Response.Delay) * time.Millisecond)
	}

	// Set response headers
	for key, value := range scenario.Response.Headers {
		w.Header().Set(key, value)
	}

	// Set status code
	status := scenario.Response.Status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)

	// Write response body
	if scenario.Response.BodyRaw != "" {
		w.Write([]byte(scenario.Response.BodyRaw))
	} else if len(scenario.Response.Body) > 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scenario.Response.Body)
	} else {
		// Default response
		response := map[string]interface{}{
			"scenario":  scenarioID,
			"name":      scenario.Name,
			"timestamp": time.Now().Unix(),
			"success":   true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func (s *Server) listScenarios(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scenarios := make([]map[string]interface{}, 0, len(s.config.Scenarios))
	for _, scenario := range s.config.Scenarios {
		scenarios = append(scenarios, map[string]interface{}{
			"id":     scenario.ID,
			"name":   scenario.Name,
			"path":   scenario.Path,
			"method": scenario.Method,
		})
	}

	response := map[string]interface{}{
		"total":     len(scenarios),
		"scenarios": scenarios,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleSessionCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate ETag from request body for caching
	body, _ := io.ReadAll(r.Body)
	hash := md5.Sum(body)
	etag := fmt.Sprintf(`"%x"`, hash[:8])

	// Check If-None-Match header
	if noneMatch := r.Header.Get("If-None-Match"); noneMatch == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	response := map[string]interface{}{
		"user_preferences": map[string]interface{}{
			"theme":    "dark",
			"language": "en",
			"timezone": "America/New_York",
		},
		"feature_flags": map[string]interface{}{
			"beta_features": true,
			"analytics":     true,
			"export":        true,
		},
		"subscription": map[string]interface{}{
			"tier":    "premium",
			"active":  true,
			"expires": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		},
		"api_quota":  10000,
		"rate_limit": 100,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=300")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Sub      string `json:"sub"`
		Provider string `json:"provider"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate ETag based on email (since auth response depends on email)
	hash := md5.Sum([]byte(req.Email))
	etag := fmt.Sprintf(`"%x"`, hash[:8])

	// Check If-None-Match header
	if noneMatch := r.Header.Get("If-None-Match"); noneMatch == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	var response map[string]interface{}

	switch req.Email {
	case "admin@example.com":
		response = map[string]interface{}{
			"roles": []string{"admin", "user", "editor"},
			"permissions": map[string]interface{}{
				"read":   true,
				"write":  true,
				"delete": true,
				"admin":  true,
			},
			"department":       "engineering",
			"seniority":        "senior",
			"can_manage_users": true,
			"access_level":     100,
		}
	case "premium@example.com":
		response = map[string]interface{}{
			"roles": []string{"user", "premium"},
			"permissions": map[string]interface{}{
				"read":      true,
				"write":     true,
				"delete":    false,
				"export":    true,
				"analytics": true,
			},
			"department":       "product",
			"seniority":        "mid",
			"can_manage_users": false,
			"access_level":     50,
		}
	default:
		response = map[string]interface{}{
			"roles": []string{"user"},
			"permissions": map[string]interface{}{
				"read": true,
			},
			"department":       "unknown",
			"seniority":        "junior",
			"can_manage_users": false,
			"access_level":     1,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=600")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"method":  r.Method,
		"path":    r.URL.Path,
		"query":   r.URL.Query(),
		"headers": r.Header,
		"body":    string(body),
		"length":  len(body),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleHeaders(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	response := map[string]interface{}{
		"headers": headers,
		"count":   len(headers),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDelay(w http.ResponseWriter, r *http.Request) {
	msStr := r.URL.Query().Get("ms")
	if msStr == "" {
		msStr = "1000"
	}

	var ms int
	fmt.Sscanf(msStr, "%d", &ms)

	if ms > 10000 {
		ms = 10000 // Max 10 seconds
	}

	time.Sleep(time.Duration(ms) * time.Millisecond)

	response := map[string]interface{}{
		"delayed_ms": ms,
		"timestamp":  time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	statusCode := strings.TrimPrefix(r.URL.Path, "/api/status/")
	var code int
	fmt.Sscanf(statusCode, "%d", &code)

	if code < 100 || code > 599 {
		code = 200
	}

	w.WriteHeader(code)
	response := map[string]interface{}{
		"status":  code,
		"message": http.StatusText(code),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ScenarioID string                 `json:"scenario_id"`
		Response   map[string]interface{} `json:"response"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Find scenario
	s.mu.RLock()
	scenario, exists := s.scenarios[req.ScenarioID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, fmt.Sprintf("Scenario not found: %s", req.ScenarioID), http.StatusNotFound)
		return
	}

	// Validate response matches expected
	validation := map[string]interface{}{
		"scenario_id": req.ScenarioID,
		"valid":       true,
		"checks":      []string{},
	}

	checks := []string{}

	// Check status code if specified
	if scenario.Response.Status > 0 {
		if status, ok := req.Response["status"].(float64); ok {
			if int(status) == scenario.Response.Status {
				checks = append(checks, fmt.Sprintf("✅ Status code: %d", scenario.Response.Status))
			} else {
				checks = append(checks, fmt.Sprintf("❌ Status code: expected %d, got %d", scenario.Response.Status, int(status)))
				validation["valid"] = false
			}
		}
	}

	// Check headers
	for key, expectedValue := range scenario.Response.Headers {
		if headers, ok := req.Response["headers"].(map[string]interface{}); ok {
			if value, ok := headers[key].(string); ok && value == expectedValue {
				checks = append(checks, fmt.Sprintf("✅ Header %s: %s", key, expectedValue))
			} else {
				checks = append(checks, fmt.Sprintf("❌ Header %s: expected %s", key, expectedValue))
				validation["valid"] = false
			}
		}
	}

	validation["checks"] = checks
	validation["total_checks"] = len(checks)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(validation)
}

// handleCallbackEndpoint handles configurable callback endpoints
func (s *Server) handleCallbackEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract callback ID from path: /callback/{id}
	callbackID := strings.TrimPrefix(r.URL.Path, "/callback/")
	if callbackID == "" || callbackID == "session" || callbackID == "auth" {
		http.NotFound(w, r)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Parse request body if JSON
	var requestData map[string]interface{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &requestData); err != nil {
			requestData = map[string]interface{}{"raw": string(body)}
		}
	}

	// Get expected status code from query param or default to 200
	expectedStatus := 200
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		if status, err := strconv.Atoi(statusStr); err == nil {
			expectedStatus = status
		}
	}

	// Get variable name from query param
	variableName := r.URL.Query().Get("variable_name")

	// Build response
	response := map[string]interface{}{
		"callback_id": callbackID,
		"timestamp":   time.Now().Unix(),
		"request":     requestData,
		"success":     true,
	}

	// Wrap in variable name if specified
	if variableName != "" {
		response = map[string]interface{}{variableName: response}
	}

	// Set headers
	w.Header().Set("Content-Type", "application/json")

	// Add cache headers if requested
	if cacheControl := r.URL.Query().Get("cache_control"); cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	if etag := r.URL.Query().Get("etag"); etag != "" {
		w.Header().Set("ETag", etag)
	}

	w.WriteHeader(expectedStatus)
	json.NewEncoder(w).Encode(response)
}

// handleCacheEndpoint handles cache testing endpoints
func (s *Server) handleCacheEndpoint(w http.ResponseWriter, r *http.Request) {
	cacheID := strings.TrimPrefix(r.URL.Path, "/cache/")
	if cacheID == "" {
		http.NotFound(w, r)
		return
	}

	// Get or create cache state
	s.cacheStateMu.Lock()
	state, exists := s.cacheState[cacheID]
	if !exists {
		// Generate ETag from cache ID
		hash := md5.Sum([]byte(cacheID))
		etag := fmt.Sprintf(`"%x"`, hash[:8])

		state = &CacheState{
			ETag:         etag,
			LastModified: time.Now(),
			Data: map[string]interface{}{
				"id":      cacheID,
				"data":    fmt.Sprintf("Cached data for %s", cacheID),
				"created": time.Now().Unix(),
			},
		}
		s.cacheState[cacheID] = state
	}
	s.cacheStateMu.Unlock()

	state.mu.Lock()
	state.RequestCount++

	// Check conditional requests
	noneMatch := r.Header.Get("If-None-Match")
	modifiedSince := r.Header.Get("If-Modified-Since")

	cacheHit := false
	if noneMatch != "" && noneMatch == state.ETag {
		state.CacheHits++
		cacheHit = true
		state.mu.Unlock()
		w.Header().Set("ETag", state.ETag)
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if modifiedSince != "" {
		if modifiedTime, err := time.Parse(time.RFC1123, modifiedSince); err == nil {
			if !state.LastModified.After(modifiedTime) {
				state.CacheHits++
				cacheHit = true
				state.mu.Unlock()
				w.Header().Set("Last-Modified", state.LastModified.Format(time.RFC1123))
				w.Header().Set("X-Cache", "HIT")
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	if !cacheHit {
		state.CacheMisses++
	}

	requestCount := state.RequestCount
	cacheHits := state.CacheHits
	cacheMisses := state.CacheMisses
	state.mu.Unlock()

	// Set cache headers
	w.Header().Set("ETag", state.ETag)
	w.Header().Set("Last-Modified", state.LastModified.Format(time.RFC1123))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Cache", "MISS")
	w.Header().Set("X-Request-Count", strconv.Itoa(requestCount))
	w.Header().Set("X-Cache-Hits", strconv.Itoa(cacheHits))
	w.Header().Set("X-Cache-Misses", strconv.Itoa(cacheMisses))
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"id":            cacheID,
		"data":          state.Data,
		"request_count": requestCount,
		"cache_hits":    cacheHits,
		"cache_misses":  cacheMisses,
		"etag":          state.ETag,
		"last_modified": state.LastModified.Format(time.RFC1123),
	}

	json.NewEncoder(w).Encode(response)
}

// handleCacheTest handles advanced cache testing with configurable behavior
func (s *Server) handleCacheTest(w http.ResponseWriter, r *http.Request) {
	testID := strings.TrimPrefix(r.URL.Path, "/cache-test/")
	if testID == "" {
		http.NotFound(w, r)
		return
	}

	// Handle specific cache test scenarios
	switch testID {
	case "no-cache":
		s.handleNoCacheTest(w, r)
		return
	case "max-age":
		s.handleMaxAgeTest(w, r)
		return
	}

	// Get cache duration from query (default 60 seconds)
	cacheDuration := 60
	if durStr := r.URL.Query().Get("duration"); durStr != "" {
		if dur, err := strconv.Atoi(durStr); err == nil {
			cacheDuration = dur
		}
	}

	// Get or create cache state
	s.cacheStateMu.Lock()
	state, exists := s.cacheState[testID]
	if !exists {
		hash := md5.Sum([]byte(testID))
		etag := fmt.Sprintf(`"%x"`, hash[:8])

		state = &CacheState{
			ETag:         etag,
			LastModified: time.Now(),
			Data: map[string]interface{}{
				"id":      testID,
				"data":    fmt.Sprintf("Cache test data for %s", testID),
				"created": time.Now().Unix(),
			},
		}
		s.cacheState[testID] = state
	}
	s.cacheStateMu.Unlock()

	state.mu.Lock()
	state.RequestCount++

	// Check conditional requests
	noneMatch := r.Header.Get("If-None-Match")
	modifiedSince := r.Header.Get("If-Modified-Since")

	if noneMatch != "" && noneMatch == state.ETag {
		state.CacheHits++
		state.mu.Unlock()
		w.Header().Set("ETag", state.ETag)
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if modifiedSince != "" {
		if modifiedTime, err := time.Parse(time.RFC1123, modifiedSince); err == nil {
			if !state.LastModified.After(modifiedTime) {
				state.CacheHits++
				state.mu.Unlock()
				w.Header().Set("Last-Modified", state.LastModified.Format(time.RFC1123))
				w.Header().Set("X-Cache", "HIT")
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	state.CacheMisses++
	requestCount := state.RequestCount
	cacheHits := state.CacheHits
	cacheMisses := state.CacheMisses
	state.mu.Unlock()

	// Set cache headers
	w.Header().Set("ETag", state.ETag)
	w.Header().Set("Last-Modified", state.LastModified.Format(time.RFC1123))
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", cacheDuration))
	w.Header().Set("X-Cache", "MISS")
	w.Header().Set("X-Request-Count", strconv.Itoa(requestCount))
	w.Header().Set("X-Cache-Hits", strconv.Itoa(cacheHits))
	w.Header().Set("X-Cache-Misses", strconv.Itoa(cacheMisses))
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"id":             testID,
		"data":           state.Data,
		"request_count":  requestCount,
		"cache_hits":     cacheHits,
		"cache_misses":   cacheMisses,
		"etag":           state.ETag,
		"last_modified":  state.LastModified.Format(time.RFC1123),
		"cache_duration": cacheDuration,
	}

	json.NewEncoder(w).Encode(response)
}

// handleConfigCallback handles config callbacks (e.g., for on_load)
func (s *Server) handleConfigCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"version": "v2.1.0",
		"env":     "production",
		"enabled": true,
		"features": map[string]interface{}{
			"beta_ui":      true,
			"api_v2":       true,
			"websockets":   true,
			"file_uploads": true,
		},
		"limits": map[string]interface{}{
			"max_upload_size": 10485760,
			"max_connections": 1000,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(response)
}

// handleWebhookCallback handles webhook callbacks
func (s *Server) handleWebhookCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var requestData map[string]interface{}
	if len(body) > 0 {
		json.Unmarshal(body, &requestData)
	}

	response := map[string]interface{}{
		"status":    "success",
		"message":   "Webhook received",
		"timestamp": time.Now().Unix(),
		"request":   requestData,
		"event_id":  fmt.Sprintf("evt_%d", time.Now().UnixNano()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleNoCacheTest handles testing no-cache directive
func (s *Server) handleNoCacheTest(w http.ResponseWriter, r *http.Request) {
	// Always return no-cache directive
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"test":      "no-cache",
		"timestamp": time.Now().Unix(),
		"message":   "This response should never be cached",
	}

	json.NewEncoder(w).Encode(response)
}

// handleMaxAgeTest handles testing max-age cache control
func (s *Server) handleMaxAgeTest(w http.ResponseWriter, r *http.Request) {
	// Get max_age from query param
	maxAge := 60
	if maxAgeStr := r.URL.Query().Get("max_age"); maxAgeStr != "" {
		if ma, err := strconv.Atoi(maxAgeStr); err == nil {
			maxAge = ma
		}
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"test":      "max-age",
		"max_age":   maxAge,
		"timestamp": time.Now().Unix(),
		"message":   fmt.Sprintf("This response can be cached for %d seconds", maxAge),
	}

	json.NewEncoder(w).Encode(response)
}

// handleCircuitBreaker handles circuit breaker simulation
func (s *Server) handleCircuitBreaker(w http.ResponseWriter, r *http.Request) {
	circuitID := strings.TrimPrefix(r.URL.Path, "/circuit/")
	if circuitID == "" {
		http.NotFound(w, r)
		return
	}

	// Get circuit breaker parameters from query
	failureThreshold := 5
	if thresholdStr := r.URL.Query().Get("failure_threshold"); thresholdStr != "" {
		if threshold, err := strconv.Atoi(thresholdStr); err == nil {
			failureThreshold = threshold
		}
	}

	shouldFail := r.URL.Query().Get("fail") == "true"
	reset := r.URL.Query().Get("reset") == "true"

	// Get or create circuit breaker state
	s.circuitMu.Lock()
	cb, exists := s.circuitBreakers[circuitID]
	if !exists || reset {
		cb = &CircuitBreakerState{
			State:     "closed",
			Failures:  0,
			Successes: 0,
		}
		s.circuitBreakers[circuitID] = cb
	}
	s.circuitMu.Unlock()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Handle reset
	if reset {
		cb.State = "closed"
		cb.Failures = 0
		cb.Successes = 0
		cb.FailureCount = 0
		cb.LastFailure = time.Time{}
	}

	// Check circuit breaker state
	if cb.State == "open" {
		// Check if timeout has passed (30 seconds default)
		if time.Since(cb.LastFailure) > 30*time.Second {
			cb.State = "half-open"
			cb.Successes = 0
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":        "Circuit breaker is open",
				"circuit_id":   circuitID,
				"state":        cb.State,
				"failures":     cb.Failures,
				"last_failure": cb.LastFailure.Format(time.RFC3339),
			})
			return
		}
	}

	// Simulate failure or success
	if shouldFail {
		cb.Failures++
		cb.FailureCount++
		cb.LastFailure = time.Now()

		if cb.Failures >= failureThreshold {
			cb.State = "open"
		} else if cb.State == "half-open" {
			cb.State = "open"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":        "Simulated failure",
			"circuit_id":   circuitID,
			"state":        cb.State,
			"failures":     cb.Failures,
			"last_failure": cb.LastFailure.Format(time.RFC3339),
		})
		return
	}

	// Success
	cb.Successes++
	cb.Failures = 0

	if cb.State == "half-open" && cb.Successes >= 2 {
		cb.State = "closed"
		cb.Successes = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"circuit_id":   circuitID,
		"state":        cb.State,
		"successes":    cb.Successes,
		"failures":     cb.Failures,
		"last_failure": cb.LastFailure.Format(time.RFC3339),
	})
}

// handleTestPage serves a static HTML page for comprehensive proxy testing
func (s *Server) handleTestPage(w http.ResponseWriter, r *http.Request) {
	htmlContent := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Test Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
        }
        .test-section {
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-left: 4px solid #4CAF50;
        }
        .json-data {
            background: #e8f5e9;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .css-test {
            color: #2196F3;
            font-weight: bold;
        }
    </style>
    <link rel="stylesheet" href="/test-page.css">
</head>
<body>
    <div class="container">
        <h1>Proxy Test Page</h1>
        <p>This is a comprehensive test page for proxy functionality testing.</p>
        
        <div class="test-section">
            <h2>HTML Content Test</h2>
            <p>This page contains various HTML elements for testing HTML transforms:</p>
            <ul>
                <li>Lists and nested structures</li>
                <li>Forms and inputs</li>
                <li>Images and media</li>
                <li>JavaScript code</li>
                <li>CSS styles</li>
            </ul>
        </div>
        
        <div class="test-section">
            <h2>JSON Data Test</h2>
            <div class="json-data" id="json-data">
                {"status": "success", "message": "JSON data for testing", "data": {"users": [{"id": 1, "name": "Test User"}]}}
            </div>
        </div>
        
        <div class="test-section">
            <h2>CSS Transform Test</h2>
            <p class="css-test">This text should be styled by CSS transforms.</p>
        </div>
        
        <div class="test-section">
            <h2>JavaScript Test</h2>
            <button onclick="testJavaScript()">Test JavaScript</button>
            <div id="js-result"></div>
        </div>
    </div>
    
    <script src="/test-page.js"></script>
    <script>
        function testJavaScript() {
            document.getElementById('js-result').innerHTML = 'JavaScript executed successfully!';
        }
        console.log('Test page loaded');
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
}

// handleTestPageCSS serves CSS for the test page
func (s *Server) handleTestPageCSS(w http.ResponseWriter, r *http.Request) {
	cssContent := `/* Test Page CSS for CSS Transform Testing */
body {
    margin: 0;
    padding: 0;
}

.test-section {
    border-radius: 5px;
    margin-bottom: 15px;
}

.css-test {
    font-size: 18px;
    text-decoration: underline;
}

/* Additional styles for transform testing */
.container {
    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
}`

	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write([]byte(cssContent))
}

// handleTestPageJS serves JavaScript for the test page
func (s *Server) handleTestPageJS(w http.ResponseWriter, r *http.Request) {
	jsContent := `// Test Page JavaScript for JavaScript Transform Testing
(function() {
    'use strict';
    
    console.log('Test page JavaScript loaded');
    
    var testData = {
        status: 'loaded',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    };
    
    function initialize() {
        console.log('Initializing test page');
        if (typeof testJavaScript === 'function') {
            console.log('testJavaScript function available');
        }
    }
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();`

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write([]byte(jsContent))
}

// handleTestPageJSON serves JSON for the test page
func (s *Server) handleTestPageJSON(w http.ResponseWriter, r *http.Request) {
	jsonData := map[string]interface{}{
		"status":  "success",
		"message": "JSON data for testing JSON transforms",
		"data": map[string]interface{}{
			"users": []map[string]interface{}{
				{"id": 1, "name": "Test User 1", "email": "user1@example.com"},
				{"id": 2, "name": "Test User 2", "email": "user2@example.com"},
			},
			"metadata": map[string]interface{}{
				"total": 2,
				"page":  1,
			},
		},
		"sensitive":    "this should be redacted",
		"empty_object": map[string]interface{}{},
		"empty_array":  []interface{}{},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(jsonData)
}

// handleRetryEndpoint handles retry testing endpoints
func (s *Server) handleRetryEndpoint(w http.ResponseWriter, r *http.Request) {
	retryID := strings.TrimPrefix(r.URL.Path, "/retry/")
	if retryID == "" {
		http.NotFound(w, r)
		return
	}

	// Get parameters from query
	successAfter := 0
	if saStr := r.URL.Query().Get("success_after"); saStr != "" {
		if sa, err := strconv.Atoi(saStr); err == nil {
			successAfter = sa
		}
	}

	retryableCode := 503
	if rcStr := r.URL.Query().Get("retryable_code"); rcStr != "" {
		if rc, err := strconv.Atoi(rcStr); err == nil {
			retryableCode = rc
		}
	}

	finalCode := 200
	if fcStr := r.URL.Query().Get("final_code"); fcStr != "" {
		if fc, err := strconv.Atoi(fcStr); err == nil {
			finalCode = fc
		}
	}

	reset := r.URL.Query().Get("reset") == "true"

	// Get or create retry state
	s.retryMu.Lock()
	state, exists := s.retryState[retryID]
	if !exists || reset {
		state = &RetryState{
			AttemptCount:  0,
			SuccessAfter:  successAfter,
			RetryableCode: retryableCode,
			FinalCode:     finalCode,
		}
		s.retryState[retryID] = state
	}
	s.retryMu.Unlock()

	state.mu.Lock()
	state.AttemptCount++
	attempt := state.AttemptCount
	successAfterVal := state.SuccessAfter
	retryableCodeVal := state.RetryableCode
	finalCodeVal := state.FinalCode
	state.mu.Unlock()

	// Determine response status
	var statusCode int
	if successAfterVal > 0 && attempt >= successAfterVal {
		statusCode = finalCodeVal
	} else if successAfterVal == 0 {
		// Always return retryable code
		statusCode = retryableCodeVal
	} else {
		// Return retryable code until success_after attempts
		statusCode = retryableCodeVal
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Retry-Attempt", strconv.Itoa(attempt))
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"retry_id":      retryID,
		"attempt":       attempt,
		"status_code":   statusCode,
		"success_after": successAfterVal,
		"message":       fmt.Sprintf("Attempt %d of retry test", attempt),
	}

	json.NewEncoder(w).Encode(response)
}

// handleMaxRequestsEndpoint handles max requests/concurrent connection testing
func (s *Server) handleMaxRequestsEndpoint(w http.ResponseWriter, r *http.Request) {
	endpointID := strings.TrimPrefix(r.URL.Path, "/max-requests/")
	if endpointID == "" {
		http.NotFound(w, r)
		return
	}

	// Get max connections from query (default 10)
	maxConnections := 10
	if mcStr := r.URL.Query().Get("max_connections"); mcStr != "" {
		if mc, err := strconv.Atoi(mcStr); err == nil {
			maxConnections = mc
		}
	}

	delay := 100
	if dStr := r.URL.Query().Get("delay"); dStr != "" {
		if d, err := strconv.Atoi(dStr); err == nil {
			delay = d
		}
	}

	reset := r.URL.Query().Get("reset") == "true"

	// Get or create max requests state
	s.maxRequestsMu.Lock()
	state, exists := s.maxRequestsState[endpointID]
	if !exists || reset {
		state = &MaxRequestsState{
			ActiveConnections: 0,
			TotalRequests:     0,
			MaxConnections:    maxConnections,
		}
		s.maxRequestsState[endpointID] = state
	}
	s.maxRequestsMu.Unlock()

	// Try to acquire connection
	state.mu.Lock()
	if state.ActiveConnections >= state.MaxConnections {
		state.mu.Unlock()
		// Connection limit reached
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Active-Connections", strconv.Itoa(state.ActiveConnections))
		w.Header().Set("X-Max-Connections", strconv.Itoa(state.MaxConnections))
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":              "Connection limit exceeded",
			"endpoint_id":        endpointID,
			"active_connections": state.ActiveConnections,
			"max_connections":    state.MaxConnections,
		})
		return
	}

	// Acquire connection
	state.ActiveConnections++
	state.TotalRequests++
	activeCount := state.ActiveConnections
	totalRequests := state.TotalRequests
	state.mu.Unlock()

	// Release connection when done
	defer func() {
		state.mu.Lock()
		state.ActiveConnections--
		state.mu.Unlock()
	}()

	// Simulate processing delay
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Active-Connections", strconv.Itoa(activeCount))
	w.Header().Set("X-Max-Connections", strconv.Itoa(state.MaxConnections))
	w.Header().Set("X-Total-Requests", strconv.Itoa(totalRequests))
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"endpoint_id":        endpointID,
		"active_connections": activeCount,
		"max_connections":    state.MaxConnections,
		"total_requests":     totalRequests,
		"status":             "success",
		"message":            fmt.Sprintf("Request processed successfully (active: %d/%d)", activeCount, state.MaxConnections),
	}

	json.NewEncoder(w).Encode(response)
}

// handleErrorCallback handles error callback endpoints for error page testing
func (s *Server) handleErrorCallback(w http.ResponseWriter, r *http.Request) {
	errorCode := strings.TrimPrefix(r.URL.Path, "/error/")
	if errorCode == "" {
		http.NotFound(w, r)
		return
	}

	// Get content type from query param or Accept header (default: text/html)
	contentType := r.URL.Query().Get("content_type")
	if contentType == "" {
		// Check Accept header
		acceptHeader := r.Header.Get("Accept")
		if strings.Contains(acceptHeader, "application/json") {
			contentType = "application/json"
		} else if strings.Contains(acceptHeader, "application/xml") {
			contentType = "application/xml"
		} else {
			contentType = "text/html"
		}
	}

	// Get template flag from query param or path
	isTemplate := r.URL.Query().Get("template") == "true" || strings.Contains(r.URL.Path, "/template")

	// Get base64 flag from query param or path
	isBase64 := r.URL.Query().Get("base64") == "true" || strings.Contains(r.URL.Path, "/base64")

	// Get fail flag (simulate callback failure)
	shouldFail := r.URL.Query().Get("fail") == "true"
	if shouldFail {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Callback endpoint failed",
			"message": "Simulated callback failure for testing",
		})
		return
	}

	// Generate error page content based on error code
	var content string
	var statusCode int

	// Handle special endpoints (template, base64) - these don't have numeric error codes
	if errorCode == "template" {
		// Template endpoint - return template content
		isTemplate = true
		statusCode = 500 // Default, but template will be used for any status
		errorCode = "500"
	} else if errorCode == "base64" {
		// Base64 endpoint - return base64 content
		isBase64 = true
		statusCode = 500
		errorCode = "500"
	} else {
		// Regular error code
		switch errorCode {
		case "400", "401", "403", "404", "408", "410", "413", "414", "415", "422", "429", "451", "500", "502", "503", "504", "507", "508", "510", "511", "5xx":
			if errorCode == "5xx" {
				statusCode = 502 // Default for 5xx range
			} else {
				statusCode, _ = strconv.Atoi(errorCode)
			}
		default:
			// Default to 500 if unknown error code
			statusCode = 500
			errorCode = "500"
		}
	}

	// Generate content based on content type
	// Check for special cases first (template, base64)
	if isTemplate {
		// Template with variables - match expected format (Mustache syntax)
		content = `<html><head><title>Error {{ status_code }}</title></head><body><h1>Error {{ status_code }}</h1><p>Origin ID: {{ origin_id }}</p><p>Hostname: {{ hostname }}</p><p>This error page uses template variables.</p></body></html>`
	} else if isBase64 {
		// Base64 content - return pre-encoded string
		content = "PGh0bWw+PGhlYWQ+PHRpdGxlPjUwMCBFcnJvcjwvdGl0bGU+PC9oZWFkPjxib2R5PjxoMT41MDAgLSBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3I8L2gxPjxwPkVycm9yIHBhZ2UgZW5jb2RlZCBpbiBCYXNlNjQuPC9wPjwvYm9keT48L2h0bWw+"
	} else {
		// Regular content based on content type
		switch contentType {
		case "application/json":
			// For 429, use the expected format with fetched_from
			if errorCode == "429" {
				content = fmt.Sprintf(`{"error": "Rate Limit Exceeded", "message": "Too many requests. Please try again later.", "retry_after": 60, "fetched_from": "callback"}`)
			} else {
				content = fmt.Sprintf(`{"error": "%s", "message": "Error Page from Callback", "status": %d, "code": "%s"}`, http.StatusText(statusCode), statusCode, errorCode)
			}
		case "application/xml":
			content = fmt.Sprintf(`<?xml version="1.0"?><error><status>%d</status><message>Error Page from Callback</message><code>%s</code></error>`, statusCode, errorCode)
		case "text/plain":
			content = fmt.Sprintf("Error %d: %s\nError Page from Callback", statusCode, http.StatusText(statusCode))
		case "text/html":
			fallthrough
		default:
			// Match expected content based on error code
			switch errorCode {
			case "404":
				content = `<html><head><title>404 Not Found</title></head><body><h1>404 - Page Not Found</h1><p>The requested page could not be found.</p><p>Error fetched from callback endpoint.</p></body></html>`
			case "500":
				content = `<html><head><title>500 Internal Server Error</title></head><body><h1>500 - Internal Server Error</h1><p>An internal server error occurred.</p><p>Error page fetched from callback.</p></body></html>`
			case "5xx":
				content = `<html><head><title>Server Error</title></head><body><h1>Server Error (5xx)</h1><p>A server error occurred. Please try again later.</p><p>This error page handles 502, 503, and 504 errors.</p></body></html>`
			default:
				content = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Error %d - %s</title></head>
<body>
<h1>Error %d: %s</h1>
<p>Error page fetched from callback</p>
<p>This error page was fetched from the callback endpoint for status code %s.</p>
</body>
</html>`, statusCode, http.StatusText(statusCode), statusCode, http.StatusText(statusCode), errorCode)
			}
		}
	}

	// Set headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")

	// Write response
	w.Write([]byte(content))
}
