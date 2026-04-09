// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// CacheAdminAPI provides admin endpoints for cache management
type CacheAdminAPI struct {
	warmer      *CacheWarmer
	invalidator *CacheInvalidator
	authKey     string // Simple API key authentication
}

// NewCacheAdminAPI creates a new cache admin API
func NewCacheAdminAPI(warmer *CacheWarmer, invalidator *CacheInvalidator, authKey string) *CacheAdminAPI {
	return &CacheAdminAPI{
		warmer:      warmer,
		invalidator: invalidator,
		authKey:     authKey,
	}
}

// authenticate checks if the request has valid authentication.
// If the admin key is empty, authentication is disabled and all requests are allowed.
func (api *CacheAdminAPI) authenticate(r *http.Request) bool {
	// Empty admin key means auth is disabled (consistent with service.go comment).
	if api.authKey == "" {
		return true
	}

	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	// Simple Bearer token authentication
	expectedAuth := fmt.Sprintf("Bearer %s", api.authKey)
	return authHeader == expectedAuth
}

// HandleCacheStats returns statistics about all caches
func (api *CacheAdminAPI) HandleCacheStats(w http.ResponseWriter, r *http.Request) {
	if !api.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	warmerStats := api.warmer.GetStats()
	invalidatorStats := api.invalidator.GetStats()
	
	stats := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"warmer": map[string]interface{}{
			"enabled":           warmerStats.Enabled,
			"total_patterns":    warmerStats.TotalPatterns,
			"hot_paths":         warmerStats.HotPaths,
			"predictable_paths": warmerStats.PredictablePaths,
			"warmed_count":      warmerStats.WarmedCount,
			"failures":          warmerStats.Failures,
			"last_warming":      warmerStats.LastWarmingTime,
		},
		"invalidator": map[string]interface{}{
			"total_invalidations": invalidatorStats.TotalInvalidations,
			"last_invalidation":   invalidatorStats.LastInvalidation,
			"total_tags":          invalidatorStats.TotalTags,
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
	
	slog.Debug("cache stats requested",
		"remote_addr", r.RemoteAddr)
}

// HandleCacheWarm triggers cache warming
func (api *CacheAdminAPI) HandleCacheWarm(w http.ResponseWriter, r *http.Request) {
	if !api.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Type        string   `json:"type"`        // expressions, callbacks, responses, predictive
		Expressions []string `json:"expressions"` // For expression warming
		LuaScripts  []string `json:"lua_scripts"` // For Lua warming
		Paths       []string `json:"paths"`       // For response warming
		Version     string   `json:"version"`     // Version for expressions
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	start := time.Now()
	var err error
	var message string
	
	ctx := r.Context()
	
	switch req.Type {
	case "expressions":
		err = api.warmer.WarmExpressions(ctx, req.Expressions, req.LuaScripts, req.Version)
		message = fmt.Sprintf("Warmed %d CEL expressions and %d Lua scripts",
			len(req.Expressions), len(req.LuaScripts))
		
	case "responses":
		var warmResult WarmResult
		warmResult, err = api.warmer.WarmResponseCache(ctx, req.Paths)
		message = fmt.Sprintf("Warmed %d URLs: %d cached, %d failed, %d skipped (already cached)",
			len(req.Paths), warmResult.Warmed, warmResult.Failed, warmResult.Skipped)
		
	case "predictive":
		err = api.warmer.PredictiveWarm(ctx)
		message = "Performed predictive cache warming"
		
	default:
		http.Error(w, fmt.Sprintf("Unknown warming type: %s", req.Type), http.StatusBadRequest)
		return
	}
	
	response := map[string]interface{}{
		"success":  err == nil,
		"message":  message,
		"duration": time.Since(start).String(),
	}
	
	if err != nil {
		response["error"] = err.Error()
	}
	
	statusCode := http.StatusOK
	if err != nil {
		statusCode = http.StatusInternalServerError
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
	
	slog.Info("cache warming triggered",
		"type", req.Type,
		"duration", time.Since(start),
		"success", err == nil)
}

// HandleCacheInvalidate handles cache invalidation requests
func (api *CacheAdminAPI) HandleCacheInvalidate(w http.ResponseWriter, r *http.Request) {
	if !api.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req CacheInvalidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	// Validate request
	if req.Type == "" {
		http.Error(w, "Cache type is required", http.StatusBadRequest)
		return
	}
	
	if req.Method == "" {
		req.Method = "invalidate_pattern" // Default method
	}
	
	// Execute invalidation
	resp, err := api.invalidator.Execute(r.Context(), req)
	if err != nil && !req.DryRun {
		slog.Error("cache invalidation failed",
			"type", req.Type,
			"method", req.Method,
			"error", err)
	}
	
	statusCode := http.StatusOK
	if err != nil && !req.DryRun {
		statusCode = http.StatusInternalServerError
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
	
	slog.Info("cache invalidation requested",
		"type", req.Type,
		"method", req.Method,
		"dry_run", req.DryRun,
		"success", resp.Success)
}

// HandleCacheHotPaths returns the hot paths from access tracking
func (api *CacheAdminAPI) HandleCacheHotPaths(w http.ResponseWriter, r *http.Request) {
	if !api.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	hotPaths := api.warmer.GetHotPaths()
	
	response := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"hot_paths": hotPaths,
		"count":     len(hotPaths),
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
	
	slog.Debug("hot paths requested",
		"count", len(hotPaths))
}

// HandleCacheHealth returns cache health status
func (api *CacheAdminAPI) HandleCacheHealth(w http.ResponseWriter, r *http.Request) {
	// No authentication required for health check
	
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	warmerStats := api.warmer.GetStats()
	invalidatorStats := api.invalidator.GetStats()
	
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"warmer": map[string]interface{}{
			"enabled":    warmerStats.Enabled,
			"hot_paths":  warmerStats.HotPaths,
			"failures":   warmerStats.Failures,
		},
		"invalidator": map[string]interface{}{
			"total_invalidations": invalidatorStats.TotalInvalidations,
		},
	}
	
	// Check for issues
	if warmerStats.Failures > 100 {
		health["status"] = "degraded"
		health["warnings"] = []string{"High warming failure rate"}
	}
	
	statusCode := http.StatusOK
	if health["status"] == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(health)
}

// RegisterRoutes registers all cache admin routes on a standard http.ServeMux.
func (api *CacheAdminAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/cache/stats", api.HandleCacheStats)
	mux.HandleFunc("/admin/cache/warm", api.HandleCacheWarm)
	mux.HandleFunc("/admin/cache/invalidate", api.HandleCacheInvalidate)
	mux.HandleFunc("/admin/cache/hot-paths", api.HandleCacheHotPaths)
	mux.HandleFunc("/admin/cache/health", api.HandleCacheHealth)

	slog.Info("cache admin API routes registered")
}

// RegisterChiRoutes registers all cache admin routes on a chi.Router (used by
// the telemetry server).
func (api *CacheAdminAPI) RegisterChiRoutes(router ChiRouter) {
	router.Get("/admin/cache/stats", api.HandleCacheStats)
	router.Post("/admin/cache/warm", api.HandleCacheWarm)
	router.Post("/admin/cache/invalidate", api.HandleCacheInvalidate)
	router.Delete("/admin/cache/invalidate", api.HandleCacheInvalidate)
	router.Get("/admin/cache/hot-paths", api.HandleCacheHotPaths)
	router.Get("/admin/cache/health", api.HandleCacheHealth)

	slog.Info("cache admin API routes registered on chi router")
}

// ChiRouter is a minimal interface satisfied by chi.Router, allowing
// registration without importing the chi package directly.
type ChiRouter interface {
	Get(pattern string, handlerFn http.HandlerFunc)
	Post(pattern string, handlerFn http.HandlerFunc)
	Delete(pattern string, handlerFn http.HandlerFunc)
}

// CacheAdminMiddleware adds cache warming tracking to requests
func CacheAdminMiddleware(warmer *CacheWarmer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Record access for warming
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				warmer.RecordAccess(r.URL.Path)
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

